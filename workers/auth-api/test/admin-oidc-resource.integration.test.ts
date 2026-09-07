import type { SQLInputValue } from "node:sqlite";
import { DatabaseSync } from "node:sqlite";
import {
	ADMIN_OIDC_CLIENT_ID,
	ADMIN_OIDC_REDIRECT_URI,
	ADMIN_OIDC_RESOURCE,
	ADMIN_OIDC_SCOPES,
} from "@cinaauth/auth-web-contract";
import type { oauthProvider } from "@cinaauth/oauth-provider";
import { generateCodeChallenge } from "cinaauth/oauth2";
import type { jwt } from "cinaauth/plugins/jwt";
import { getTestInstance } from "cinaauth/test";
import { describe, expect, it } from "vitest";
import { ensureAdminOidcClient } from "../src/admin-oidc-client";
import { createAuthPlugins } from "../src/plugins";
import { makeOriginEnv } from "./origin-test-env";

/** @see https://www.rfc-editor.org/rfc/rfc8707.html#section-2 */
describe("production Admin resource authorization", () => {
	it("issues an Admin audience token and rejects unknown resources", async () => {
		const env = makeOriginEnv();
		const plugins = createAuthPlugins(env);
		const oidc = plugins.find(
			(plugin): plugin is ReturnType<typeof oauthProvider> =>
				plugin.id === "oauth-provider",
		)!;
		const signing = plugins.find(
			(plugin): plugin is ReturnType<typeof jwt> => plugin.id === "jwt",
		)!;
		const { auth, signInWithTestUser, testUser } = await getTestInstance({
			baseURL: env.CINAAUTH_URL,
			advanced: { useSecureCookies: false },
			plugins: [signing, oidc],
		});
		const context = await auth.$context;
		await context.adapter.update({
			model: "user",
			where: [{ field: "email", value: testUser.email }],
			update: { emailVerified: true },
		});
		const { headers, user } = await signInWithTestUser();
		const database = auth.options.database;
		if (!(database instanceof DatabaseSync))
			throw new Error("Expected the isolated SQLite test database");
		const clientSecret =
			"cina_cs_admin-test-secret-with-at-least-32-characters";
		const execute = async (sql: string, values: unknown[]) =>
			database
				.prepare(sql)
				.run(
					Object.fromEntries(
						values.map((value, index) => [
							`$${index + 1}`,
							value instanceof Date
								? value.toISOString()
								: typeof value === "boolean"
									? Number(value)
									: (value as SQLInputValue),
						]),
					),
				);
		await ensureAdminOidcClient(
			{ query: execute },
			clientSecret,
			ADMIN_OIDC_RESOURCE,
		);
		await ensureAdminOidcClient(
			{ query: execute },
			clientSecret,
			ADMIN_OIDC_RESOURCE,
		);
		await context.adapter.update({
			model: "oauthClient",
			where: [{ field: "clientId", value: ADMIN_OIDC_CLIENT_ID }],
			update: { skipConsent: true },
		});
		const verifier = "admin-resource-pkce-verifier-with-at-least-43-characters";
		const query = new URLSearchParams({
			client_id: ADMIN_OIDC_CLIENT_ID,
			redirect_uri: ADMIN_OIDC_REDIRECT_URI,
			response_type: "code",
			scope: ADMIN_OIDC_SCOPES.join(" "),
			state: "admin-resource-state",
			nonce: "admin-resource-nonce",
			code_challenge: await generateCodeChallenge(verifier),
			code_challenge_method: "S256",
			resource: ADMIN_OIDC_RESOURCE,
		});
		const authorize = () =>
			auth.handler(
				new Request(`${env.CINAAUTH_URL}/api/auth/oauth2/authorize?${query}`, {
					headers,
				}),
			);
		const response = await authorize();
		expect(response.status).toBe(302);
		const callback = new URL(response.headers.get("location")!);
		expect(
			callback.searchParams.get("error"),
			callback.searchParams.get("error_description") ?? "",
		).toBeNull();
		expect(callback.searchParams.get("code")).toBeTruthy();
		const tokenResponse = await auth.handler(
			new Request(`${env.CINAAUTH_URL}/api/auth/oauth2/token`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: `Basic ${btoa(`${ADMIN_OIDC_CLIENT_ID}:${clientSecret}`)}`,
				},
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code: callback.searchParams.get("code")!,
					redirect_uri: ADMIN_OIDC_REDIRECT_URI,
					code_verifier: verifier,
					resource: ADMIN_OIDC_RESOURCE,
				}),
			}),
		);
		expect(tokenResponse.status).toBe(200);
		const tokens = (await tokenResponse.json()) as {
			access_token: string;
			id_token: string;
		};
		const payload = JSON.parse(
			atob(
				tokens.access_token
					.split(".")[1]!
					.replace(/-/g, "+")
					.replace(/_/g, "/"),
			),
		) as Record<string, unknown>;
		expect(payload).toMatchObject({ sub: user.id, azp: ADMIN_OIDC_CLIENT_ID });
		expect([payload.aud].flat()).toContain(ADMIN_OIDC_RESOURCE);
		const userInfo = await auth.handler(
			new Request(`${env.CINAAUTH_URL}/api/auth/oauth2/userinfo`, {
				headers: { authorization: `Bearer ${tokens.access_token}` },
			}),
		);
		expect(userInfo.status).toBe(200);
		expect(await userInfo.json()).toMatchObject({
			sub: user.id,
			email: testUser.email,
		});
		query.set("resource", "https://unregistered.example.com");
		const rejected = await authorize();
		expect(
			new URL(rejected.headers.get("location")!).searchParams.get("error"),
		).toBe("invalid_target");
		query.set("resource", ADMIN_OIDC_RESOURCE);
		await context.adapter.deleteMany({
			model: "oauthClientResource",
			where: [{ field: "clientId", value: ADMIN_OIDC_CLIENT_ID }],
		});
		const unlinked = await authorize();
		expect(
			new URL(unlinked.headers.get("location")!).searchParams.get("error"),
		).toBe("invalid_target");
		await context.adapter.update({
			model: "oauthResource",
			where: [{ field: "identifier", value: ADMIN_OIDC_RESOURCE }],
			update: { disabled: true, accessTokenTtl: 120 },
		});
		await ensureAdminOidcClient(
			{ query: execute },
			clientSecret,
			ADMIN_OIDC_RESOURCE,
		);
		const resource = await context.adapter.findOne({
			model: "oauthResource",
			where: [{ field: "identifier", value: ADMIN_OIDC_RESOURCE }],
		});
		expect(resource).toMatchObject({ disabled: true, accessTokenTtl: 120 });
		const disabled = await authorize();
		expect(
			new URL(disabled.headers.get("location")!).searchParams.get("error"),
		).toBe("invalid_target");
	});
});

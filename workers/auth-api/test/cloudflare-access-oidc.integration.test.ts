import { ADMIN_OIDC_CLIENT_ID } from "@cinaauth/auth-web-contract";
import type { oauthProvider } from "@cinaauth/oauth-provider";
import { generateCodeChallenge } from "cinaauth/oauth2";
import type { jwt } from "cinaauth/plugins/jwt";
import { getTestInstance } from "cinaauth/test";
import { describe, expect, it } from "vitest";
import { createAuthPlugins } from "../src/plugins";
import { makeOriginEnv } from "./origin-test-env";

/** @see https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-oidc/ */
describe("Cloudflare Access ID token email", () => {
	it.each([
		{ scope: "openid email profile offline_access", emailVerified: true },
		{ scope: "openid email profile offline_access", emailVerified: false },
		{ scope: "openid profile offline_access", emailVerified: true },
	])("honors $scope and emailVerified=$emailVerified", async ({
		scope,
		emailVerified,
	}) => {
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
		const creator = await signInWithTestUser();
		const redirectUri =
			"https://test-team.cloudflareaccess.com/cdn-cgi/access/callback";
		const registered = await auth.api.adminCreateOAuthClient({
			headers: creator.headers,
			body: {
				token_endpoint_auth_method: "client_secret_basic",
				grant_types: ["authorization_code", "refresh_token"],
				redirect_uris: [redirectUri],
				require_pkce: true,
				skip_consent: true,
			},
		});
		// Use a server-owned client to exercise production policy without a billing DB.
		await context.adapter.update({
			model: "oauthClient",
			where: [{ field: "clientId", value: registered.client_id }],
			update: { clientId: ADMIN_OIDC_CLIENT_ID },
		});
		await context.adapter.update({
			model: "user",
			where: [{ field: "email", value: testUser.email }],
			update: { emailVerified },
		});
		const { headers, user } = await signInWithTestUser();
		const verifier = "cloudflare-access-pkce-verifier-at-least-43-characters";
		const query = new URLSearchParams({
			client_id: ADMIN_OIDC_CLIENT_ID,
			redirect_uri: redirectUri,
			response_type: "code",
			scope,
			state: "cloudflare-access-test",
			nonce: "cloudflare-access-nonce",
			code_challenge: await generateCodeChallenge(verifier),
			code_challenge_method: "S256",
		});
		const authorization = await auth.handler(
			new Request(`${env.CINAAUTH_URL}/api/auth/oauth2/authorize?${query}`, {
				headers,
			}),
		);
		expect(authorization.status).toBe(302);
		const callback = new URL(authorization.headers.get("location")!);
		expect(callback.searchParams.get("error")).toBeNull();
		expect(callback.searchParams.get("state")).toBe("cloudflare-access-test");
		const tokenRequest = async (body: Record<string, string>) => {
			const response = await auth.handler(
				new Request(`${env.CINAAUTH_URL}/api/auth/oauth2/token`, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: `Basic ${btoa(`${ADMIN_OIDC_CLIENT_ID}:${registered.client_secret}`)}`,
					},
					body: new URLSearchParams(body),
				}),
			);
			expect(response.status).toBe(200);
			return (await response.json()) as {
				id_token: string;
				refresh_token: string;
				scope: string;
			};
		};
		const tokens = await tokenRequest({
			grant_type: "authorization_code",
			code: callback.searchParams.get("code")!,
			redirect_uri: redirectUri,
			code_verifier: verifier,
		});
		expect(tokens.scope).toBe(scope);
		const payload = JSON.parse(
			atob(
				tokens.id_token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"),
			),
		) as Record<string, unknown>;
		expect(payload).toMatchObject({
			iss: env.CINAAUTH_URL,
			aud: ADMIN_OIDC_CLIENT_ID,
			sub: user.id,
			nonce: "cloudflare-access-nonce",
		});
		if (scope.split(" ").includes("email")) {
			expect(payload).toMatchObject({
				email: testUser.email,
				email_verified: emailVerified,
			});
		} else {
			expect(payload).not.toHaveProperty("email");
			expect(payload).not.toHaveProperty("email_verified");
		}
		const refreshed = await tokenRequest({
			grant_type: "refresh_token",
			refresh_token: tokens.refresh_token,
			scope: "openid",
		});
		const refreshedPayload = JSON.parse(
			atob(
				refreshed.id_token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"),
			),
		) as Record<string, unknown>;
		expect(refreshed.scope).toBe("openid");
		expect(refreshedPayload).not.toHaveProperty("email");
		expect(refreshedPayload).not.toHaveProperty("email_verified");
	});
});

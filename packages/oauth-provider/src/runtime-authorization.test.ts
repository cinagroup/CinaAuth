import { jwt } from "cinaauth/plugins/jwt";
import { getTestInstance } from "cinaauth/test";
import { describe, expect, it } from "vitest";
import { oauthProvider } from "./oauth";

describe("OAuth client runtime authorization", () => {
	it("denies authorize and token issuance for an otherwise valid client", async () => {
		const decisions: string[] = [];
		const { auth, signInWithTestUser } = await getTestInstance({
			baseURL: "http://localhost:3000",
			plugins: [
				oauthProvider({
					loginPage: "/login",
					consentPage: "/consent",
					silenceWarnings: {
						oauthAuthServerConfig: true,
						openidConfig: true,
					},
					authorizeClient: ({ endpoint, grantType }) => {
						decisions.push(`${endpoint}:${grantType}`);
						return false;
					},
				}),
				jwt(),
			],
		});
		const { headers } = await signInWithTestUser();
		const client = await auth.api.adminCreateOAuthClient({
			headers,
			body: {
				grant_types: ["authorization_code", "client_credentials"],
				redirect_uris: ["https://client.example.com/callback"],
			},
		});
		if (!client?.client_id || !client.client_secret) {
			throw new Error("OAuth client was not created");
		}

		const authorize = await auth.handler(
			new Request(
				`http://localhost:3000/api/auth/oauth2/authorize?response_type=code&client_id=${encodeURIComponent(client.client_id)}&redirect_uri=${encodeURIComponent("https://client.example.com/callback")}&scope=openid`,
				{ headers: { accept: "application/json" } },
			),
		);
		expect(authorize.status).toBe(200);
		const authorizeBody = (await authorize.json()) as {
			redirect: boolean;
			url: string;
		};
		expect(authorizeBody.url).toContain("error=access_denied");

		const token = await auth.handler(
			new Request("http://localhost:3000/api/auth/oauth2/token", {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					authorization: `Basic ${Buffer.from(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`).toString("base64")}`,
				},
				body: new URLSearchParams({
					grant_type: "client_credentials",
				}),
			}),
		);
		expect(token.status).toBe(403);
		expect(await token.json()).toMatchObject({ error: "access_denied" });
		expect(decisions).toEqual([
			"authorize:authorization_code",
			"token:client_credentials",
		]);
	});
});

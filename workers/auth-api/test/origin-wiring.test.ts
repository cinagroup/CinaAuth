import { OIDC_DEMO_CLIENT_ID } from "@cinaauth/auth-web-contract";
import { describe, expect, it } from "vitest";
import { getConfiguredSocialProviders } from "../src/auth";
import type { CloudflareBindings } from "../src/env";
import worker from "../src/index";
import { createAuthPlugins } from "../src/plugins";

const stagingEnv = {
	CINAAUTH_URL: "https://auth-siwe-staging.cinaseek.ai",
	CINAAUTH_ACCOUNT_ORIGIN: "https://accounts-siwe-staging.cinaseek.ai",
	CINAAUTH_ADMIN_ORIGIN: "https://admin-siwe-staging.cinaseek.ai",
	CINAAUTH_PASSKEY_RP_ID: "accounts-siwe-staging.cinaseek.ai",
	CINAAUTH_OIDC_DEMO_ENVIRONMENT: "staging",
	CINAAUTH_OIDC_DEMO_ORIGIN: "https://oidc-demo-siwe-staging.cinaseek.ai",
	CINAAUTH_OIDC_DEMO_CLIENT_ID: "cinaauth-oidc-demo-siwe-staging",
} as CloudflareBindings;

describe("environment-specific origin wiring", () => {
	it("derives callbacks, Passkey, OAuth pages, and trusted clients from staging", () => {
		const plugins = createAuthPlugins(stagingEnv);

		expect(plugins.find(({ id }) => id === "passkey")?.options).toMatchObject({
			rpID: "accounts-siwe-staging.cinaseek.ai",
			origin: ["https://accounts-siwe-staging.cinaseek.ai"],
		});
		expect(
			plugins.find(({ id }) => id === "device-authorization")?.options,
		).toMatchObject({
			verificationUri: "https://accounts-siwe-staging.cinaseek.ai/device",
		});
		const oauthProvider = plugins.find(({ id }) => id === "oauth-provider");
		expect(oauthProvider?.options).toMatchObject({
			loginPage: "https://accounts-siwe-staging.cinaseek.ai/sign-in",
			consentPage: "https://accounts-siwe-staging.cinaseek.ai/oauth/consent",
			resources: [
				"https://auth-siwe-staging.cinaseek.ai",
				"https://admin-siwe-staging.cinaseek.ai",
				"https://accounts-siwe-staging.cinaseek.ai/api/mcp",
			],
		});
		expect(
			(oauthProvider?.options.cachedTrustedClients as Set<string>).has(
				"cinaauth-oidc-demo-siwe-staging",
			),
		).toBe(true);
		expect(
			(oauthProvider?.options.cachedTrustedClients as Set<string>).has(
				OIDC_DEMO_CLIENT_ID,
			),
		).toBe(false);
	});

	it("pins configured social callbacks to the staging Accounts facade", () => {
		expect(
			getConfiguredSocialProviders(
				{
					GOOGLE_CLIENT_ID: "google-client-id",
					GOOGLE_CLIENT_SECRET: "google-secret",
				},
				"https://accounts-siwe-staging.cinaseek.ai",
			),
		).toMatchObject({
			google: {
				redirectURI:
					"https://accounts-siwe-staging.cinaseek.ai/api/auth/callback/google",
			},
		});
	});

	it("allows the configured staging CORS origin but not production or another port", async () => {
		const preflight = (origin: string) =>
			worker.fetch(
				new Request(
					"https://auth-siwe-staging.cinaseek.ai/api/auth/get-session",
					{
						method: "OPTIONS",
						headers: {
							Origin: origin,
							"Access-Control-Request-Method": "GET",
						},
					},
				),
				stagingEnv,
				{} as ExecutionContext,
			);

		await expect(
			preflight("https://accounts-siwe-staging.cinaseek.ai").then((response) =>
				response.headers.get("Access-Control-Allow-Origin"),
			),
		).resolves.toBe("https://accounts-siwe-staging.cinaseek.ai");
		await expect(
			preflight("https://accounts.cinaseek.ai").then((response) =>
				response.headers.get("Access-Control-Allow-Origin"),
			),
		).resolves.toBeNull();
		await expect(
			preflight("https://accounts-siwe-staging.cinaseek.ai:8443").then(
				(response) => response.headers.get("Access-Control-Allow-Origin"),
			),
		).resolves.toBeNull();
	});
});

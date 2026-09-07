// @vitest-environment node

import {
	ADMIN_OIDC_CLIENT_ID,
	ADMIN_OIDC_REDIRECT_URI,
	ADMIN_OIDC_RESOURCE,
	ADMIN_OIDC_SCOPES,
	ADMIN_OIDC_STEP_UP_MAX_AGE_SECONDS,
} from "@cinaauth/auth-web-contract";
import * as oauth from "oauth4webapi";
import { describe, expect, it } from "vitest";
import {
	createAdminAuthorizationUrl,
	getAdminOidcFailureDetails,
	hasRequiredAdminAuthenticationProof,
} from "@/lib/cinaauth/oidc-client";
import type { AdminOidcTransaction } from "@/lib/cinaauth/oidc-transaction";

/** @see https://www.rfc-editor.org/rfc/rfc8707.html#section-2 */
describe("Admin OIDC authorization request", () => {
	it("uses exact redirect URI, S256 PKCE, state, nonce, and standard scopes", async () => {
		const transaction: AdminOidcTransaction = {
			state: "state-value",
			nonce: "nonce-value",
			codeVerifier: oauth.generateRandomCodeVerifier(),
			callbackPath: "/dashboard",
			createdAt: Date.now(),
			mode: "login",
		};
		const url = await createAdminAuthorizationUrl(
			{
				issuer: "https://auth.cinaseek.ai",
				authorization_endpoint:
					"https://auth.cinaseek.ai/api/auth/oauth2/authorize",
			},
			transaction,
		);

		expect(url.searchParams.get("client_id")).toBe(ADMIN_OIDC_CLIENT_ID);
		expect(url.searchParams.get("redirect_uri")).toBe(ADMIN_OIDC_REDIRECT_URI);
		expect(url.searchParams.get("scope")).toBe(ADMIN_OIDC_SCOPES.join(" "));
		expect(url.searchParams.get("resource")).toBe(ADMIN_OIDC_RESOURCE);
		expect(url.searchParams.get("state")).toBe(transaction.state);
		expect(url.searchParams.get("nonce")).toBe(transaction.nonce);
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		expect(url.searchParams.get("code_challenge")).toBe(
			await oauth.calculatePKCECodeChallenge(transaction.codeVerifier),
		);
		expect(url.searchParams.has("prompt")).toBe(false);
		expect(url.searchParams.has("max_age")).toBe(false);
	});

	it("forces provider login and requests a bounded auth age for step-up", async () => {
		const transaction: AdminOidcTransaction = {
			state: "step-up-state",
			nonce: "step-up-nonce",
			codeVerifier: oauth.generateRandomCodeVerifier(),
			callbackPath: "/settings/security",
			createdAt: Date.now(),
			mode: "step-up",
		};
		const url = await createAdminAuthorizationUrl(
			{
				issuer: "https://auth.cinaseek.ai",
				authorization_endpoint:
					"https://auth.cinaseek.ai/api/auth/oauth2/authorize",
				prompt_values_supported: ["login"],
			},
			transaction,
		);

		expect(url.searchParams.get("prompt")).toBe("login");
		expect(url.searchParams.get("max_age")).toBe(
			String(ADMIN_OIDC_STEP_UP_MAX_AGE_SECONDS),
		);
	});

	it("fails closed when discovery does not advertise prompt=login", async () => {
		const transaction: AdminOidcTransaction = {
			state: "step-up-state",
			nonce: "step-up-nonce",
			codeVerifier: oauth.generateRandomCodeVerifier(),
			callbackPath: "/settings/security",
			createdAt: Date.now(),
			mode: "step-up",
		};

		await expect(
			createAdminAuthorizationUrl(
				{
					issuer: "https://auth.cinaseek.ai",
					authorization_endpoint:
						"https://auth.cinaseek.ai/api/auth/oauth2/authorize",
					prompt_values_supported: ["consent"],
				},
				transaction,
			),
		).rejects.toThrow(/prompt=login/i);
	});

	it("requires step-up auth_time to be recent and tied to this transaction", () => {
		const createdAt = Date.UTC(2026, 7, 11, 8, 0, 0);
		const transaction: AdminOidcTransaction = {
			state: "step-up-state",
			nonce: "step-up-nonce",
			codeVerifier: "step-up-verifier",
			callbackPath: "/settings/security",
			createdAt,
			mode: "step-up",
		};
		const now = createdAt + 30_000;

		expect(
			hasRequiredAdminAuthenticationProof(
				transaction,
				Math.floor((createdAt + 5_000) / 1000),
				now,
			),
		).toBe(true);
		expect(
			hasRequiredAdminAuthenticationProof(transaction, undefined, now),
		).toBe(false);
		expect(
			hasRequiredAdminAuthenticationProof(
				transaction,
				Math.floor((createdAt - 60_000) / 1000),
				now,
			),
		).toBe(false);
		expect(
			hasRequiredAdminAuthenticationProof(
				transaction,
				Math.floor(createdAt / 1000),
				createdAt + (ADMIN_OIDC_STEP_UP_MAX_AGE_SECONDS + 1) * 1000,
			),
		).toBe(false);
		expect(
			hasRequiredAdminAuthenticationProof(
				transaction,
				Math.floor(
					(now + (ADMIN_OIDC_STEP_UP_MAX_AGE_SECONDS + 1) * 1000) / 1000,
				),
				now,
			),
		).toBe(false);
	});

	it("preserves ordinary login when auth_time is not present", () => {
		const transaction: AdminOidcTransaction = {
			state: "login-state",
			nonce: "login-nonce",
			codeVerifier: "login-verifier",
			callbackPath: "/dashboard",
			createdAt: Date.now(),
			mode: "login",
		};

		expect(hasRequiredAdminAuthenticationProof(transaction, undefined)).toBe(
			true,
		);
	});

	it("redacts token endpoint failures to safe OAuth fields", () => {
		const failure = new oauth.ResponseBodyError(
			"server responded with an error in the response body",
			{
				cause: {
					error: "invalid_client",
					error_description: "invalid client_secret",
				},
				response: new Response(null, { status: 401 }),
			},
		);

		expect(getAdminOidcFailureDetails(failure)).toEqual({
			category: "oauth_response",
			code: "invalid_client",
			description: "invalid client_secret",
			status: 401,
		});
		expect(JSON.stringify(getAdminOidcFailureDetails(failure))).not.toContain(
			"client-secret-value",
		);
	});
});

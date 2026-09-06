import type { GenericEndpointContext } from "@cinaauth/core";
import { parseSetCookieHeader } from "cinaauth/cookies";
import { makeSignature } from "cinaauth/crypto";
import { genericOAuth } from "cinaauth/plugins/generic-oauth";
import { jwt } from "cinaauth/plugins/jwt";
import { getTestInstance } from "cinaauth/test";
import { describe, expect, it } from "vitest";
import { oauthProvider } from "./oauth";
import { consumeRegistrationProof } from "./registration-proof";
import {
	canonicalizeOAuthQueryParams,
	setSignedOAuthQueryParameterNames,
	signedQueryIssuedAtParam,
} from "./signed-query";

const baseURL = "http://localhost:3000";
const secret = "social-proof-secret-social-proof-secret";
const providerId = "registration-provider";
const querySignatureStateKey = "oauthProviderRegistrationQuerySignature";
const queryExpiresAtStateKey = "oauthProviderRegistrationExpiresAt";

type CookieJar = Map<string, string>;
type FetchImpl = (
	url: string | Request | URL,
	init?: RequestInit,
) => Promise<Response>;

function captureCookies(response: Response, jar: CookieJar) {
	const cookies = parseSetCookieHeader(
		response.headers.get("set-cookie") ?? "",
	);
	for (const [name, cookie] of cookies) jar.set(name, cookie.value);
}

function cookieHeader(jar: CookieJar) {
	return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

async function createSignedPromptCreateQuery(id: string) {
	const expiresAt = Math.floor(Date.now() / 1000) + 600;
	const query = new URLSearchParams({
		client_id: `client-${id}`,
		redirect_uri: "https://rp.example.com/callback",
		response_type: "code",
		prompt: "create",
		exp: String(expiresAt),
		[signedQueryIssuedAtParam]: String(Date.now()),
	});
	setSignedOAuthQueryParameterNames(query);
	query.set(
		"sig",
		await makeSignature(canonicalizeOAuthQueryParams(query).toString(), secret),
	);
	return {
		query: query.toString(),
		querySignature: query.get("sig")!,
		expiresAt: expiresAt * 1000,
	};
}

function createOptions(storeStateStrategy: "cookie" | "database" = "database") {
	return {
		baseURL,
		secret,
		account: { storeStateStrategy },
		socialProviders: {
			google: {
				clientId: "google-client",
				clientSecret: "google-secret",
				enabled: true,
			},
		},
		plugins: [
			jwt(),
			genericOAuth({
				config: [
					{
						providerId,
						authorizationUrl: "https://provider.example.com/authorize",
						tokenUrl: "https://provider.example.com/token",
						clientId: "provider-client",
						clientSecret: "provider-secret",
						async getToken() {
							return { accessToken: "provider-access-token" };
						},
						async getUserInfo() {
							return {
								id: "provider-user",
								email: "social-registration@example.com",
								name: "Social Registration",
								emailVerified: true,
							};
						},
					},
				],
			}),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				signup: { page: "/signup" },
				silenceWarnings: {
					oauthAuthServerConfig: true,
					openidConfig: true,
				},
			}),
		],
	};
}

async function startOAuth(
	customFetchImpl: FetchImpl,
	path: "/sign-in/social",
	body: Record<string, unknown>,
	jar: CookieJar = new Map(),
) {
	const response = await customFetchImpl(`${baseURL}/api/auth${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			...(jar.size ? { cookie: cookieHeader(jar) } : {}),
		},
		body: JSON.stringify(body),
	});
	captureCookies(response, jar);
	if (response.status !== 200) {
		throw new Error(
			`OAuth start failed: ${response.status} ${await response.text()}`,
		);
	}
	const payload = (await response.json()) as { url?: string };
	const state = payload.url
		? new URL(payload.url).searchParams.get("state")
		: null;
	expect(state).toBeTruthy();
	return { state: state!, jar };
}

describe("social OAuth prompt=create registration proof", () => {
	it("isolates proof in server context for built-in and Generic OAuth providers", async () => {
		const { auth, customFetchImpl } = await getTestInstance(createOptions(), {
			disableTestUser: true,
		});
		const context = await auth.$context;
		const starts = [
			{
				path: "/sign-in/social" as const,
				body: { provider: "google", callbackURL: "/callback" },
			},
			{
				path: "/sign-in/social" as const,
				body: { provider: providerId, callbackURL: "/callback" },
			},
		];

		for (const [index, start] of starts.entries()) {
			const forged = await startOAuth(customFetchImpl, start.path, {
				...start.body,
				disableRedirect: true,
				additionalData: {
					[querySignatureStateKey]: "attacker-signature",
					[queryExpiresAtStateKey]: Date.now() + 60_000,
					serverContext: { [querySignatureStateKey]: "attacker-signature" },
				},
			});
			const forgedState = await context.internalAdapter.findVerificationValue(
				forged.state,
			);
			expect(forgedState).toBeTruthy();
			const forgedPayload = JSON.parse(forgedState!.value) as Record<
				string,
				unknown
			>;
			expect(forgedPayload[querySignatureStateKey]).toBeUndefined();
			expect(forgedPayload[queryExpiresAtStateKey]).toBeUndefined();
			expect(forgedPayload.serverContext).toBeUndefined();

			const signed = await createSignedPromptCreateQuery(String(index));
			const protectedStart = await startOAuth(customFetchImpl, start.path, {
				...start.body,
				disableRedirect: true,
				oauth_query: signed.query,
				additionalData: {
					[querySignatureStateKey]: "attacker-signature",
					[queryExpiresAtStateKey]: 1,
					serverContext: { [querySignatureStateKey]: "attacker-signature" },
				},
			});
			const protectedState =
				await context.internalAdapter.findVerificationValue(
					protectedStart.state,
				);
			expect(protectedState).toBeTruthy();
			const protectedPayload = JSON.parse(protectedState!.value) as Record<
				string,
				unknown
			>;
			const serverContext = protectedPayload.serverContext as Record<
				string,
				unknown
			>;
			expect(protectedPayload[querySignatureStateKey]).toBeUndefined();
			expect(serverContext[querySignatureStateKey]).toBe(signed.querySignature);
			expect(serverContext[queryExpiresAtStateKey]).toBe(signed.expiresAt);
		}
	});

	for (const storeStateStrategy of ["database", "cookie"] as const) {
		it(`restores proof through a real ${storeStateStrategy} callback only for a newly created user`, async () => {
			const { auth, customFetchImpl } = await getTestInstance(
				createOptions(storeStateStrategy),
				{ disableTestUser: true },
			);
			const endpointContext = {
				context: await auth.$context,
			} as GenericEndpointContext;

			const runCallback = async (id: string) => {
				const signed = await createSignedPromptCreateQuery(id);
				const { state, jar } = await startOAuth(
					customFetchImpl,
					"/sign-in/social",
					{
						provider: providerId,
						callbackURL: "/callback",
						disableRedirect: true,
						oauth_query: signed.query,
					},
				);
				const callback = await customFetchImpl(
					`${baseURL}/api/auth/callback/${providerId}?code=test-code&state=${encodeURIComponent(state)}`,
					{
						headers: { cookie: cookieHeader(jar) },
						redirect: "manual",
					},
				);
				captureCookies(callback, jar);
				expect(callback.status).toBe(302);
				const session = await auth.api.getSession({
					headers: new Headers({ cookie: cookieHeader(jar) }),
				});
				expect(session).toBeTruthy();
				return { signed, session: session!, endpointContext };
			};

			const registration = await runCallback(`new-${storeStateStrategy}`);
			await expect(
				consumeRegistrationProof(registration.endpointContext, {
					querySignature: registration.signed.querySignature,
					sessionId: registration.session.session.id,
					userId: registration.session.user.id,
				}),
			).resolves.toBe(true);

			const existing = await runCallback(`existing-${storeStateStrategy}`);
			await expect(
				consumeRegistrationProof(existing.endpointContext, {
					querySignature: existing.signed.querySignature,
					sessionId: existing.session.session.id,
					userId: existing.session.user.id,
				}),
			).resolves.toBe(false);
		});
	}
});

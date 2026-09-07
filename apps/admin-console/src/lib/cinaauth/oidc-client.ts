import {
	ADMIN_OIDC_CLIENT_ID,
	ADMIN_OIDC_ISSUER,
	ADMIN_OIDC_REDIRECT_URI,
	ADMIN_OIDC_RESOURCE,
	ADMIN_OIDC_SCOPES,
	ADMIN_OIDC_STEP_UP_MAX_AGE_SECONDS,
} from "@cinaauth/auth-web-contract";
import * as oauth from "oauth4webapi";
import { fetchAuthRequest } from "./fetcher";
import type { AdminOidcTransaction } from "./oidc-transaction";

export const adminOidcClient: oauth.Client = {
	client_id: ADMIN_OIDC_CLIENT_ID,
	token_endpoint_auth_method: "client_secret_basic",
};

/** Redacts an OIDC failure to safe fields suitable for structured logs. */
export const getAdminOidcFailureDetails = (error: unknown) => {
	if (error instanceof oauth.ResponseBodyError) {
		return {
			category: "oauth_response",
			code: error.error,
			description: error.error_description?.slice(0, 160),
			status: error.status,
		};
	}
	if (error instanceof Error) {
		return {
			category: "runtime",
			code: error.name,
			status: null,
		};
	}
	return { category: "unknown", code: "unknown", status: null };
};

const authServiceFetch = async <Method, BodyType>(
	url: string,
	options: oauth.CustomFetchOptions<Method, BodyType>,
) => {
	const request = new Request(url, {
		method: String(options.method),
		headers: options.headers,
		body: options.body instanceof URLSearchParams ? options.body : undefined,
		redirect: options.redirect,
		signal: options.signal,
	});
	return fetchAuthRequest(request);
};

/** Resolves and validates the authorization server's OIDC discovery document. */
export const discoverAdminAuthorizationServer = async () => {
	const issuer = new URL(ADMIN_OIDC_ISSUER);
	const response = await oauth.discoveryRequest(issuer, {
		algorithm: "oidc",
		[oauth.customFetch]: authServiceFetch,
	});
	return oauth.processDiscoveryResponse(issuer, response);
};

/** Creates the exact authorization request for the fixed Admin client. */
export const createAdminAuthorizationUrl = async (
	authorizationServer: oauth.AuthorizationServer,
	transaction: AdminOidcTransaction,
) => {
	if (!authorizationServer.authorization_endpoint) {
		throw new Error("OIDC authorization endpoint is unavailable");
	}
	const codeChallenge = await oauth.calculatePKCECodeChallenge(
		transaction.codeVerifier,
	);
	const url = new URL(authorizationServer.authorization_endpoint);
	url.searchParams.set("client_id", ADMIN_OIDC_CLIENT_ID);
	url.searchParams.set("redirect_uri", ADMIN_OIDC_REDIRECT_URI);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("scope", ADMIN_OIDC_SCOPES.join(" "));
	url.searchParams.set("resource", ADMIN_OIDC_RESOURCE);
	url.searchParams.set("state", transaction.state);
	url.searchParams.set("nonce", transaction.nonce);
	url.searchParams.set("code_challenge", codeChallenge);
	url.searchParams.set("code_challenge_method", "S256");
	if (transaction.mode === "step-up") {
		const supportedPrompts = authorizationServer.prompt_values_supported;
		if (
			!Array.isArray(supportedPrompts) ||
			!supportedPrompts.some((prompt) => prompt === "login")
		) {
			throw new Error("OIDC provider does not advertise prompt=login");
		}
		url.searchParams.set("prompt", "login");
		url.searchParams.set("max_age", String(ADMIN_OIDC_STEP_UP_MAX_AGE_SECONDS));
	}
	return url;
};

/**
 * Verifies that a step-up ID Token proves authentication for this transaction.
 * Ordinary login intentionally remains compatible with providers omitting auth_time.
 */
export const hasRequiredAdminAuthenticationProof = (
	transaction: AdminOidcTransaction,
	authenticationTime: number | undefined,
	now = Date.now(),
) => {
	if (transaction.mode !== "step-up") return true;
	if (
		typeof authenticationTime !== "number" ||
		!Number.isInteger(authenticationTime)
	) {
		return false;
	}
	const authenticationTimeMs = authenticationTime * 1000;
	const transactionStartSecond =
		Math.floor(transaction.createdAt / 1000) * 1000;
	if (authenticationTimeMs < transactionStartSecond) return false;
	if (authenticationTimeMs > now) return false;
	return (
		now - authenticationTimeMs <= ADMIN_OIDC_STEP_UP_MAX_AGE_SECONDS * 1000
	);
};

/** Exchanges and validates the authorization response entirely server-side. */
export const exchangeAdminAuthorizationCode = async ({
	authorizationServer,
	callbackUrl,
	transaction,
	clientSecret,
}: {
	authorizationServer: oauth.AuthorizationServer;
	callbackUrl: URL;
	transaction: AdminOidcTransaction;
	clientSecret: string;
}) => {
	const parameters = oauth.validateAuthResponse(
		authorizationServer,
		adminOidcClient,
		callbackUrl,
		transaction.state,
	);
	const tokenResponse = await oauth.authorizationCodeGrantRequest(
		authorizationServer,
		adminOidcClient,
		oauth.ClientSecretBasic(clientSecret),
		parameters,
		ADMIN_OIDC_REDIRECT_URI,
		transaction.codeVerifier,
		{
			additionalParameters: { resource: ADMIN_OIDC_RESOURCE },
			[oauth.customFetch]: authServiceFetch,
		},
	);
	const tokens = await oauth.processAuthorizationCodeResponse(
		authorizationServer,
		adminOidcClient,
		tokenResponse,
		{
			expectedNonce: transaction.nonce,
			maxAge:
				transaction.mode === "step-up"
					? ADMIN_OIDC_STEP_UP_MAX_AGE_SECONDS
					: oauth.skipAuthTimeCheck,
			requireIdToken: true,
		},
	);
	await oauth.validateApplicationLevelSignature(
		authorizationServer,
		tokenResponse,
		{ [oauth.customFetch]: authServiceFetch },
	);
	const claims = oauth.getValidatedIdTokenClaims(tokens);
	if (!claims?.sub || !tokens.id_token) {
		throw new Error("Validated ID token claims are missing");
	}
	const userInfoResponse = await oauth.userInfoRequest(
		authorizationServer,
		adminOidcClient,
		tokens.access_token,
		{ [oauth.customFetch]: authServiceFetch },
	);
	await oauth.processUserInfoResponse(
		authorizationServer,
		adminOidcClient,
		claims.sub,
		userInfoResponse,
	);
	return {
		accessToken: tokens.access_token,
		subject: claims.sub,
		authenticationTime: claims.auth_time,
	};
};

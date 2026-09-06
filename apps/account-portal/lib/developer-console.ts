import { isReverseDomainPrivateUseRedirectUri } from "@cinaauth/core/utils/redirect-uri";
import type { Locale } from "./i18n";

export const DEVELOPER_OAUTH_SCOPES = [
	"openid",
	"profile",
	"email",
	"offline_access",
] as const;

export type DeveloperOAuthScope = (typeof DEVELOPER_OAUTH_SCOPES)[number];
export type DeveloperOAuthClientType = "web" | "native";

type OAuthClientSource = {
	client_id: string;
	client_name?: string;
	client_id_issued_at?: number;
	redirect_uris: string[];
	scope?: string;
	token_endpoint_auth_method?:
		| "none"
		| "client_secret_basic"
		| "client_secret_post"
		| "private_key_jwt";
	grant_types?: Array<
		"authorization_code" | "client_credentials" | "refresh_token"
	>;
	response_types?: "code"[];
	public?: boolean;
	type?: "web" | "native" | "user-agent-based";
	application_type?: "web" | "native";
	disabled?: boolean;
};

type OAuthConsentSource = {
	id: string;
	clientId: string;
	userId: string;
	referenceId?: string;
	scopes: string[];
	createdAt: Date | string;
	updatedAt: Date | string;
};

export type DeveloperOAuthClient = {
	clientId: string;
	name: string;
	createdAt: string | null;
	redirectUris: string[];
	scopes: string[];
	tokenEndpointAuthMethod:
		| "none"
		| "client_secret_basic"
		| "client_secret_post"
		| "private_key_jwt";
	grantTypes: Array<
		"authorization_code" | "client_credentials" | "refresh_token"
	>;
	responseTypes: "code"[];
	public: boolean;
	type: "web" | "native" | "user-agent-based";
	disabled: boolean;
};

export type DeveloperOAuthConsent = {
	id: string;
	clientId: string;
	userId: string;
	referenceId: string | null;
	scopes: string[];
	createdAt: string;
	updatedAt: string;
};

const developerDateFormatters: Record<Locale, Intl.DateTimeFormat> = {
	en: new Intl.DateTimeFormat("en", {
		dateStyle: "medium",
		timeStyle: "short",
		timeZone: "UTC",
	}),
	"zh-CN": new Intl.DateTimeFormat("zh-CN", {
		dateStyle: "medium",
		timeStyle: "short",
		timeZone: "UTC",
	}),
};

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const BLOCKED_NATIVE_SCHEMES = new Set([
	"data:",
	"file:",
	"ftp:",
	"http:",
	"javascript:",
	"mailto:",
	"tel:",
	"vbscript:",
]);

const isLoopbackHttp = (uri: string, url: URL) =>
	url.protocol === "http:" &&
	LOOPBACK_HOSTS.has(url.hostname) &&
	/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(uri);

const isNativeCustomScheme = (url: URL) =>
	isReverseDomainPrivateUseRedirectUri(url) &&
	!BLOCKED_NATIVE_SCHEMES.has(url.protocol);

export const parseDeveloperRedirectUris = (
	value: string,
	clientType: DeveloperOAuthClientType,
): { uris: string[]; error: string | null } => {
	const uris = [
		...new Set(
			value
				.split(/\r?\n/)
				.map((item) => item.trim())
				.filter(Boolean),
		),
	];
	if (uris.length === 0) {
		return { uris, error: "Add at least one redirect URI." };
	}
	if (uris.length > 10) {
		return { uris, error: "A client can use at most 10 redirect URIs." };
	}

	for (const uri of uris) {
		if (uri.length > 2048) {
			return {
				uris,
				error: "Each redirect URI must be 2048 characters or less.",
			};
		}

		let url: URL;
		try {
			url = new URL(uri);
		} catch {
			return { uris, error: `Invalid redirect URI: ${uri}` };
		}

		if (url.username || url.password || uri.includes("#")) {
			return {
				uris,
				error: "Redirect URIs cannot contain credentials or URL fragments.",
			};
		}

		const loopback =
			LOOPBACK_HOSTS.has(url.hostname) ||
			/^127\./.test(url.hostname) ||
			/^localhost\.+$/i.test(url.hostname);
		const secureWebUri = url.protocol === "https:" && !loopback;
		const allowed =
			clientType === "web"
				? secureWebUri
				: secureWebUri || isLoopbackHttp(uri, url) || isNativeCustomScheme(url);
		if (!allowed) {
			return {
				uris,
				error:
					clientType === "web"
						? "Web callbacks require HTTPS on a non-loopback host."
						: "Native callbacks require non-loopback HTTPS, exact loopback HTTP, or an authority-free reverse-domain scheme.",
			};
		}
	}

	return { uris, error: null };
};

export const validateDeveloperClientName = (
	value: string,
): { name: string; error: string | null } => {
	const name = value.trim();
	if (!name) return { name, error: "Application name is required." };
	if (name.length > 100) {
		return { name, error: "Application name must be 100 characters or less." };
	}
	return { name, error: null };
};

export const toDeveloperOAuthClient = (
	client: OAuthClientSource,
): DeveloperOAuthClient => ({
	clientId: client.client_id,
	name: client.client_name?.trim() || "Untitled application",
	createdAt:
		typeof client.client_id_issued_at === "number"
			? new Date(client.client_id_issued_at * 1000).toISOString()
			: null,
	redirectUris: [...client.redirect_uris],
	scopes: client.scope?.split(/\s+/).filter(Boolean) ?? [],
	tokenEndpointAuthMethod:
		client.token_endpoint_auth_method ??
		(client.public ? "none" : "client_secret_basic"),
	grantTypes: client.grant_types ?? ["authorization_code"],
	responseTypes: client.response_types ?? ["code"],
	public: client.token_endpoint_auth_method
		? client.token_endpoint_auth_method === "none"
		: client.public === true,
	type: client.application_type ?? client.type ?? "web",
	disabled: client.disabled === true,
});

export const toDeveloperOAuthConsent = (
	consent: OAuthConsentSource,
): DeveloperOAuthConsent => ({
	id: consent.id,
	clientId: consent.clientId,
	userId: consent.userId,
	referenceId: consent.referenceId ?? null,
	scopes: [...consent.scopes],
	createdAt: new Date(consent.createdAt).toISOString(),
	updatedAt: new Date(consent.updatedAt).toISOString(),
});

export const canRotateDeveloperSecret = (client: DeveloperOAuthClient) =>
	!client.public &&
	(client.tokenEndpointAuthMethod === "client_secret_basic" ||
		client.tokenEndpointAuthMethod === "client_secret_post");

export const formatDeveloperDate = (value: string, locale: Locale = "en") =>
	`${developerDateFormatters[locale].format(new Date(value))} UTC`;

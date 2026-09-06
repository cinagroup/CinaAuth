import type { AuthFetcher } from "@cinaauth/auth-proxy";
import { createAuthProxyRequest as createSharedAuthProxyRequest } from "@cinaauth/auth-proxy";
import type {
	AuthCapabilities,
	EntitlementSnapshot,
} from "@cinaauth/auth-web-contract";
import { AUTH_WEB_ENDPOINTS } from "@cinaauth/auth-web-contract";
import { resolveAuthClientRuntimeBaseURL } from "./auth-runtime-config";

export type { AuthFetcher } from "@cinaauth/auth-proxy";
export { createAuthProxyResponse } from "@cinaauth/auth-proxy";
export { DEFAULT_CINAAUTH_API_URL } from "./auth-runtime-config";

export const shouldSkipOAuthProxy = (pathname: string) =>
	pathname === "/api/auth/sign-in/oauth2" ||
	pathname.startsWith("/api/auth/oauth2/callback/");

export const createAuthProxyRequest = (request: Request, baseURL: string) => {
	const proxied = createSharedAuthProxyRequest(request, baseURL);
	if (shouldSkipOAuthProxy(new URL(request.url).pathname)) {
		proxied.headers.set("x-skip-oauth-proxy", "1");
	}
	return proxied;
};

/**
 * Browser auth calls must stay on the current application origin so session
 * cookies are scoped to the relying-party domain. Server rendering can use
 * the configured Auth Worker URL directly.
 */
export const resolveAuthClientBaseURL = (
	browserOrigin?: string,
	configuredBaseURL: string | undefined = process.env
		.NEXT_PUBLIC_CINAAUTH_API_URL,
) =>
	resolveAuthClientRuntimeBaseURL(
		browserOrigin,
		configuredBaseURL,
		process.env.CINAAUTH_REQUIRE_AUTH_WORKER_BINDING,
	);

export type AuthUser = {
	id: string;
	createdAt: Date;
	updatedAt: Date;
	email: string;
	emailVerified: boolean;
	name: string;
	image?: string | null;
	isAnonymous: boolean | null | undefined;
	twoFactorEnabled: boolean | null | undefined;
	role: string | null | undefined;
	banned: boolean | null | undefined;
	banReason: string | null | undefined;
	banExpires: Date | null | undefined;
	[key: string]: unknown;
};

export type AuthSession = {
	id: string;
	createdAt: Date;
	updatedAt: Date;
	userId: string;
	expiresAt: Date;
	token: string;
	userAgent?: string | null;
	ipAddress?: string | null;
	impersonatedBy: string | null | undefined;
	activeOrganizationId: string | null | undefined;
	[key: string]: unknown;
};

export type Session = {
	user: AuthUser;
	session: AuthSession;
};

export type DeviceSession = Session;

export type { EntitlementSnapshot } from "@cinaauth/auth-web-contract";

export type AuthAccount = {
	id: string;
	accountId: string;
	providerId: string;
	userId: string;
	createdAt: Date;
	updatedAt: Date;
	scopes: string[];
};

export type AuthPasskey = {
	id: string;
	name?: string | null;
	createdAt: Date;
	updatedAt: Date;
};

export type AuthApiKey = {
	id: string;
	name: string | null;
	start: string | null;
	prefix: string | null;
	enabled: boolean;
	rateLimitEnabled: boolean;
	rateLimitTimeWindow: number | null;
	rateLimitMax: number | null;
	requestCount: number;
	lastRequest: Date | null;
	expiresAt: Date | null;
	createdAt: Date;
	updatedAt: Date;
};

export type AuthApiKeyList = {
	apiKeys: AuthApiKey[];
	total: number;
	limit: number;
	offset: number;
};

export type AuthWallet = {
	id: string;
	address: string;
	chainId: number;
	isPrimary: boolean;
	createdAt: Date;
};

export type OrganizationRole = "owner" | "admin" | "member";

export type OrganizationTeam = {
	id: string;
	name: string;
	organizationId: string;
	createdAt: Date;
	updatedAt?: Date | null;
};

export type OrganizationTeamMember = {
	id: string;
	teamId: string;
	userId: string;
	createdAt?: Date | null;
};

export type OrganizationDynamicRole = {
	id: string;
	organizationId: string;
	role: string;
	permission: Record<string, string[]>;
	createdAt: Date;
	updatedAt?: Date | null;
};

export type ActiveOrganization = {
	id: string;
	name: string;
	slug?: string;
	logo?: string | null;
	createdAt?: Date;
	[key: string]: unknown;
};

export type OAuthClientPublic = {
	client_id: string;
	client_name: string;
	logo_uri?: string | null;
};

export type OAuthClientRecord = {
	client_id: string;
	client_secret?: string;
	client_secret_expires_at?: number;
	scope?: string;
	user_id?: string | null;
	client_id_issued_at?: number;
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	contacts?: string[];
	tos_uri?: string;
	policy_uri?: string;
	redirect_uris: string[];
	post_logout_redirect_uris?: string[];
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
	require_pkce?: boolean;
	subject_type?: "public" | "pairwise";
};

export type OAuthConsentRecord = {
	id: string;
	clientId: string;
	userId: string;
	referenceId?: string;
	scopes: string[];
	createdAt: Date;
	updatedAt: Date;
};

export type FullOrganization = {
	id: string;
	name: string;
	slug: string;
	logo?: string | null;
	createdAt: Date;
	members: Array<{
		id: string;
		organizationId: string;
		userId: string;
		role: string;
		createdAt: Date;
		user: {
			id: string;
			name: string;
			email: string;
			image?: string | null;
		};
	}>;
	invitations: Array<{
		id: string;
		organizationId: string;
		email: string;
		role: string;
		status: "pending" | "accepted" | "rejected" | "canceled";
		expiresAt: Date;
		createdAt: Date;
	}>;
};

export type OrganizationAuditEntry = {
	id: string;
	timestamp: Date;
	category: string;
	action: string;
	result: string;
	actorId: string | null;
	actorRole: string | null;
	actorSite: string | null;
	targetType: string | null;
	targetId: string | null;
	metadata: string | null;
};

export type OrganizationAuditList = {
	rows: OrganizationAuditEntry[];
	total: number;
	limit: number;
	offset: number;
};

export type SSOProviderSummary = {
	providerId: string;
	type: "oidc" | "saml";
	issuer: string;
	domain: string;
	organizationId: string | null;
	domainVerified: boolean;
	spMetadataUrl: string;
	oidcConfig?: {
		discoveryEndpoint?: string;
		clientIdLastFour?: string;
		pkce?: boolean;
		authorizationEndpoint?: string;
		tokenEndpoint?: string;
		userInfoEndpoint?: string;
		jwksEndpoint?: string;
		scopes?: string[];
		tokenEndpointAuthentication?: "client_secret_post" | "client_secret_basic";
	};
	samlConfig?: {
		entryPoint?: string;
		callbackUrl?: string;
		idpInitiatedCallbackUrl?: string;
		audience?: string;
		wantAssertionsSigned?: boolean;
		authnRequestsSigned?: boolean;
		identifierFormat?: string;
		signatureAlgorithm?: string;
		digestAlgorithm?: string;
		certificate?: {
			fingerprintSha256?: string;
			notBefore?: string;
			notAfter?: string;
			publicKeyAlgorithm?: string;
			error?: string;
		};
	};
};

export type SCIMProviderConnection = {
	id: string;
	providerId: string;
	organizationId: string | null;
};

type QueryValue = string | number | boolean | null | undefined;

type AuthRequestOptions = {
	headers?: HeadersInit;
	query?: Record<string, QueryValue>;
};

const DATE_KEYS = new Set([
	"createdAt",
	"updatedAt",
	"expiresAt",
	"banExpires",
	"lastRefillAt",
	"lastRequest",
]);

const parseJson = async <T>(response: Response): Promise<T> => {
	const text = await response.text();
	return JSON.parse(text, (key, value: unknown) => {
		if (
			DATE_KEYS.has(key) &&
			typeof value === "string" &&
			!Number.isNaN(Date.parse(value))
		) {
			return new Date(value);
		}
		return value;
	}) as T;
};

const appendQuery = (url: URL, query?: Record<string, QueryValue>) => {
	for (const [key, value] of Object.entries(query ?? {})) {
		if (value !== undefined && value !== null) {
			url.searchParams.set(key, String(value));
		}
	}
};

export const createServerAuthApi = (fetcher: AuthFetcher, baseURL: string) => {
	const request = async <T>(
		path: string,
		options: AuthRequestOptions = {},
	): Promise<T> => {
		const url = new URL(path, baseURL);
		appendQuery(url, options.query);
		const headers = new Headers(options.headers);
		headers.delete("host");
		headers.set("accept", "application/json");
		headers.set("cache-control", "no-store");

		const response = await fetcher.fetch(
			new Request(url, {
				method: "GET",
				headers,
			}),
		);
		if (!response.ok) {
			throw new Error(`CinaSeek request failed with HTTP ${response.status}`);
		}
		return parseJson<T>(response);
	};

	return {
		getCapabilities: (options?: AuthRequestOptions) =>
			request<AuthCapabilities>(AUTH_WEB_ENDPOINTS.capabilities, options),
		getEntitlements: (
			organizationId?: string,
			options: AuthRequestOptions = {},
		) =>
			request<EntitlementSnapshot>(AUTH_WEB_ENDPOINTS.entitlements, {
				...options,
				query: { ...options.query, organizationId },
			}),
		getSession: (options?: AuthRequestOptions) =>
			request<Session | null>(AUTH_WEB_ENDPOINTS.session, options),
		listSessions: (options?: AuthRequestOptions) =>
			request<AuthSession[]>("/api/auth/list-sessions", options),
		listUserAccounts: (options?: AuthRequestOptions) =>
			request<AuthAccount[]>("/api/auth/list-accounts", options),
		listPasskeys: (options?: AuthRequestOptions) =>
			request<AuthPasskey[]>("/api/auth/passkey/list-user-passkeys", options),
		listApiKeys: (options?: AuthRequestOptions) =>
			request<AuthApiKeyList>("/api/auth/api-key/list", options),
		listWallets: (options?: AuthRequestOptions) =>
			request<{ wallets: AuthWallet[] }>(
				"/api/auth/siwe/list-wallets",
				options,
			),
		listDeviceSessions: (options?: AuthRequestOptions) =>
			request<DeviceSession[]>(
				"/api/auth/multi-session/list-device-sessions",
				options,
			),
		listOrganizations: (options?: AuthRequestOptions) =>
			request<ActiveOrganization[]>("/api/auth/organization/list", options),
		listOAuthClients: (options?: AuthRequestOptions) =>
			request<OAuthClientRecord[]>("/api/auth/oauth2/get-clients", options),
		listOAuthConsents: (options?: AuthRequestOptions) =>
			request<OAuthConsentRecord[]>("/api/auth/oauth2/get-consents", options),
		getOAuthClientPublic: (options?: AuthRequestOptions) =>
			request<OAuthClientPublic>("/api/auth/oauth2/public-client", options),
		getFullOrganization: (options?: AuthRequestOptions) =>
			request<FullOrganization | null>(
				"/api/auth/organization/get-full-organization",
				options,
			),
		listOrganizationTeams: (
			organizationId: string,
			options: AuthRequestOptions = {},
		) =>
			request<OrganizationTeam[]>("/api/auth/organization/list-teams", {
				...options,
				query: { ...options.query, organizationId },
			}),
		listOrganizationRoles: (
			organizationId: string,
			options: AuthRequestOptions = {},
		) =>
			request<OrganizationDynamicRole[]>("/api/auth/organization/list-roles", {
				...options,
				query: { ...options.query, organizationId },
			}),
		listOrganizationAudit: (
			organizationId: string,
			options: AuthRequestOptions = {},
		) =>
			request<OrganizationAuditList>("/api/auth/audit/organization", {
				...options,
				query: {
					...options.query,
					organizationId,
				},
			}),
		listSSOProviders: (options?: AuthRequestOptions) =>
			request<{ providers: SSOProviderSummary[] }>(
				"/api/auth/sso/providers",
				options,
			),
		listSCIMProviderConnections: (options?: AuthRequestOptions) =>
			request<{ providers: SCIMProviderConnection[] }>(
				"/api/auth/scim/list-provider-connections",
				options,
			),
		getOpenIdConfig: (options?: AuthRequestOptions) =>
			request<Record<string, unknown>>(
				"/api/auth/.well-known/openid-configuration",
				options,
			),
		getOAuthServerConfig: (options?: AuthRequestOptions) =>
			request<Record<string, unknown>>(
				"/api/auth/.well-known/oauth-authorization-server",
				options,
			),
	};
};

export type ServerAuthApi = ReturnType<typeof createServerAuthApi>;

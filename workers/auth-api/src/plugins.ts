import { apiKey } from "@cinaauth/api-key";
import {
	ADMIN_CONSOLE_ROLES,
	ADMIN_OIDC_CLIENT_ID,
	ADMIN_OIDC_CLIENT_SECRET_PREFIX,
	ADMIN_PERMISSION_STATEMENT,
	ADMIN_ROLE_PERMISSIONS,
} from "@cinaauth/auth-web-contract";
import { electron } from "@cinaauth/electron";
import { oauthProvider } from "@cinaauth/oauth-provider";
import { passkey } from "@cinaauth/passkey";
import { scim } from "@cinaauth/scim/legacy";
import { sso } from "@cinaauth/sso";
import { stripe } from "@cinaauth/stripe";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { CinaAuthPlugin } from "cinaauth";
import {
	captcha,
	lastLoginMethod,
	oauthPopup,
	oneTap,
	openAPI,
} from "cinaauth/plugins";
import { createAccessControl } from "cinaauth/plugins/access";
import { admin } from "cinaauth/plugins/admin";
import { anonymous } from "cinaauth/plugins/anonymous";
import { auditLog } from "cinaauth/plugins/audit-log";
import { bearer } from "cinaauth/plugins/bearer";
import { customSession } from "cinaauth/plugins/custom-session";
import { deviceAuthorization } from "cinaauth/plugins/device-authorization";
import { emailOTP } from "cinaauth/plugins/email-otp";
import type { GenericOAuthConfig } from "cinaauth/plugins/generic-oauth";
import { genericOAuth } from "cinaauth/plugins/generic-oauth";
import { haveIBeenPwned } from "cinaauth/plugins/haveibeenpwned";
import { jwt } from "cinaauth/plugins/jwt";
import { multiSession } from "cinaauth/plugins/multi-session";
import { oAuthProxy } from "cinaauth/plugins/oauth-proxy";
import { oneTimeToken } from "cinaauth/plugins/one-time-token";
import { organization } from "cinaauth/plugins/organization";
import {
	defaultAc as organizationAccessControl,
	defaultRoles as organizationRoles,
} from "cinaauth/plugins/organization/access";
import { phoneNumber } from "cinaauth/plugins/phone-number";
import { privacyCenter } from "cinaauth/plugins/privacy-center";
import { siwe } from "cinaauth/plugins/siwe-v2";
import { twoFactor } from "cinaauth/plugins/two-factor";
import Stripe from "stripe";
import { adminOidcBridge } from "./admin-oidc-bridge";
import { createAgentAuthPlugin } from "./agent-auth-policy";
import {
	getTurnstileConfig,
	TURNSTILE_ACTION,
	TURNSTILE_PROTECTED_ENDPOINTS,
} from "./captcha-config";
import { cinatokenOidcBridge } from "./cinatoken-oidc-bridge";
import { CINATOKEN_OIDC_CLIENT_ID } from "./cinatoken-oidc-client";
import { enqueueDelivery } from "./delivery";
import { createEmailOtpTargetRateLimitPlugin } from "./email-otp-target-rate-limit";
import type { RuntimeEntitlementSubject } from "./entitlement-runtime";
import {
	getRuntimeEntitlementLimit,
	isRuntimeEntitlementFeatureEnabled,
	withRuntimeOrganizationMemberCapacity,
} from "./entitlement-runtime";
import { getBillingRuntimeConfiguration } from "./entitlements";
import type { CloudflareBindings } from "./env";
import { parseProductionGenericOAuthConfig } from "./oauth-config";
import { requireAuthOriginConfig } from "./origin-config";
import { createRequiredPrivacyDeletionProcessor } from "./privacy-deletion";
import {
	createR2PrivacyExportProvider,
	hasPrivacyExportRuntime,
} from "./privacy-export";
import { getSiweRuntimeConfig } from "./siwe-runtime-config";
import type { SocialSignInSettings } from "./social-provider-store";

export const JWT_ROTATION_INTERVAL_SECONDS = 60 * 60 * 24 * 30;
export const JWT_GRACE_PERIOD_SECONDS = 60 * 60 * 24 * 30;

/**
 * Access-control statements for the admin plugin.
 *
 * Roles mirror cinaadmin's two-tier model (spec section 3.1):
 *   - super_admin:     full CRUD across every module
 *   - security_admin:  read + ban/unban + session revoke + audit read;
 *                      NO create/delete/set-role/set-password/impersonate
 */
const ac = createAccessControl({
	user: [...ADMIN_PERMISSION_STATEMENT.user],
	session: [...ADMIN_PERMISSION_STATEMENT.session],
	stats: [...ADMIN_PERMISSION_STATEMENT.stats],
	wallet: [...ADMIN_PERMISSION_STATEMENT.wallet],
	passkey: [...ADMIN_PERMISSION_STATEMENT.passkey],
});

export const roles = {
	super_admin: ac.newRole({
		user: [...ADMIN_ROLE_PERMISSIONS.super_admin.user],
		session: [...ADMIN_ROLE_PERMISSIONS.super_admin.session],
		stats: [...ADMIN_ROLE_PERMISSIONS.super_admin.stats],
		wallet: [...ADMIN_ROLE_PERMISSIONS.super_admin.wallet],
		passkey: [...ADMIN_ROLE_PERMISSIONS.super_admin.passkey],
	}),
	security_admin: ac.newRole({
		// read + ban/unban + sessions + stats; NO create/delete/role/password/impersonate.
		user: [...ADMIN_ROLE_PERMISSIONS.security_admin.user],
		session: [...ADMIN_ROLE_PERMISSIONS.security_admin.session],
		stats: [...ADMIN_ROLE_PERMISSIONS.security_admin.stats],
		wallet: [...ADMIN_ROLE_PERMISSIONS.security_admin.wallet],
		passkey: [...ADMIN_ROLE_PERMISSIONS.security_admin.passkey],
	}),
	user: ac.newRole({
		user: [...ADMIN_ROLE_PERMISSIONS.user.user],
		session: [...ADMIN_ROLE_PERMISSIONS.user.session],
		stats: [...ADMIN_ROLE_PERMISSIONS.user.stats],
		wallet: [...ADMIN_ROLE_PERMISSIONS.user.wallet],
		passkey: [...ADMIN_ROLE_PERMISSIONS.user.passkey],
	}),
};

const tempEmailForPhone = (phoneNumber: string, emailDomainName: string) => {
	const normalized = phoneNumber.replace(/[^a-zA-Z0-9]/g, "").slice(-24);
	return `phone-${normalized || "unknown"}@${emailDomainName}`;
};

const ethereumPersonalMessageHash = (message: string) => {
	const messageBytes = utf8ToBytes(message);
	const prefix = utf8ToBytes(
		`\x19Ethereum Signed Message:\n${messageBytes.length}`,
	);
	const bytes = new Uint8Array(prefix.length + messageBytes.length);
	bytes.set(prefix);
	bytes.set(messageBytes, prefix.length);
	return keccak_256(bytes);
};

const recoverPersonalSignAddress = (
	message: string,
	signature: string,
): string | null => {
	const normalizedSignature = signature.startsWith("0x")
		? signature.slice(2)
		: signature;
	if (!/^[0-9a-fA-F]{130}$/.test(normalizedSignature)) {
		return null;
	}

	const signatureBytes = hexToBytes(normalizedSignature);
	const recoveryByte = signatureBytes[64]!;
	const recovery = recoveryByte >= 27 ? recoveryByte - 27 : recoveryByte;
	if (recovery !== 0 && recovery !== 1) {
		return null;
	}

	const compactSignature = signatureBytes.slice(0, 64);
	const publicKey = secp256k1.Signature.fromCompact(compactSignature)
		.addRecoveryBit(recovery)
		.recoverPublicKey(ethereumPersonalMessageHash(message))
		.toRawBytes(false);
	const addressBytes = keccak_256(publicKey.slice(1)).slice(-20);
	return `0x${bytesToHex(addressBytes)}`;
};

const configuredPairwiseSecret = (env: CloudflareBindings) => {
	const secret = env.OAUTH_PAIRWISE_SECRET || env.CINAAUTH_SECRET;
	return secret && secret.length >= 32 ? secret : undefined;
};

const stripePlans = (env: CloudflareBindings) => {
	const billing = getBillingRuntimeConfiguration(env);
	if (!billing) return [];
	const policy = billing.entitlements.plans[billing.stripePlanName];
	if (!policy) return [];
	return [
		{
			name: billing.stripePlanName,
			priceId: billing.priceId,
			limits: policy.limits,
		},
	];
};

const ORGANIZATION_BILLING_ROLES = new Set(["owner", "admin"]);

const getOwnedRuntimeSubject = (owner: {
	organizationId?: string;
	referenceId?: string;
	userId?: string | null;
}): RuntimeEntitlementSubject | undefined => {
	const organizationId = owner.organizationId || owner.referenceId;
	if (organizationId) return { type: "organization", id: organizationId };
	return owner.userId ? { type: "user", id: owner.userId } : undefined;
};

/** Returns true only for organization roles allowed to manage billing. */
export const canManageOrganizationBilling = (role: string | null | undefined) =>
	typeof role === "string" &&
	role
		.split(",")
		.map((candidate) => candidate.trim())
		.some((candidate) => ORGANIZATION_BILLING_ROLES.has(candidate));

export const canUseDeveloperOAuthClients = ({
	session,
	user,
}: {
	session: { id?: string } | undefined;
	user:
		| {
				emailVerified?: boolean;
				isAnonymous?: boolean | null;
		  }
		| undefined;
}) =>
	Boolean(session && user?.emailVerified === true && user.isAnonymous !== true);

const createElectronPlugin = (options: Parameters<typeof electron>[0]) =>
	electron(options) as CinaAuthPlugin;

export const createAuthPlugins = (
	env: CloudflareBindings,
	options: {
		advancedOrganization?: boolean;
		authenticationSettings?: SocialSignInSettings;
		googleOneTapClientId?: string | null;
	} = {},
	resolvedGenericOAuthConfig?: GenericOAuthConfig[],
): CinaAuthPlugin[] => {
	const origins = requireAuthOriginConfig(env);
	const baseURL = origins.authOrigin;
	const authHostname = new URL(origins.authOrigin).hostname;
	const pairwiseSecret = configuredPairwiseSecret(env);
	const genericOAuthConfig =
		resolvedGenericOAuthConfig ??
		parseProductionGenericOAuthConfig(
			env.GENERIC_OAUTH_CONFIG,
			origins.accountOrigin,
		);
	const plans = stripePlans(env);
	const turnstile = getTurnstileConfig(env);
	const siweRuntime = getSiweRuntimeConfig(env);

	const plugins: CinaAuthPlugin[] = [
		createAgentAuthPlugin(origins.accountOrigin),
		jwt({
			jwks: {
				keyPairConfig: { alg: "ES256" },
				rotationInterval: JWT_ROTATION_INTERVAL_SECONDS,
				gracePeriod: JWT_GRACE_PERIOD_SECONDS,
			},
			jwt: {
				issuer: baseURL,
			},
		}),
		bearer(),
		adminOidcBridge(env, origins.authOrigin, origins.adminOrigin),
		...(origins.cinatokenProfile
			? [
					cinatokenOidcBridge(
						env,
						origins.authOrigin,
						origins.cinatokenProfile.applicationOrigin,
					),
				]
			: []),
		anonymous({
			emailDomainName: authHostname,
		}),
		lastLoginMethod({
			storeInDatabase: true,
		}),
		multiSession(),
		customSession(async ({ user, session }) => ({
			user,
			session,
			activeOrganizationId:
				(session as Record<string, unknown>).activeOrganizationId ?? null,
		})),
		twoFactor({
			allowPasswordless: true,
			additionalSignInEndpoints: ["/sign-in/email-otp"],
			requireFreshSessionForPasswordless: true,
			// Email OTP is the first factor, so the second factor must remain an
			// independent TOTP or backup code rather than another message sent to
			// the same mailbox.
		}),
		organization({
			...(options.advancedOrganization
				? {
						ac: organizationAccessControl,
						roles: organizationRoles,
						membershipLimit: (_user, organization) =>
							getRuntimeEntitlementLimit(
								env,
								{ type: "organization", id: organization.id },
								"organizationMembers",
							),
						dynamicAccessControl: {
							enabled: true,
							maximumRolesPerOrganization: (organizationId) =>
								getRuntimeEntitlementLimit(
									env,
									{ type: "organization", id: organizationId },
									"dynamicRoles",
								),
						},
						teams: {
							enabled: true,
							maximumMembersPerTeam: ({ organizationId }) =>
								getRuntimeEntitlementLimit(
									env,
									{ type: "organization", id: organizationId },
									"teamMembers",
								),
							maximumTeams: ({ organizationId }) =>
								getRuntimeEntitlementLimit(
									env,
									{ type: "organization", id: organizationId },
									"teams",
								),
						},
					}
				: {}),
		}),
		apiKey({
			// API keys are scoped to individual users, not organizations.
			references: "user",
			// New keys are visibly owned by CinaAuth while the secret remains
			// irrecoverable after the one-time creation response.
			defaultPrefix: "cina_sk_",
			requireName: true,
			startingCharactersConfig: {
				shouldStore: true,
				charactersLength: 12,
			},
			authorizeReference: ({ referenceId }) =>
				isRuntimeEntitlementFeatureEnabled(
					env,
					{ type: "user", id: referenceId },
					"apiKeys",
				),
		}),
		passkey({
			rpID: origins.passkeyRpId,
			rpName: "CinaSeek",
			// WebAuthn runs in the Accounts document. The Service Binding only
			// changes the upstream request URL; clientDataJSON keeps this origin.
			origin: [origins.accountOrigin],
		}),
		createEmailOtpTargetRateLimitPlugin(env),
		emailOTP({
			// Email verification is the account-creation boundary: existing users
			// sign in and unknown addresses are created only after a valid OTP.
			disableImplicitSignUp: false,
			// Password credentials are not part of the passwordless Accounts
			// contract, so do not expose OTP routes that can create one.
			disablePasswordReset: true,
			// Six-digit codes have too little entropy for an unsalted database hash.
			// Auth-secret-backed encryption prevents offline enumeration after a
			// database-only disclosure while preserving atomic single-use checks.
			storeOTP: "encrypted",
			// Backfill the core email-verification flow: without this,
			// /send-verification-email returns 400 VERIFICATION_EMAIL_NOT_ENABLED
			// because no emailVerification.sendVerificationEmail is configured.
			overrideDefaultEmailVerification: true,
			sendVerificationOTP: async ({ email, otp, type }) => {
				await enqueueDelivery(env, {
					kind: "email-otp",
					payload: { email, otp, type },
				});
			},
		}),
		phoneNumber({
			sendOTP: async ({ phoneNumber, code }) => {
				await enqueueDelivery(env, {
					kind: "phone-otp",
					payload: { phoneNumber, code },
				});
			},
			sendPasswordResetOTP: async ({ phoneNumber, code }) => {
				await enqueueDelivery(env, {
					kind: "phone-reset-otp",
					payload: {
						phoneNumber,
						code,
					},
				});
			},
			signUpOnVerification: {
				getTempEmail: (phoneNumber) =>
					tempEmailForPhone(phoneNumber, authHostname),
				getTempName: (phoneNumber) => phoneNumber,
			},
		}),
		privacyCenter({
			...(hasPrivacyExportRuntime(env)
				? {
						asyncExport: {
							provider: createR2PrivacyExportProvider(env),
							expiresInSeconds: 24 * 60 * 60,
						},
					}
				: {}),
			deletion: {
				policyVersion: "2026-08-10",
				processors: [createRequiredPrivacyDeletionProcessor(env)],
				retentionExceptions: [
					{
						code: "cloudflare-delivery-queues-1d",
						category: "Queued authentication delivery messages",
						purpose:
							"Retry pending email and SMS authentication deliveries and retain failed deliveries for bounded operational review",
						maximumRetentionDays: 1,
						legalBasis:
							"Legitimate interests in reliable authentication delivery and abuse investigation",
					},
					{
						code: "planetscale-postgres-backups-2d",
						category: "Encrypted PostgreSQL backups and WAL",
						purpose:
							"Point-in-time disaster recovery after active account data has been deleted",
						maximumRetentionDays: 2,
						legalBasis:
							"Legitimate interests in service availability and disaster recovery",
					},
					{
						code: "security-audit-90d",
						category: "Security audit evidence",
						purpose:
							"Fraud prevention, incident response, and protection of the authentication service",
						maximumRetentionDays: 90,
						legalBasis: "Legitimate interests in platform and account security",
					},
				],
			},
		}),
		deviceAuthorization({
			verificationUri: `${origins.accountOrigin}/device`,
			validateClient: async (clientId, ctx) => {
				const client = await ctx.context.adapter.findOne<{
					clientId: string;
					disabled?: boolean;
					public?: boolean;
					referenceId?: string;
					userId?: string | null;
				}>({
					model: "oauthClient",
					where: [{ field: "clientId", value: clientId }],
				});
				const subject = client ? getOwnedRuntimeSubject(client) : undefined;
				return Boolean(
					client?.public === true &&
						client.disabled !== true &&
						subject &&
						(await isRuntimeEntitlementFeatureEnabled(
							env,
							subject,
							"oauthClients",
						)),
				);
			},
		}),
		oauthProvider({
			// The plugin serves the well-known discovery routes; silence the
			// advisory reminders so they don't log on every isolate init.
			silenceWarnings: {
				oauthAuthServerConfig: true,
				openidConfig: true,
			},
			loginPage: `${origins.accountOrigin}/sign-in`,
			consentPage: `${origins.accountOrigin}/oauth/consent`,
			signup: {
				page: `${origins.accountOrigin}/sign-in`,
			},
			selectAccount: {
				page: `${origins.accountOrigin}/oauth/select-account`,
				shouldRedirect: () => false,
			},
			scopes: ["openid", "profile", "email", "offline_access"],
			advertisedMetadata: {
				claims_supported: [
					"sub",
					"iss",
					"aud",
					"exp",
					"iat",
					"sid",
					"scope",
					"azp",
					"email",
					"email_verified",
					"name",
					"picture",
					"family_name",
					"given_name",
					"auth_time",
					"acr",
				],
			},
			validAudiences: [
				baseURL,
				origins.adminOrigin,
				...(origins.cinatokenProfile
					? [origins.cinatokenProfile.applicationOrigin]
					: []),
				`${origins.accountOrigin}/api/mcp`,
			],
			allowDynamicClientRegistration: true,
			allowUnauthenticatedClientRegistration: false,
			cachedTrustedClients: new Set([
				ADMIN_OIDC_CLIENT_ID,
				...(origins.cinatokenProfile ? [CINATOKEN_OIDC_CLIENT_ID] : []),
				...(origins.oidcDemoProfile ? [origins.oidcDemoProfile.clientId] : []),
			]),
			clientRegistrationDefaultScopes: [
				"openid",
				"profile",
				"email",
				"offline_access",
			],
			clientPrivileges: ({ session, user }) =>
				canUseDeveloperOAuthClients({ session, user }),
			authorizeClient: ({ client }) => {
				// 1.7 derives client classification from its token authentication
				// method. Reject contradictory flags retained on older stored rows.
				const isPublicClient = client.tokenEndpointAuthMethod === "none";
				const legacyPublic = Reflect.get(client, "public");
				if (
					legacyPublic !== undefined &&
					legacyPublic !== null &&
					legacyPublic !== isPublicClient
				) {
					return false;
				}
				if (
					client.clientId === ADMIN_OIDC_CLIENT_ID ||
					(origins.cinatokenProfile &&
						client.clientId === CINATOKEN_OIDC_CLIENT_ID)
				) {
					return (
						client.disabled !== true &&
						client.tokenEndpointAuthMethod === "client_secret_basic" &&
						!isPublicClient &&
						client.requirePKCE === true
					);
				}
				if (client.clientId === origins.oidcDemoProfile?.clientId) {
					return (
						client.disabled !== true &&
						client.tokenEndpointAuthMethod === "none" &&
						isPublicClient &&
						client.requirePKCE === true
					);
				}
				const subject = getOwnedRuntimeSubject(client);
				return subject
					? isRuntimeEntitlementFeatureEnabled(env, subject, "oauthClients")
					: false;
			},
			pairwiseSecret,
			prefix: {
				opaqueAccessToken: "cina_at_",
				refreshToken: "cina_rt_",
				clientSecret: ADMIN_OIDC_CLIENT_SECRET_PREFIX,
			},
			rateLimit: {
				token: { window: 60, max: 20 },
				authorize: { window: 60, max: 30 },
				introspect: { window: 60, max: 100 },
				revoke: { window: 60, max: 30 },
				register: { window: 60, max: 5 },
				userinfo: { window: 60, max: 60 },
			},
		}),
		sso({
			domainVerification: {
				enabled: true,
			},
			organizationProvisioning: {
				defaultRole: "member",
				withOrganizationMemberProvisioning: async (
					{ organizationId, userId },
					provision,
				) => {
					return withRuntimeOrganizationMemberCapacity(
						env,
						organizationId,
						userId,
						provision,
					);
				},
			},
			authorizeProvider: ({ provider }) => {
				const subject = getOwnedRuntimeSubject(provider);
				return subject
					? isRuntimeEntitlementFeatureEnabled(env, subject, "sso")
					: false;
			},
		}),
		scim({
			providerOwnership: {
				enabled: true,
			},
			requiredRole: ["owner", "admin"],
			storeSCIMToken: "hashed",
			canGenerateToken: ({ member }) => member !== null,
			authorizeProvider: ({ provider }) => {
				const subject = getOwnedRuntimeSubject(provider);
				return subject
					? isRuntimeEntitlementFeatureEnabled(env, subject, "scim")
					: false;
			},
			withOrganizationMemberProvisioning: async (
				{ organizationId, userId },
				provision,
			) => {
				return withRuntimeOrganizationMemberCapacity(
					env,
					organizationId,
					userId,
					provision,
				);
			},
		}),
		createElectronPlugin({
			clientID: "electron",
			cookiePrefix: "cinaauth",
		}),
		oauthPopup(),
		oAuthProxy({
			productionURL: baseURL,
		}),
		oneTimeToken(),
		openAPI({
			title: "CinaSeek Identity",
			description: "CinaSeek identity and access management API",
		}),
		haveIBeenPwned(),
		admin({
			// Roles recognized by the admin console's whitelist
			// (CINAADMIN_ALLOWED_ROLES = super_admin,security_admin).
			defaultRole: "user",
			adminRoles: [...ADMIN_CONSOLE_ROLES],
			ac,
			roles,
		}),
		auditLog({
			// Defaults to ["admin"] if omitted, which would exclude our console roles.
			allowedRoles: ["super_admin", "security_admin"],
			// Service token for the admin console (cinaadmin) to call POST /audit/log.
			writeTokens: env.CINAUTH_ADMIN_SERVICE_KEY
				? [env.CINAUTH_ADMIN_SERVICE_KEY]
				: [],
		}),
	];

	if (siweRuntime.enabled) {
		plugins.push(
			siwe({
				domain: siweRuntime.rpDomain,
				uri: siweRuntime.rpUri,
				enabled: true,
				allowedChainIds: siweRuntime.allowedChainIds,
				legacyNonce: siweRuntime.allowLegacy,
				allowUserCreation: siweRuntime.autoSignup,
				challengeExpiresIn: 5 * 60,
				maxMessageAge: 5 * 60,
				clockSkew: 60,
				emailDomainName: authHostname,
				verifyMessage: async ({ message, signature, address }) => {
					try {
						const recoveredAddress = recoverPersonalSignAddress(
							message,
							signature,
						);
						return recoveredAddress?.toLowerCase() === address.toLowerCase();
					} catch {
						return false;
					}
				},
			}),
		);
	}

	if (turnstile.enabled && turnstile.secretKey) {
		plugins.push(
			captcha({
				provider: "cloudflare-turnstile",
				secretKey: turnstile.secretKey,
				endpoints: [...TURNSTILE_PROTECTED_ENDPOINTS],
				expectedAction: TURNSTILE_ACTION,
				allowedHostnames: origins.trustedHostnames,
			}),
		);
	}

	if (genericOAuthConfig.length > 0) {
		plugins.push(
			genericOAuth({
				config: genericOAuthConfig,
			}),
		);
	}

	if (env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET) {
		plugins.push(
			stripe({
				stripeClient: new Stripe(env.STRIPE_SECRET_KEY),
				stripeWebhookSecret: env.STRIPE_WEBHOOK_SECRET,
				createCustomerOnSignUp: false,
				organization: {
					enabled: true,
				},
				subscription:
					plans.length > 0
						? {
								enabled: true,
								plans,
								authorizeReference: async ({ user, referenceId }, ctx) => {
									const member = await ctx.context.adapter.findOne<{
										role: string;
									}>({
										model: "member",
										where: [
											{ field: "organizationId", value: referenceId },
											{ field: "userId", value: user.id },
										],
									});
									return canManageOrganizationBilling(member?.role);
								},
							}
						: {
								enabled: false,
							},
			}),
		);
	}

	if (
		options.authenticationSettings?.googleOneTapEnabled === true &&
		options.googleOneTapClientId
	) {
		plugins.push(
			oneTap({
				clientId: options.googleOneTapClientId,
				disableSignup: false,
			}),
		);
	}

	return plugins;
};

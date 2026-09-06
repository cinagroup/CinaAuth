import {
	ADMIN_OIDC_CLIENT_ID,
	ENTITLEMENT_FEATURES,
	ENTITLEMENT_LIMITS,
	OIDC_DEMO_CLIENT_ID,
} from "@cinaauth/auth-web-contract";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
	getConfiguredSocialProviders,
	getProductionSocialProviders,
} from "../src/auth";
import {
	canManageOrganizationBilling,
	createAuthPlugins,
	JWT_GRACE_PERIOD_SECONDS,
	JWT_ROTATION_INTERVAL_SECONDS,
	roles,
} from "../src/plugins";
import { makeOriginEnv, PRODUCTION_ORIGIN_ENV } from "./origin-test-env";

const getOrganizationSchema = (advancedOrganization: boolean) => {
	const plugin = createAuthPlugins(makeOriginEnv(), {
		advancedOrganization,
	}).find((candidate) => candidate.id === "organization");

	expect(plugin).toBeDefined();
	return plugin?.schema;
};

const entitlementConfig = () =>
	JSON.stringify({
		version: 1,
		defaultPlan: "default",
		plans: {
			default: {
				features: Object.fromEntries(
					ENTITLEMENT_FEATURES.map((feature) => [feature, true]),
				),
				limits: Object.fromEntries(
					ENTITLEMENT_LIMITS.map((limit) => [limit, null]),
				),
			},
		},
	});

describe("Agent Auth production policy", () => {
	it("enables only delegated device-approved profile access", () => {
		const plugin = createAuthPlugins(makeOriginEnv()).find(
			(candidate) => candidate.id === "agent-auth",
		);

		expect(plugin?.options).toMatchObject({
			providerName: "CinaSeek Identity",
			modes: ["delegated"],
			approvalMethods: ["device_authorization"],
			deviceAuthorizationPage:
				"https://accounts.cinaseek.ai/device/capabilities",
			allowDynamicHostRegistration: true,
			freshSessionWindow: 15 * 60,
			maxAgentsPerUser: 10,
			capabilities: [
				expect.objectContaining({
					name: "identity.profile.read",
					approvalStrength: "session",
					grantTTL: 24 * 60 * 60,
				}),
			],
		});
		expect(plugin?.schema).toMatchObject({
			agentHost: expect.any(Object),
			agent: expect.any(Object),
			agentCapabilityGrant: expect.any(Object),
			approvalRequest: expect.any(Object),
		});
	});
});

describe("organization schema mode", () => {
	it("keeps advanced organization schema dormant by default", () => {
		const schema = getOrganizationSchema(false);

		expect(schema).not.toHaveProperty("team");
		expect(schema).not.toHaveProperty("teamMember");
		expect(schema).not.toHaveProperty("organizationRole");
		expect(schema?.session?.fields).not.toHaveProperty("activeTeamId");
	});

	it("includes teams and dynamic roles only in advanced mode", () => {
		const plugin = createAuthPlugins(makeOriginEnv(), {
			advancedOrganization: true,
		}).find((candidate) => candidate.id === "organization");
		const schema = getOrganizationSchema(true);

		expect(plugin?.options).toMatchObject({
			ac: expect.any(Object),
			dynamicAccessControl: {
				enabled: true,
				maximumRolesPerOrganization: expect.any(Function),
			},
			roles: {
				admin: expect.any(Object),
				member: expect.any(Object),
				owner: expect.any(Object),
			},
			teams: {
				enabled: true,
				maximumMembersPerTeam: expect.any(Function),
				maximumTeams: expect.any(Function),
			},
		});
		expect(schema).toHaveProperty("team");
		expect(schema).toHaveProperty("teamMember");
		expect(schema).toHaveProperty("organizationRole");
		expect(schema?.session?.fields).toHaveProperty("activeTeamId");
		expect(schema?.invitation?.fields).toHaveProperty("teamId");
	});
});

describe("passwordless email authentication policy", () => {
	it("registers encrypted email OTP without password-backed sign-in plugins", () => {
		const plugins = createAuthPlugins(makeOriginEnv());
		const pluginIds = new Set(plugins.map((plugin) => plugin.id));
		const emailOtpPlugin = plugins.find((plugin) => plugin.id === "email-otp");
		const emailOtpTargetRateLimitPlugin = plugins.find(
			(plugin) => plugin.id === "email-otp-target-rate-limit",
		);
		const twoFactorPlugin = plugins.find(
			(plugin) => plugin.id === "two-factor",
		);

		expect(pluginIds.has("username")).toBe(false);
		expect(pluginIds.has("magic-link")).toBe(false);
		expect(emailOtpTargetRateLimitPlugin?.hooks?.before).toEqual([
			expect.objectContaining({ priority: 200 }),
		]);
		expect(
			plugins.findIndex(
				(plugin) => plugin.id === "email-otp-target-rate-limit",
			),
		).toBeLessThan(plugins.findIndex((plugin) => plugin.id === "email-otp"));
		expect(emailOtpPlugin?.options).toMatchObject({
			disableImplicitSignUp: false,
			disablePasswordReset: true,
			storeOTP: "encrypted",
		});
		expect(twoFactorPlugin?.options).toMatchObject({
			allowPasswordless: true,
			additionalSignInEndpoints: ["/sign-in/email-otp"],
			requireFreshSessionForPasswordless: true,
		});
		expect(twoFactorPlugin?.options).not.toHaveProperty("otpOptions");
	});
});

describe("authoritative Admin role permissions", () => {
	it("allows both Admin roles to inspect and unbind user wallets", () => {
		expect(
			roles.super_admin.authorize({ wallet: ["list", "unbind"] }).success,
		).toBe(true);
		expect(
			roles.security_admin.authorize({ wallet: ["list", "unbind"] }).success,
		).toBe(true);
	});

	it("keeps security_admin scoped to reversible security operations", () => {
		expect(roles.security_admin.authorize({ user: ["ban"] }).success).toBe(
			true,
		);
		expect(
			roles.security_admin.authorize({ session: ["revoke"] }).success,
		).toBe(true);
		expect(roles.security_admin.authorize({ user: ["update"] }).success).toBe(
			false,
		);
		expect(roles.security_admin.authorize({ user: ["set-role"] }).success).toBe(
			false,
		);
		expect(
			roles.security_admin.authorize({ user: ["set-password"] }).success,
		).toBe(false);
	});
});

describe("OIDC signing and social provider configuration", () => {
	/** @see https://www.better-auth.com/docs/plugins/oauth-provider */
	it("accepts owned canonical public device clients and rejects inconsistent or disabled clients", async () => {
		type Client = {
			clientId: string;
			tokenEndpointAuthMethod?: string;
			public?: boolean;
			disabled?: boolean;
			userId?: string;
		};
		const plugin = createAuthPlugins(makeOriginEnv()).find(
			(candidate) => candidate.id === "device-authorization",
		);
		const options = plugin?.options as unknown as {
			validateClient(
				clientId: string,
				context: {
					context: { adapter: { findOne: () => Promise<Client | null> } };
				},
			): Promise<boolean>;
		};
		const client: Client = {
			clientId: "owned-device-client",
			tokenEndpointAuthMethod: "none",
			userId: "device-owner",
		};
		const validate = (record: Client | null) =>
			options.validateClient(client.clientId, {
				context: { adapter: { findOne: async () => record } },
			});
		expect(await validate(client)).toBe(true);
		expect(await validate({ ...client, public: true })).toBe(true);
		for (const rejected of [
			null,
			{ ...client, public: false },
			{ ...client, disabled: true },
			{ ...client, userId: undefined },
			{ ...client, tokenEndpointAuthMethod: undefined, public: true },
			{
				...client,
				tokenEndpointAuthMethod: "client_secret_basic",
				public: true,
			},
		]) {
			expect(await validate(rejected)).toBe(false);
		}
	});
	it("authorizes canonical 1.7 clients while rejecting inconsistent legacy flags", async () => {
		const plugin = createAuthPlugins(makeOriginEnv()).find(
			(candidate) => candidate.id === "oauth-provider",
		);
		const options = plugin?.options as unknown as {
			authorizeClient(input: {
				client: {
					clientId: string;
					tokenEndpointAuthMethod?: string;
					requirePKCE: boolean;
					disabled: boolean;
					public?: boolean;
				};
			}): boolean | Promise<boolean>;
		};
		for (const clientId of [ADMIN_OIDC_CLIENT_ID, OIDC_DEMO_CLIENT_ID]) {
			const isPublic = clientId === OIDC_DEMO_CLIENT_ID;
			const client = {
				clientId,
				tokenEndpointAuthMethod: isPublic ? "none" : "client_secret_basic",
				requirePKCE: true,
				disabled: false,
			};
			expect(await options.authorizeClient({ client })).toBe(true);
			expect(
				await options.authorizeClient({
					client: { ...client, public: isPublic },
				}),
			).toBe(true);
			expect(
				await options.authorizeClient({
					client: { ...client, public: !isPublic },
				}),
			).toBe(false);
			expect(
				await options.authorizeClient({
					client: { ...client, requirePKCE: false },
				}),
			).toBe(false);
			expect(
				await options.authorizeClient({
					client: { ...client, disabled: true },
				}),
			).toBe(false);
			for (const method of [
				undefined,
				"unknown",
				isPublic ? "client_secret_basic" : "none",
			]) {
				expect(
					await options.authorizeClient({
						client: { ...client, tokenEndpointAuthMethod: method },
					}),
				).toBe(false);
			}
		}
	});
	it("uses redirect OAuth for Google without registering One Tap", () => {
		const plugins = createAuthPlugins(
			makeOriginEnv({
				GOOGLE_CLIENT_ID: "google-client-id",
				GOOGLE_CLIENT_SECRET: "google-secret",
			}),
		);
		const oauthProviderPlugin = plugins.find(
			(plugin) => plugin.id === "oauth-provider",
		);

		expect(plugins.some((plugin) => plugin.id === "one-tap")).toBe(false);
		expect(oauthProviderPlugin?.options).toMatchObject({
			loginPage: "https://accounts.cinaseek.ai/sign-in",
			signup: { page: "https://accounts.cinaseek.ai/sign-in" },
		});
	});

	it("rejects a persisted demo client when the optional demo origin is disabled", async () => {
		const plugin = createAuthPlugins(
			makeOriginEnv({
				CINAAUTH_OIDC_DEMO_ENVIRONMENT: undefined,
				CINAAUTH_OIDC_DEMO_ORIGIN: undefined,
				CINAAUTH_OIDC_DEMO_CLIENT_ID: undefined,
			}),
		).find((candidate) => candidate.id === "oauth-provider");
		const authorizeClient = (
			plugin?.options as {
				authorizeClient?: (input: {
					client: {
						clientId: string;
						disabled: boolean;
						public: boolean;
						requirePKCE: boolean;
						tokenEndpointAuthMethod: string;
					};
				}) => boolean | Promise<boolean>;
			}
		).authorizeClient;

		expect(authorizeClient).toBeTypeOf("function");
		expect(
			await authorizeClient?.({
				client: {
					clientId: "cinaauth-oidc-demo",
					disabled: false,
					public: true,
					requirePKCE: true,
					tokenEndpointAuthMethod: "none",
				},
			}),
		).toBe(false);
	});

	it("trusts only the configured staging demo client", async () => {
		const plugin = createAuthPlugins(
			makeOriginEnv({
				CINAAUTH_URL: "https://auth-siwe-staging.cinaseek.ai",
				CINAAUTH_ACCOUNT_ORIGIN: "https://accounts-siwe-staging.cinaseek.ai",
				CINAAUTH_ADMIN_ORIGIN: "https://admin-siwe-staging.cinaseek.ai",
				CINAAUTH_PASSKEY_RP_ID: "accounts-siwe-staging.cinaseek.ai",
				CINAAUTH_LEGACY_ACCOUNT_ORIGIN: undefined,
				CINAAUTH_OIDC_DEMO_ENVIRONMENT: "staging",
				CINAAUTH_OIDC_DEMO_ORIGIN: "https://oidc-demo-siwe-staging.cinaseek.ai",
				CINAAUTH_OIDC_DEMO_CLIENT_ID: "cinaauth-oidc-demo-siwe-staging",
			}),
		).find((candidate) => candidate.id === "oauth-provider");
		const options = plugin?.options as {
			cachedTrustedClients?: Set<string>;
			authorizeClient?: (input: {
				client: {
					clientId: string;
					disabled: boolean;
					public: boolean;
					requirePKCE: boolean;
					tokenEndpointAuthMethod: string;
				};
			}) => boolean | Promise<boolean>;
		};

		expect(
			options.cachedTrustedClients?.has("cinaauth-oidc-demo-siwe-staging"),
		).toBe(true);
		expect(options.cachedTrustedClients?.has(OIDC_DEMO_CLIENT_ID)).toBe(false);
		const configuredClient = {
			clientId: "cinaauth-oidc-demo-siwe-staging",
			disabled: false,
			public: true,
			requirePKCE: true,
			tokenEndpointAuthMethod: "none",
		};
		expect(await options.authorizeClient?.({ client: configuredClient })).toBe(
			true,
		);
		expect(
			await options.authorizeClient?.({
				client: { ...configuredClient, clientId: OIDC_DEMO_CLIENT_ID },
			}),
		).toBe(false);
	});

	it("uses ES256 with bounded rotation and grace periods", () => {
		const plugin = createAuthPlugins(makeOriginEnv()).find(
			(candidate) => candidate.id === "jwt",
		);

		expect(plugin?.options).toMatchObject({
			jwks: {
				keyPairConfig: { alg: "ES256" },
				rotationInterval: JWT_ROTATION_INTERVAL_SECONDS,
				gracePeriod: JWT_GRACE_PERIOD_SECONDS,
			},
			jwt: { issuer: "https://auth.cinaseek.ai" },
		});
	});

	it("enables Google and GitHub only from complete secret pairs", () => {
		expect(
			getConfiguredSocialProviders(
				{
					GOOGLE_CLIENT_ID: "google-client-id",
				},
				PRODUCTION_ORIGIN_ENV.CINAAUTH_ACCOUNT_ORIGIN,
			),
		).toEqual({});
		expect(
			getConfiguredSocialProviders(
				{
					GOOGLE_CLIENT_ID: "google-client-id",
					GOOGLE_CLIENT_SECRET: "google-secret",
					GITHUB_CLIENT_ID: "github-client-id",
					GITHUB_CLIENT_SECRET: "github-secret",
				},
				PRODUCTION_ORIGIN_ENV.CINAAUTH_ACCOUNT_ORIGIN,
			),
		).toEqual({
			google: {
				clientId: "google-client-id",
				clientSecret: "google-secret",
				redirectURI: "https://accounts.cinaseek.ai/api/auth/callback/google",
				disableImplicitSignUp: false,
				disableSignUp: false,
			},
			github: {
				clientId: "github-client-id",
				clientSecret: "github-secret",
				redirectURI: "https://accounts.cinaseek.ai/api/auth/callback/github",
				disableImplicitSignUp: false,
				disableSignUp: false,
			},
		});
	});

	it("keeps Google and GitHub ids reserved when credentials are temporarily absent", () => {
		expect(
			getProductionSocialProviders(
				{},
				PRODUCTION_ORIGIN_ENV.CINAAUTH_ACCOUNT_ORIGIN,
			),
		).toEqual({
			google: {
				clientId: "provider-id-reservation-only",
				clientSecret: "provider-id-reservation-only",
				enabled: false,
			},
			github: {
				clientId: "provider-id-reservation-only",
				clientSecret: "provider-id-reservation-only",
				enabled: false,
			},
		});
		expect(
			getProductionSocialProviders(
				{
					GOOGLE_CLIENT_ID: "google-client-id",
					GOOGLE_CLIENT_SECRET: "google-secret",
				},
				PRODUCTION_ORIGIN_ENV.CINAAUTH_ACCOUNT_ORIGIN,
			),
		).toMatchObject({
			google: { clientId: "google-client-id", clientSecret: "google-secret" },
			github: { enabled: false },
		});
	});
});

describe("organization member entitlement chokepoints", () => {
	it("wraps both SSO and SCIM automatic membership provisioning", () => {
		const plugins = createAuthPlugins(makeOriginEnv());
		const ssoPlugin = plugins.find((candidate) => candidate.id === "sso");
		const scimPlugin = plugins.find(
			(candidate) => candidate.id === "scim-legacy",
		);

		expect(ssoPlugin?.options).toMatchObject({
			organizationProvisioning: {
				withOrganizationMemberProvisioning: expect.any(Function),
			},
		});
		expect(scimPlugin?.options).toMatchObject({
			withOrganizationMemberProvisioning: expect.any(Function),
		});
	});
});

describe("SIWE production gate", () => {
	const enabledSiweEnv = makeOriginEnv({
		CINAAUTH_SIWE_ENABLED: "true",
		CINAAUTH_SIWE_ALLOWED_CHAIN_IDS: "1,11155111",
		CINAAUTH_SIWE_RP_DOMAIN: "accounts.cinaseek.ai",
		CINAAUTH_SIWE_RP_URI: "https://accounts.cinaseek.ai",
		CINAAUTH_SIWE_ALLOW_LEGACY: "false",
		CINAAUTH_SIWE_AUTO_SIGNUP: "true",
	});

	it("does not register SIWE without a complete enabled configuration", () => {
		expect(
			createAuthPlugins(makeOriginEnv()).find(
				(candidate) => candidate.id === "siwe-v2",
			),
		).toBeUndefined();
	});

	it("passes the strict RP, chain, and stage-two account-creation policy to SIWE v2", () => {
		const plugin = createAuthPlugins(enabledSiweEnv).find(
			(candidate) => candidate.id === "siwe-v2",
		);

		expect(plugin?.options).toMatchObject({
			domain: "accounts.cinaseek.ai",
			uri: "https://accounts.cinaseek.ai",
			enabled: true,
			allowedChainIds: [1, 11155111],
			legacyNonce: false,
			allowUserCreation: true,
		});
	});

	it("keeps wallet management installed while the runtime sign-in switch gates verification", () => {
		const plugin = createAuthPlugins(enabledSiweEnv, {
			authenticationSettings: {
				socialProviderLimit: 20,
				emailOtpLoginEnabled: true,
				emailPasswordLoginEnabled: false,
				passkeyLoginEnabled: false,
				siweLoginEnabled: false,
				googleOneTapEnabled: false,
			},
		}).find((candidate) => candidate.id === "siwe-v2");

		expect(plugin).toBeDefined();
	});

	it("registers Google One Tap only when the runtime switch and client id are ready", () => {
		const authenticationSettings = {
			socialProviderLimit: 20,
			emailOtpLoginEnabled: true,
			emailPasswordLoginEnabled: false,
			passkeyLoginEnabled: false,
			siweLoginEnabled: true,
			googleOneTapEnabled: true,
		};
		const enabled = createAuthPlugins(makeOriginEnv(), {
			authenticationSettings,
			googleOneTapClientId: "google-client-id",
		}).find((candidate) => candidate.id === "one-tap");
		expect(enabled?.options).toMatchObject({
			clientId: "google-client-id",
			disableSignup: false,
		});

		const missingClient = createAuthPlugins(makeOriginEnv(), {
			authenticationSettings,
		}).find((candidate) => candidate.id === "one-tap");
		expect(missingClient).toBeUndefined();
	});

	it("verifies a real EIP-191 personal signature for the recovered EOA", async () => {
		const plugin = createAuthPlugins(enabledSiweEnv).find(
			(candidate) => candidate.id === "siwe-v2",
		);
		if (!plugin || !("verifyMessage" in plugin.options)) {
			throw new Error("Expected the enabled SIWE verifier");
		}
		const message = "CinaSeek SIWE production verifier: 登录验证 🔐";
		const messageBytes = utf8ToBytes(message);
		const prefix = utf8ToBytes(
			`\x19Ethereum Signed Message:\n${messageBytes.length}`,
		);
		const payload = new Uint8Array(prefix.length + messageBytes.length);
		payload.set(prefix);
		payload.set(messageBytes, prefix.length);
		const privateKey = new Uint8Array(32);
		privateKey[31] = 1;
		const signature = secp256k1.sign(keccak_256(payload), privateKey);
		const signatureBytes = new Uint8Array(65);
		signatureBytes.set(signature.toCompactRawBytes());
		signatureBytes[64] = signature.recovery + 27;
		const publicKey = secp256k1.getPublicKey(privateKey, false);
		const address = `0x${bytesToHex(keccak_256(publicKey.slice(1)).slice(-20))}`;

		await expect(
			plugin.options.verifyMessage({
				message,
				signature: `0x${bytesToHex(signatureBytes)}`,
				address,
				chainId: 1,
			}),
		).resolves.toBe(true);
	});
});

describe("Stripe organization billing policy", () => {
	it("allows only organization owners and administrators", () => {
		expect(canManageOrganizationBilling("owner")).toBe(true);
		expect(canManageOrganizationBilling("admin,member")).toBe(true);
		expect(canManageOrganizationBilling("member")).toBe(false);
		expect(canManageOrganizationBilling("billing-manager")).toBe(false);
	});

	it("registers an authoritative organization reference callback", () => {
		const stripePlugin = createAuthPlugins(
			makeOriginEnv({
				STRIPE_SECRET_KEY: "stripe-secret",
				STRIPE_WEBHOOK_SECRET: "stripe-webhook-secret",
				STRIPE_DEFAULT_PRICE_ID: "price_production",
				CINAAUTH_ENTITLEMENT_CONFIG: entitlementConfig(),
			}),
		).find((candidate) => candidate.id === "stripe");

		expect(stripePlugin).toBeDefined();
		expect(stripePlugin?.options).toMatchObject({
			organization: { enabled: true },
			subscription: {
				enabled: true,
				authorizeReference: expect.any(Function),
				plans: [
					expect.objectContaining({
						name: "default",
						limits: expect.any(Object),
					}),
				],
			},
		});
	});
});

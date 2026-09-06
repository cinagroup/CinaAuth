import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const workerDir = dirname(scriptDir);
const repoRoot = dirname(dirname(workerDir));

const failures = [];
let passed = 0;

const rel = (file) => relative(repoRoot, file).replaceAll("\\", "/");

const read = (file) => readFileSync(file, "utf8");

const check = (condition, message) => {
	if (condition) {
		passed += 1;
		return;
	}
	failures.push(message);
};

const checkIncludes = (content, token, file, reason) => {
	check(
		content.includes(token),
		`${rel(file)} must include ${JSON.stringify(token)} (${reason})`,
	);
};

const checkIncludesAll = (content, tokens, file, reason) => {
	for (const token of tokens) {
		checkIncludes(content, token, file, reason);
	}
};

const readJson = (file) => {
	try {
		return JSON.parse(read(file));
	} catch (error) {
		failures.push(`${rel(file)} is not valid JSON: ${error.message}`);
		return {};
	}
};

const SECRETS_STORE_ID = "346e2b4b86334bc29083c064116e91cf";

const expectedSecretsStoreBindings = {
	auth: [
		{
			binding: "CINAAUTH_DELIVERY_WEBHOOK_SECRET_STORE_V2",
			secret_name: "CINAAUTH_DELIVERY_WEBHOOK_SECRET_V2",
		},
		{
			binding: "CINAAUTH_ERASURE_WEBHOOK_SECRET_STORE_V2",
			secret_name: "CINAAUTH_ERASURE_WEBHOOK_SECRET_V2",
		},
		{
			binding: "CINAADMIN_OIDC_CLIENT_SECRET_STORE_V2",
			secret_name: "CINAADMIN_OIDC_CLIENT_SECRET_V2",
		},
		{
			binding: "CINAADMIN_OIDC_BRIDGE_SECRET_STORE_V2",
			secret_name: "CINAADMIN_OIDC_BRIDGE_SECRET_V2",
		},
		{
			binding: "CINATOKEN_IDENTITY_EVENTS_SECRET_STORE_V2",
			secret_name: "CINATOKEN_IDENTITY_EVENTS_SECRET_V2",
		},
	],
	delivery: [
		{
			binding: "CINAAUTH_DELIVERY_WEBHOOK_SECRET_STORE_V2",
			secret_name: "CINAAUTH_DELIVERY_WEBHOOK_SECRET_V2",
		},
		{
			binding: "CINAAUTH_DELIVERY_CONFIG_KEK_STORE",
			secret_name: "CINAAUTH_DELIVERY_CONFIG_KEK_V1",
		},
	],
	privacyErasure: [
		{
			binding: "CINAAUTH_ERASURE_WEBHOOK_SECRET_STORE_V2",
			secret_name: "CINAAUTH_ERASURE_WEBHOOK_SECRET_V2",
		},
		{
			binding: "CINAAUTH_ERASURE_CONFIG_KEK_STORE",
			secret_name: "CINAAUTH_ERASURE_CONFIG_KEK_V1",
		},
	],
	admin: [
		{
			binding: "CINAADMIN_OIDC_CLIENT_SECRET_STORE_V2",
			secret_name: "CINAADMIN_OIDC_CLIENT_SECRET_V2",
		},
		{
			binding: "CINAADMIN_OIDC_BRIDGE_SECRET_STORE_V2",
			secret_name: "CINAADMIN_OIDC_BRIDGE_SECRET_V2",
		},
		{
			binding: "CINAADMIN_OIDC_TRANSACTION_SECRET_STORE_V2",
			secret_name: "CINAADMIN_OIDC_TRANSACTION_SECRET_V2",
		},
	],
};

const secretStoreBindingKey = ({ binding, store_id, secret_name }) =>
	`${binding}\u0000${store_id}\u0000${secret_name}`;

const checkExactSecretsStoreBindings = (config, file, expectedBindings) => {
	const configuredBindings = config.secrets_store_secrets;
	check(
		Array.isArray(configuredBindings),
		`${rel(file)} must declare secrets_store_secrets`,
	);
	if (!Array.isArray(configuredBindings)) return;

	const entries = configuredBindings.filter(
		(entry) => entry && typeof entry === "object" && !Array.isArray(entry),
	);
	check(
		entries.length === configuredBindings.length,
		`${rel(file)} secrets_store_secrets entries must be objects`,
	);
	check(
		configuredBindings.length === expectedBindings.length,
		`${rel(file)} must declare exactly ${expectedBindings.length} active Secrets Store binding(s)`,
	);

	const exactKeys = entries.map(secretStoreBindingKey);
	check(
		new Set(exactKeys).size === exactKeys.length,
		`${rel(file)} must not duplicate Secrets Store binding triples`,
	);
	check(
		new Set(entries.map((entry) => entry.binding)).size === entries.length,
		`${rel(file)} must not duplicate Secrets Store binding names`,
	);
	check(
		new Set(entries.map((entry) => entry.secret_name)).size === entries.length,
		`${rel(file)} must not map one active secret name more than once`,
	);

	for (const entry of entries) {
		check(
			Object.keys(entry).sort().join(",") === "binding,secret_name,store_id",
			`${rel(file)} Secrets Store entries must contain only binding, store_id, and secret_name`,
		);
	}

	const expectedKeys = new Set(
		expectedBindings.map((entry) =>
			secretStoreBindingKey({ ...entry, store_id: SECRETS_STORE_ID }),
		),
	);
	for (const expected of expectedBindings) {
		const expectedKey = secretStoreBindingKey({
			...expected,
			store_id: SECRETS_STORE_ID,
		});
		check(
			exactKeys.filter((key) => key === expectedKey).length === 1,
			`${rel(file)} must map ${expected.binding} exactly once to ${expected.secret_name} in Secrets Store ${SECRETS_STORE_ID}`,
		);
	}
	check(
		exactKeys.every((key) => expectedKeys.has(key)),
		`${rel(file)} must not contain unexpected or incorrectly mapped Secrets Store bindings`,
	);
};

const packageFile = join(workerDir, "package.json");
const repoPackageFile = join(repoRoot, "package.json");
const cloudflareEdgeMitigationFile = join(
	repoRoot,
	"scripts",
	"cloudflare-edge-mitigation.mjs",
);
const cloudflareEdgeMitigationTestFile = join(
	repoRoot,
	"scripts",
	"cloudflare-edge-mitigation.test.mjs",
);
const deploymentTargetParserFile = join(
	repoRoot,
	"scripts",
	"cloudflare-deployment-target.mjs",
);
const wranglerFile = join(workerDir, "wrangler.json");
const devVarsExampleFile = join(workerDir, ".dev.vars.example");
const indexFile = join(workerDir, "src", "index.ts");
const adminConfigurationFile = join(workerDir, "src", "admin-configuration.ts");
const adminSendVerificationFile = join(
	workerDir,
	"src",
	"admin-send-verification.ts",
);
const impersonationMutationGuardFile = join(
	workerDir,
	"src",
	"impersonation-mutation-guard.ts",
);
const authFile = join(workerDir, "src", "auth.ts");
const authRoutingFile = join(workerDir, "src", "auth-routing.ts");
const authenticationMethodGateFile = join(
	workerDir,
	"src",
	"authentication-method-gate.ts",
);
const adminSocialProvidersFile = join(
	workerDir,
	"src",
	"admin-social-providers.ts",
);
const adminAgentAuthFile = join(workerDir, "src", "admin-agent-auth.ts");
const captchaConfigFile = join(workerDir, "src", "captcha-config.ts");
const capabilitiesFile = join(workerDir, "src", "capabilities.ts");
const socialProviderStoreFile = join(
	workerDir,
	"src",
	"social-provider-store.ts",
);
const entitlementsFile = join(workerDir, "src", "entitlements.ts");
const entitlementEnforcementFile = join(
	workerDir,
	"src",
	"entitlement-enforcement.ts",
);
const entitlementRuntimeFile = join(workerDir, "src", "entitlement-runtime.ts");
const entitlementLockFile = join(workerDir, "src", "entitlement-lock.ts");
const superAdminGovernanceFile = join(
	workerDir,
	"src",
	"super-admin-governance.ts",
);
const superAdminDatabaseInvariantFile = join(
	workerDir,
	"src",
	"super-admin-database-invariant.ts",
);
const providerNamespaceInvariantFile = join(
	workerDir,
	"src",
	"provider-namespace-invariant.ts",
);
const organizationIdentityOutboxInvariantFile = join(
	workerDir,
	"src",
	"organization-identity-outbox-invariant.ts",
);
const organizationIdentityEventsFile = join(
	workerDir,
	"src",
	"organization-identity-events.ts",
);
const databaseInvariantsFile = join(workerDir, "src", "database-invariants.ts");
const adminPluginFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"admin",
	"admin.ts",
);
const adminSuperAdminGuardFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"admin",
	"super-admin.ts",
);
const auditRetentionFile = join(workerDir, "src", "audit-retention.ts");
const oauthConfigFile = join(workerDir, "src", "oauth-config.ts");
const pluginsFile = join(workerDir, "src", "plugins.ts");
const socialProviderCatalogFile = join(
	workerDir,
	"src",
	"social-provider-catalog.ts",
);
const emailOtpTargetRateLimitFile = join(
	workerDir,
	"src",
	"email-otp-target-rate-limit.ts",
);
const originConfigFile = join(workerDir, "src", "origin-config.ts");
const coreRedirectUriFile = join(
	repoRoot,
	"packages",
	"core",
	"src",
	"utils",
	"redirect-uri.ts",
);
const oauthRegisterFile = join(
	repoRoot,
	"packages",
	"oauth-provider",
	"src",
	"register.ts",
);
const databaseFile = join(workerDir, "src", "database.ts");
const d1MigrationFile = join(workerDir, "src", "d1-migration.ts");
const scimOwnershipMigrationFile = join(
	workerDir,
	"src",
	"scim-ownership-migration.ts",
);
const rateLimitFile = join(workerDir, "src", "rate-limit.ts");
const rateLimitStorageFile = join(workerDir, "src", "rate-limit-storage.ts");
const deliveryFile = join(workerDir, "src", "delivery.ts");
const privacyExportFile = join(workerDir, "src", "privacy-export.ts");
const privacyDeletionRuntimeFile = join(
	workerDir,
	"src",
	"privacy-deletion.ts",
);
const envFile = join(workerDir, "src", "env.d.ts");
const siweRuntimeConfigFile = join(workerDir, "src", "siwe-runtime-config.ts");
const siweRequestBodyLimitFile = join(
	workerDir,
	"src",
	"siwe-request-body-limit.ts",
);
const remotePreflightFile = join(
	workerDir,
	"scripts",
	"check-cloudflare-remote.mjs",
);
const authReadinessCheckFile = join(
	workerDir,
	"scripts",
	"check-auth-readiness.mjs",
);
const runtimeCapabilitiesCheckFile = join(
	workerDir,
	"scripts",
	"check-runtime-capabilities.mjs",
);
const configureHyperdriveFile = join(
	workerDir,
	"scripts",
	"configure-hyperdrive.mjs",
);
const configureTurnstileFile = join(
	workerDir,
	"scripts",
	"configure-turnstile.mjs",
);
const configureDeliveryQueuesFile = join(
	workerDir,
	"scripts",
	"configure-delivery-queues.mjs",
);
const configurePrivacyExportFile = join(
	workerDir,
	"scripts",
	"configure-privacy-export.mjs",
);
const checkPlanetScaleBackupsFile = join(
	workerDir,
	"scripts",
	"check-planetscale-backups.mjs",
);
const provisionSecretsFile = join(
	workerDir,
	"scripts",
	"provision-secrets.mjs",
);
const preservedSecretCheckFile = join(
	repoRoot,
	"scripts",
	"check-cloudflare-preserved-secrets.mjs",
);
const deliveryRemotePreflightFile = join(
	repoRoot,
	"workers",
	"delivery",
	"scripts",
	"check-cloudflare-remote.mjs",
);
const deliveryAcceptanceFile = join(
	repoRoot,
	"workers",
	"delivery",
	"scripts",
	"run-provider-acceptance.mjs",
);
const productionLifecycleAcceptanceFile = join(
	workerDir,
	"scripts",
	"run-production-lifecycle-acceptance.mjs",
);
const deliveryPackageFile = join(
	repoRoot,
	"workers",
	"delivery",
	"package.json",
);
const deliveryProvisionFile = join(
	repoRoot,
	"workers",
	"delivery",
	"scripts",
	"provision-secrets.mjs",
);
const deliveryWranglerFile = join(
	repoRoot,
	"workers",
	"delivery",
	"wrangler.json",
);
const deliveryDeploymentFile = join(
	repoRoot,
	"workers",
	"delivery",
	"DEPLOYMENT.md",
);
const privacyErasureDir = join(repoRoot, "workers", "privacy-erasure");
const privacyErasureIndexFile = join(privacyErasureDir, "src", "index.ts");
const privacyErasureCoordinatorFile = join(
	privacyErasureDir,
	"src",
	"coordinator.ts",
);
const privacyErasureProtocolFile = join(
	privacyErasureDir,
	"src",
	"protocol.ts",
);
const privacyErasureManagementFile = join(
	privacyErasureDir,
	"src",
	"management.ts",
);
const privacyErasurePackageFile = join(privacyErasureDir, "package.json");
const privacyErasureWranglerFile = join(privacyErasureDir, "wrangler.json");
const privacyErasureProvisionFile = join(
	privacyErasureDir,
	"scripts",
	"provision-secrets.mjs",
);
const privacyErasureRemoteFile = join(
	privacyErasureDir,
	"scripts",
	"check-cloudflare-remote.mjs",
);
const privacyErasureDeploymentFile = join(privacyErasureDir, "DEPLOYMENT.md");
const workflowFile = join(
	repoRoot,
	".github",
	"workflows",
	"deploy-cloudflare.yml",
);
const ciWorkflowFile = join(repoRoot, ".github", "workflows", "ci.yml");
const accountWorkflowFile = join(
	repoRoot,
	".github",
	"workflows",
	"deploy-account-portal.yml",
);
const adminWorkflowFile = join(
	repoRoot,
	".github",
	"workflows",
	"deploy-admin-console.yml",
);
const nextDemoDir = join(repoRoot, "apps", "account-portal");
const accountPackageFile = join(nextDemoDir, "package.json");
const accountDeployFile = join(nextDemoDir, "deploy-cf.mjs");
const localDeploymentScriptFile = join(repoRoot, "deploy-cloudflare.sh");
const accountWranglerFile = join(nextDemoDir, "wrangler.toml");
const accountMiddlewareFile = join(nextDemoDir, "middleware.ts");
const accountSignInExperienceFile = join(
	nextDemoDir,
	"lib",
	"sign-in-experience.ts",
);
const accountEmailOtpFlowFile = join(nextDemoDir, "lib", "email-otp-flow.ts");
const accountHomeI18nFile = join(nextDemoDir, "lib", "i18n.ts");
const accountDashboardI18nFile = join(nextDemoDir, "lib", "dashboard-i18n.ts");
const accountLegacyAuthRedirectFile = join(
	nextDemoDir,
	"lib",
	"legacy-auth-redirect.ts",
);
const accountSignInPageFile = join(
	nextDemoDir,
	"app",
	"(auth)",
	"sign-in",
	"page.tsx",
);
const accountSignInComponentFile = join(
	nextDemoDir,
	"app",
	"(auth)",
	"sign-in",
	"_components",
	"sign-in.tsx",
);
const accountSignInPageShellFile = join(
	nextDemoDir,
	"components",
	"auth",
	"sign-in-page-shell.tsx",
);
const accountLegacySignUpPageFile = join(
	nextDemoDir,
	"app",
	"(auth)",
	"sign-up",
	"page.tsx",
);
const accountLegacyEmailSignUpPageFile = join(
	nextDemoDir,
	"app",
	"(auth)",
	"sign-up",
	"email",
	"page.tsx",
);
const legacyAdminPageFile = join(nextDemoDir, "app", "admin", "page.tsx");
const adminConsoleDir = join(repoRoot, "apps", "admin-console");
const adminPackageFile = join(adminConsoleDir, "package.json");
const adminWranglerFile = join(adminConsoleDir, "wrangler.jsonc");
const adminFetcherFile = join(
	adminConsoleDir,
	"src",
	"lib",
	"cinaauth",
	"fetcher.ts",
);
const adminOidcClientFile = join(
	adminConsoleDir,
	"src",
	"lib",
	"cinaauth",
	"oidc-client.ts",
);
const adminOidcCallbackFile = join(
	adminConsoleDir,
	"src",
	"app",
	"api",
	"auth",
	"oidc",
	"callback",
	"route.ts",
);
const adminOidcLoginFile = join(
	adminConsoleDir,
	"src",
	"app",
	"api",
	"auth",
	"oidc",
	"login",
	"route.ts",
);
const adminProvisionSecretsFile = join(
	adminConsoleDir,
	"scripts",
	"provision-secrets.mjs",
);
const authWebContractFile = join(
	repoRoot,
	"packages",
	"auth-web-contract",
	"src",
	"admin.ts",
);
const adminOidcContractFile = join(
	repoRoot,
	"packages",
	"auth-web-contract",
	"src",
	"admin-oidc.ts",
);
const authEntitlementContractFile = join(
	repoRoot,
	"packages",
	"auth-web-contract",
	"src",
	"entitlements.ts",
);
const stripeSchemaFile = join(
	repoRoot,
	"packages",
	"stripe",
	"src",
	"schema.ts",
);
const authCapabilitiesFile = join(nextDemoDir, "lib", "auth-capabilities.ts");
const authApiFile = join(nextDemoDir, "lib", "auth-api.ts");
const accountAuthTransportFile = join(nextDemoDir, "lib", "auth.ts");
const accountAuthRuntimeConfigFile = join(
	nextDemoDir,
	"lib",
	"auth-runtime-config.ts",
);
const billingConsolePolicyFile = join(nextDemoDir, "lib", "billing-console.ts");
const accountDashboardPageFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"page.tsx",
);
const subscriptionCardFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"_components",
	"subscription-card.tsx",
);
const pricingPageFile = join(nextDemoDir, "app", "pricing", "page.tsx");
const pricingComponentFile = join(nextDemoDir, "components", "pricing.tsx");
const authProxyPackageFile = join(
	repoRoot,
	"packages",
	"auth-proxy",
	"src",
	"index.ts",
);
const authClientFile = join(nextDemoDir, "lib", "auth-client.ts");
const oauthProviderButtonsFile = join(
	nextDemoDir,
	"components",
	"oauth-provider-buttons.tsx",
);
const accountOAuthBuildCheckFile = join(
	nextDemoDir,
	"scripts",
	"check-oauth-build.mjs",
);
const accountBuildReadinessFile = join(
	nextDemoDir,
	"lib",
	"account-build-readiness.ts",
);
const accountBuildReadinessRouteFile = join(
	nextDemoDir,
	"app",
	"api",
	"build-readiness",
	"route.ts",
);
const globalCssFile = join(nextDemoDir, "app", "globals.css");
const authProxyRouteFile = join(
	nextDemoDir,
	"app",
	"api",
	"auth",
	"[...all]",
	"route.ts",
);
const accountDiagnoseRouteFile = join(
	nextDemoDir,
	"app",
	"api",
	"diagnose",
	"route.ts",
);
const accountMcpRouteFile = join(nextDemoDir, "app", "api", "mcp", "route.ts");
const turnstileComponentFile = join(
	nextDemoDir,
	"components",
	"turnstile-challenge.tsx",
);
const privacyCenterPageFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"privacy",
	"page.tsx",
);
const privacyCenterComponentFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"privacy",
	"privacy-center.tsx",
);
const privacyCenterPolicyFile = join(nextDemoDir, "lib", "privacy-center.ts");
const securityCenterPageFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"security",
	"page.tsx",
);
const securityCenterComponentFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"security",
	"security-center.tsx",
);
const securityCenterPolicyFile = join(nextDemoDir, "lib", "security-center.ts");
const organizationConsolePageFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"organization",
	"page.tsx",
);
const organizationConsoleComponentFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"organization",
	"organization-console.tsx",
);
const advancedOrganizationComponentFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"organization",
	"advanced-organization-card.tsx",
);
const advancedOrganizationPolicyFile = join(
	nextDemoDir,
	"lib",
	"advanced-organization-console.ts",
);
const advancedOrganizationMutationFile = join(
	nextDemoDir,
	"data",
	"organization",
	"advanced-organization-mutations.ts",
);
const organizationAuditComponentFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"organization",
	"organization-audit-card.tsx",
);
const organizationAuditDataFile = join(
	nextDemoDir,
	"data",
	"organization",
	"organization-audit.ts",
);
const organizationAuditExportPolicyFile = join(
	nextDemoDir,
	"lib",
	"organization-audit-export.ts",
);
const enterpriseConnectionsComponentFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"organization",
	"enterprise-connections-card.tsx",
);
const ssoProviderManagerFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"organization",
	"sso-provider-manager.tsx",
);
const ssoProviderConsolePolicyFile = join(
	nextDemoDir,
	"lib",
	"sso-provider-console.ts",
);
const organizationConsolePolicyFile = join(
	nextDemoDir,
	"lib",
	"organization-console.ts",
);
const developerConsolePageFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"developer",
	"page.tsx",
);
const developerConsoleComponentFile = join(
	nextDemoDir,
	"app",
	"dashboard",
	"developer",
	"developer-console.tsx",
);
const developerConsolePolicyFile = join(
	nextDemoDir,
	"lib",
	"developer-console.ts",
);
const organizationRoleMutationFile = join(
	nextDemoDir,
	"data",
	"organization",
	"member-role-update-mutation.ts",
);
const organizationLeaveMutationFile = join(
	nextDemoDir,
	"data",
	"organization",
	"organization-leave-mutation.ts",
);
const enterpriseConnectionsMutationFile = join(
	nextDemoDir,
	"data",
	"organization",
	"enterprise-connection-mutations.ts",
);
const accountVitestConfigFile = join(nextDemoDir, "vitest.config.mts");
const siweWalletFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"siwe-v2",
	"wallets.ts",
);
const siweProofFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"siwe-v2",
	"verify-proof.ts",
);
const privacyCenterPluginFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"privacy-center",
	"index.ts",
);
const privacyCenterDeletionFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"privacy-center",
	"deletion.ts",
);
const privacyCenterAsyncExportFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"privacy-center",
	"async-export.ts",
);
const sessionRouteFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"api",
	"routes",
	"session.ts",
);
const auditCaptureFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"audit-log",
	"capture.ts",
);
const auditRoutesFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"audit-log",
	"routes.ts",
);
const auditPluginFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"audit-log",
	"index.ts",
);
const customSessionFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"custom-session",
	"index.ts",
);
const customSessionCookieHeadersFile = join(
	repoRoot,
	"packages",
	"cinaauth",
	"src",
	"plugins",
	"custom-session",
	"cookie-headers.ts",
);
const protectedFormFiles = [
	join(nextDemoDir, "components", "forms", "email-otp-form.tsx"),
];
const deploymentDocFile = join(workerDir, "DEPLOYMENT.md");
const siweStagingDocFile = join(repoRoot, "docs", "SIWE_STAGING.md");
const siweStagingInventoryFile = join(
	workerDir,
	"scripts",
	"siwe-staging-inventory.mjs",
);
const siweStagingInventoryTestFile = join(
	workerDir,
	"scripts",
	"siwe-staging-inventory.test.mjs",
);
const verifySiweStagingFile = join(
	workerDir,
	"scripts",
	"verify-siwe-staging.mjs",
);
const verifySiweStagingTestFile = join(
	workerDir,
	"scripts",
	"verify-siwe-staging.test.mjs",
);
const chineseDeploymentDocFile = join(
	repoRoot,
	"docs",
	"CLOUDFLARE_DEPLOYMENT.md",
);
const functionalDesignFile = join(
	repoRoot,
	"CINAAUTH_FUNCTIONAL_DESIGN.zh-CN.md",
);
const privacyCenterDocFile = join(
	repoRoot,
	"docs",
	"content",
	"docs",
	"plugins",
	"privacy-center.mdx",
);
const oauthProductionDocFile = join(
	repoRoot,
	"docs",
	"CINAAUTH_OAUTH_PRODUCTION.md",
);
const developerConsoleDocFile = join(
	repoRoot,
	"docs",
	"CINAAUTH_DEVELOPER_CONSOLE.md",
);
const gitignoreFile = join(repoRoot, ".gitignore");

const packageJson = readJson(packageFile);
const wrangler = readJson(wranglerFile);
const repoPackage = readJson(repoPackageFile);
const cloudflareEdgeMitigation = read(cloudflareEdgeMitigationFile);
const cloudflareEdgeMitigationTest = read(cloudflareEdgeMitigationTestFile);
const deploymentTargetParser = read(deploymentTargetParserFile);
const indexTs = read(indexFile);
const adminConfigurationTs = read(adminConfigurationFile);
const adminSendVerificationTs = read(adminSendVerificationFile);
const impersonationMutationGuardTs = read(impersonationMutationGuardFile);
const authTs = read(authFile);
const authRoutingTs = read(authRoutingFile);
const authenticationMethodGateTs = read(authenticationMethodGateFile);
const adminSocialProvidersTs = read(adminSocialProvidersFile);
const adminAgentAuthTs = read(adminAgentAuthFile);
const captchaConfigTs = read(captchaConfigFile);
const capabilitiesTs = read(capabilitiesFile);
const socialProviderStoreTs = read(socialProviderStoreFile);
const entitlementsTs = read(entitlementsFile);
const entitlementEnforcementTs = read(entitlementEnforcementFile);
const entitlementRuntimeTs = read(entitlementRuntimeFile);
const entitlementLockTs = read(entitlementLockFile);
const superAdminGovernanceTs = read(superAdminGovernanceFile);
const superAdminDatabaseInvariantTs = read(superAdminDatabaseInvariantFile);
const providerNamespaceInvariantTs = read(providerNamespaceInvariantFile);
const organizationIdentityOutboxInvariantTs = read(
	organizationIdentityOutboxInvariantFile,
);
const organizationIdentityEventsTs = read(organizationIdentityEventsFile);
const databaseInvariantsTs = read(databaseInvariantsFile);
const adminPluginTs = read(adminPluginFile);
const adminSuperAdminGuardTs = read(adminSuperAdminGuardFile);
const auditRetentionTs = read(auditRetentionFile);
const oauthConfigTs = read(oauthConfigFile);
const pluginsTs = read(pluginsFile);
const socialProviderCatalogTs = read(socialProviderCatalogFile);
const emailOtpTargetRateLimitTs = read(emailOtpTargetRateLimitFile);
const originConfigTs = read(originConfigFile);
const coreRedirectUriTs = read(coreRedirectUriFile);
const oauthRegisterTs = read(oauthRegisterFile);
const databaseTs = read(databaseFile);
const d1MigrationTs = read(d1MigrationFile);
const scimOwnershipMigrationTs = read(scimOwnershipMigrationFile);
const rateLimitTs = read(rateLimitFile);
const rateLimitStorageTs = read(rateLimitStorageFile);
const deliveryTs = read(deliveryFile);
const privacyExportTs = read(privacyExportFile);
const privacyDeletionRuntimeTs = read(privacyDeletionRuntimeFile);
const envTs = read(envFile);
const siweRuntimeConfigTs = read(siweRuntimeConfigFile);
const siweRequestBodyLimitTs = read(siweRequestBodyLimitFile);
const remotePreflight = read(remotePreflightFile);
const authReadinessCheck = read(authReadinessCheckFile);
const runtimeCapabilitiesCheck = read(runtimeCapabilitiesCheckFile);
const configureHyperdrive = read(configureHyperdriveFile);
const configureTurnstile = read(configureTurnstileFile);
const configureDeliveryQueues = read(configureDeliveryQueuesFile);
const configurePrivacyExport = read(configurePrivacyExportFile);
const checkPlanetScaleBackups = read(checkPlanetScaleBackupsFile);
const provisionSecrets = read(provisionSecretsFile);
const preservedSecretCheck = read(preservedSecretCheckFile);
const deliveryProvision = read(deliveryProvisionFile);
const deliveryRemotePreflight = read(deliveryRemotePreflightFile);
const deliveryAcceptance = read(deliveryAcceptanceFile);
const productionLifecycleAcceptance = read(productionLifecycleAcceptanceFile);
const deliveryPackage = readJson(deliveryPackageFile);
const deliveryWrangler = readJson(deliveryWranglerFile);
const deliveryDeployment = read(deliveryDeploymentFile);
const privacyErasureIndex = read(privacyErasureIndexFile);
const privacyErasureCoordinator = read(privacyErasureCoordinatorFile);
const privacyErasureProtocol = read(privacyErasureProtocolFile);
const privacyErasureManagement = read(privacyErasureManagementFile);
const privacyErasurePackage = readJson(privacyErasurePackageFile);
const privacyErasureWrangler = readJson(privacyErasureWranglerFile);
const privacyErasureProvision = read(privacyErasureProvisionFile);
const privacyErasureRemote = read(privacyErasureRemoteFile);
const privacyErasureDeployment = read(privacyErasureDeploymentFile);
const workflow = read(workflowFile);
const ciWorkflow = read(ciWorkflowFile);
const accountWorkflow = read(accountWorkflowFile);
const adminWorkflow = read(adminWorkflowFile);
const workflowJobBlock = (source, job, nextJob) => {
	const start = source.indexOf(`  ${job}:`);
	if (start === -1) return "";
	const end = nextJob ? source.indexOf(`  ${nextJob}:`, start + 1) : -1;
	return source.slice(start, end === -1 ? undefined : end);
};
const accountPackage = readJson(accountPackageFile);
const accountDeploy = read(accountDeployFile);
const localDeploymentScript = read(localDeploymentScriptFile);
const accountWrangler = read(accountWranglerFile);
const accountMiddleware = read(accountMiddlewareFile);
const accountSignInExperience = read(accountSignInExperienceFile);
const accountEmailOtpFlow = read(accountEmailOtpFlowFile);
const accountHomeI18n = read(accountHomeI18nFile);
const accountDashboardI18n = read(accountDashboardI18nFile);
const accountLegacyAuthRedirect = read(accountLegacyAuthRedirectFile);
const accountSignInPage = read(accountSignInPageFile);
const accountSignInComponent = read(accountSignInComponentFile);
const accountSignInPageShell = read(accountSignInPageShellFile);
const accountLegacySignUpPage = read(accountLegacySignUpPageFile);
const accountLegacyEmailSignUpPage = read(accountLegacyEmailSignUpPageFile);
const legacyAdminPage = read(legacyAdminPageFile);
const adminPackage = readJson(adminPackageFile);
const adminWrangler = read(adminWranglerFile);
const adminWranglerConfig = readJson(adminWranglerFile);
const adminFetcher = read(adminFetcherFile);
const adminOidcClient = read(adminOidcClientFile);
const adminOidcCallback = read(adminOidcCallbackFile);
const adminOidcLogin = read(adminOidcLoginFile);
const adminProvisionSecrets = read(adminProvisionSecretsFile);
const authWebContract = read(authWebContractFile);
const adminOidcContract = read(adminOidcContractFile);
const authEntitlementContractTs = read(authEntitlementContractFile);
const stripeSchemaTs = read(stripeSchemaFile);
const authCapabilitiesTs = read(authCapabilitiesFile);
const authApiTs = read(authApiFile);
const accountAuthTransportTs = read(accountAuthTransportFile);
const accountAuthRuntimeConfigTs = read(accountAuthRuntimeConfigFile);
const accountDiagnoseRouteTs = read(accountDiagnoseRouteFile);
const accountMcpRouteTs = read(accountMcpRouteFile);
const billingConsolePolicyTs = read(billingConsolePolicyFile);
const accountDashboardPageTs = read(accountDashboardPageFile);
const subscriptionCardTs = read(subscriptionCardFile);
const pricingPageTs = read(pricingPageFile);
const pricingComponentTs = read(pricingComponentFile);
const authProxyPackageTs = read(authProxyPackageFile);
const authClientTs = read(authClientFile);
const oauthProviderButtonsTs = read(oauthProviderButtonsFile);
const accountOAuthBuildCheck = read(accountOAuthBuildCheckFile);
const accountBuildReadiness = read(accountBuildReadinessFile);
const accountBuildReadinessRoute = read(accountBuildReadinessRouteFile);
const globalCss = read(globalCssFile);
const authProxyRouteTs = read(authProxyRouteFile);
const turnstileComponentTs = read(turnstileComponentFile);
const privacyCenterPageTs = read(privacyCenterPageFile);
const privacyCenterComponentTs = read(privacyCenterComponentFile);
const privacyCenterPolicyTs = read(privacyCenterPolicyFile);
const securityCenterPageTs = read(securityCenterPageFile);
const securityCenterComponentTs = read(securityCenterComponentFile);
const securityCenterPolicyTs = read(securityCenterPolicyFile);
const organizationConsolePageTs = read(organizationConsolePageFile);
const organizationConsoleComponentTs = read(organizationConsoleComponentFile);
const advancedOrganizationComponentTs = read(advancedOrganizationComponentFile);
const advancedOrganizationPolicyTs = read(advancedOrganizationPolicyFile);
const advancedOrganizationMutationTs = read(advancedOrganizationMutationFile);
const organizationAuditComponentTs = read(organizationAuditComponentFile);
const organizationAuditDataTs = read(organizationAuditDataFile);
const organizationAuditExportPolicyTs = read(organizationAuditExportPolicyFile);
const enterpriseConnectionsComponentTs = read(
	enterpriseConnectionsComponentFile,
);
const ssoProviderManagerTs = read(ssoProviderManagerFile);
const ssoProviderConsolePolicyTs = read(ssoProviderConsolePolicyFile);
const organizationConsolePolicyTs = read(organizationConsolePolicyFile);
const developerConsolePageTs = read(developerConsolePageFile);
const developerConsoleComponentTs = read(developerConsoleComponentFile);
const developerConsolePolicyTs = read(developerConsolePolicyFile);
const organizationRoleMutationTs = read(organizationRoleMutationFile);
const organizationLeaveMutationTs = read(organizationLeaveMutationFile);
const enterpriseConnectionsMutationTs = read(enterpriseConnectionsMutationFile);
const accountVitestConfigTs = read(accountVitestConfigFile);
const siweWalletTs = read(siweWalletFile);
const siweProofTs = read(siweProofFile);
const privacyCenterPluginTs = read(privacyCenterPluginFile);
const privacyCenterDeletionTs = read(privacyCenterDeletionFile);
const privacyCenterAsyncExportTs = read(privacyCenterAsyncExportFile);
const sessionRouteTs = read(sessionRouteFile);
const auditCaptureTs = read(auditCaptureFile);
const auditRoutesTs = read(auditRoutesFile);
const auditPluginTs = read(auditPluginFile);
const customSessionTs = read(customSessionFile);
const customSessionCookieHeadersTs = read(customSessionCookieHeadersFile);
const protectedForms = protectedFormFiles.map((file) => ({
	file,
	content: read(file),
}));
const deploymentDoc = read(deploymentDocFile);
const siweStagingDoc = read(siweStagingDocFile);
const siweStagingInventory = read(siweStagingInventoryFile);
const siweStagingInventoryTest = read(siweStagingInventoryTestFile);
const verifySiweStaging = read(verifySiweStagingFile);
const verifySiweStagingTest = read(verifySiweStagingTestFile);
const chineseDeploymentDoc = read(chineseDeploymentDocFile);
const functionalDesign = read(functionalDesignFile);
const privacyCenterDoc = read(privacyCenterDocFile);
const oauthProductionDoc = read(oauthProductionDocFile);
const developerConsoleDoc = read(developerConsoleDocFile);
const gitignore = read(gitignoreFile);
const devVarsExample = existsSync(devVarsExampleFile)
	? read(devVarsExampleFile)
	: "";

checkIncludesAll(
	captchaConfigTs,
	[
		'TURNSTILE_ACTION = "cinaauth"',
		'"/sign-in/email"',
		'"/phone-number/send-otp"',
		'"/phone-number/request-password-reset"',
		"CLOUDFLARE_TURNSTILE_SITE_KEY",
		"CLOUDFLARE_TURNSTILE_SECRET_KEY",
	],
	captchaConfigFile,
	"Turnstile must fail closed unless the paired keys and protected auth paths are configured",
);
check(
	!captchaConfigTs.includes('"/email-otp/send-verification-otp"'),
	`${rel(captchaConfigFile)} must leave Email OTP on the dedicated IP and recipient rate limits`,
);
check(
	[
		'"/sign-up/email"',
		'"/request-password-reset"',
		'"/sign-in/magic-link"',
		'"/email-otp/request-password-reset"',
		'"/forget-password/email-otp"',
	].every((path) => !captchaConfigTs.includes(path)),
	`${rel(captchaConfigFile)} must not advertise retired sign-up, reset, or Magic Link endpoints as protected production flows`,
);
checkIncludesAll(
	adminSendVerificationTs,
	[
		'const VERIFICATION_TYPES = ["email-otp", "phone-number"] as const',
		"sendVerificationOTP",
		"sendPhoneNumberOTP",
	],
	adminSendVerificationFile,
	"Admin verification delivery must expose only enabled OTP channels",
);
check(
	!adminSendVerificationTs.includes('"magic-link"'),
	`${rel(adminSendVerificationFile)} must not accept the retired Magic Link channel`,
);
checkIncludesAll(
	capabilitiesTs,
	[
		"getTurnstileConfig",
		'"cloudflare-turnstile"',
		"protectedEndpoints",
		"DeliveryProviderCapabilities",
		"version: 5",
		"emailPassword: settings.emailPasswordLoginEnabled",
		"emailOtp: settings.emailOtpLoginEnabled && delivery.email",
		"magicLink: false",
		"phoneOtp: delivery.sms",
		"username: false",
		"passkey: settings.passkeyLoginEnabled",
		"oneTapClientId: oneTap ? googleOneTapClientId : null",
		"isBillingRuntimeReady(env)",
		'providers.push({ id: "google", type: "social" })',
		'providers.push({ id: "github", type: "social" })',
	],
	capabilitiesFile,
	"public capability discovery must expose only the client-safe Turnstile configuration",
);
checkIncludesAll(
	socialProviderStoreTs,
	[
		"DEFAULT_SOCIAL_SIGN_IN_SETTINGS",
		"emailOtpLoginEnabled: true",
		"emailPasswordLoginEnabled: false",
		"passkeyLoginEnabled: false",
		"siweLoginEnabled: true",
		"googleOneTapEnabled: false",
		"capabilitiesProviders.splice(settings.socialProviderLimit)",
		"googleOneTapClientId = null",
	],
	socialProviderStoreFile,
	"runtime authentication methods must default safely and apply the provider limit to One Tap",
);
checkIncludesAll(
	authenticationMethodGateTs,
	[
		'authPath === "/sign-in/email"',
		'authPath === "/sign-in/email-otp"',
		'authPath === "/passkey/verify-authentication"',
		'authPath === "/siwe/verify"',
		'authPath === "/one-tap/callback"',
	],
	authenticationMethodGateFile,
	"disabled runtime authentication methods must fail closed at the Auth API boundary",
);
const authenticationMethodGateIndex = indexTs.indexOf(
	"const disabledAuthenticationMethod = getDisabledAuthenticationMethod(",
);
const requestScopedAuthIndex = indexTs.indexOf(
	'c.set("auth", await createAuth(runtimeEnv))',
);
check(
	authenticationMethodGateIndex >= 0 &&
		requestScopedAuthIndex > authenticationMethodGateIndex,
	`${rel(indexFile)} must enforce runtime authentication switches before invoking the Auth handler`,
);
checkIncludesAll(
	adminSocialProvidersTs,
	[
		"AUTHENTICATION_SETTING_KEYS",
		'"security.policy.publish"',
		"enablingUnavailable",
		'"AUTHENTICATION_METHOD_UNAVAILABLE"',
		"hasEffectiveRuntimeMethod",
		'"LAST_SIGN_IN_METHOD_REQUIRED"',
		"invalidateSocialSignInCache()",
	],
	adminSocialProvidersFile,
	"admin authentication changes must require policy permission, reject unavailable methods, and prevent lockout",
);
checkIncludesAll(
	adminAgentAuthTs,
	[
		'"integration.agent-auth.read"',
		'"integration.agent-auth.manage"',
		"session.session.impersonatedBy",
		"origin !== allowedOrigin",
		"isFreshSession(session.session.createdAt)",
		"RATE_LIMIT_UNAVAILABLE",
		'phase: "intent"',
		'phase: "outcome"',
		'FROM "agent" AS "agent"',
		'FROM "agentHost" AS "host"',
		'FROM "agentCapabilityGrant" AS "grant"',
		'FROM "approvalRequest" AS "approval"',
	],
	adminAgentAuthFile,
	"Agent Auth administration must stay permission-scoped, redacted, fresh-authenticated, origin-bound, rate-limited, and audited",
);
checkIncludesAll(
	indexTs,
	[
		'"/api/auth/admin/agent-auth"',
		'"/api/auth/admin/agent-auth/agents/:id/revoke"',
		'"/api/auth/admin/agent-auth/hosts/:id/revoke"',
		'"/api/auth/admin/agent-auth/grants/:id/revoke"',
		'"/api/auth/admin/agent-auth/approvals/:id/deny"',
	],
	indexFile,
	"the Auth Worker must expose the governed Agent Auth administration routes",
);
checkIncludesAll(
	originConfigTs,
	[
		"CINAAUTH_ACCOUNT_ORIGIN",
		"CINAAUTH_ADMIN_ORIGIN",
		"CINAAUTH_PASSKEY_RP_ID",
		"CINAAUTH_LEGACY_ACCOUNT_ORIGIN",
		"CINAAUTH_OIDC_DEMO_ENVIRONMENT",
		"CINAAUTH_OIDC_DEMO_ORIGIN",
		"CINAAUTH_OIDC_DEMO_CLIENT_ID",
		"resolveOidcDemoProfile",
		'"invalid_cinaauth_oidc_demo_profile"',
		"parseCanonicalHttpsOrigin",
		'url.protocol !== "https:"',
		'url.port !== ""',
		"value !== url.origin",
		'"duplicate_cinaauth_origins"',
		'"invalid_cinaauth_siwe_rp_origin"',
		"config.trustedOrigins.includes(origin)",
	],
	originConfigFile,
	"browser-facing Auth origins must be canonical, role-distinct, SIWE-aligned, and compared as exact origins",
);
checkIncludesAll(
	pluginsTs,
	[
		"cachedTrustedClients",
		"origins.oidcDemoProfile.clientId",
		"client.clientId === origins.oidcDemoProfile?.clientId",
	],
	pluginsFile,
	"OIDC demo trust must use only the client ID from the validated environment profile",
);
checkIncludesAll(
	indexTs,
	[
		"origins.oidcDemoProfile",
		"ensureOidcDemoClient(database, origins.oidcDemoProfile)",
	],
	indexFile,
	"OIDC demo request recognition and client reconciliation must share the validated environment profile",
);
checkIncludesAll(
	authEntitlementContractTs,
	[
		"ENTITLEMENT_FEATURES",
		"ENTITLEMENT_LIMITS",
		"EntitlementSnapshot",
		'"unmetered" | "subscription"',
		'"deployment-default" | "stripe-subscription"',
	],
	authEntitlementContractFile,
	"the shared web contract must expose a versioned, provider-independent entitlement snapshot",
);
checkIncludesAll(
	entitlementsTs,
	[
		"parseEntitlementConfig",
		"getBillingRuntimeConfiguration",
		"CINAAUTH_ENTITLEMENT_CONFIG",
		"createUnmeteredEntitlementSnapshot",
		"auditRetentionDays: 90",
		"selectEntitlementSubscription",
		"loadEntitlementSnapshot",
		"ENTITLEMENT_PLAN_UNMAPPED",
		"ENTITLEMENT_SUBSCRIPTION_AMBIGUOUS",
	],
	entitlementsFile,
	"billing must require a complete policy and fail closed on ambiguous or unmapped subscription state",
);
checkIncludesAll(
	indexTs,
	[
		'app.get("/api/auth/entitlements"',
		"disableCookieCache: true",
		'SELECT "role" FROM "member"',
		'SELECT "plan", "status", "periodEnd", "cancelAtPeriodEnd", "seats"',
		"ENTITLEMENT_STORAGE_UNAVAILABLE",
		"withNoStore(c.json(loaded.snapshot))",
	],
	indexFile,
	"the entitlement endpoint must authenticate, recheck tenant membership, read webhook state locally, fail closed, and disable caching",
);
checkIncludesAll(
	entitlementEnforcementTs,
	[
		"getEntitlementRequestPolicy",
		"evaluateEntitlementAccess",
		'"POST /api/auth/api-key/create"',
		'"POST /api/auth/oauth2/create-client"',
		'"POST /api/auth/organization/create-team"',
		'"POST /api/auth/organization/add-member"',
		'"POST /api/auth/organization/create-role"',
		'"POST /api/auth/sso/register"',
		'"POST /api/auth/scim/generate-token"',
		'"GET /api/auth/audit/organization"',
		"ENTITLEMENT_FEATURE_DISABLED",
		"ENTITLEMENT_LIMIT_REACHED",
		"ENTITLEMENT_USAGE_UNAVAILABLE",
	],
	entitlementEnforcementFile,
	"commercial management paths must have one fail-closed feature and limit policy",
);
checkIncludesAll(
	entitlementRuntimeTs,
	[
		"withRuntimeOrganizationMemberCapacity",
		'FROM "member" WHERE "organizationId" = $1',
		"ENTITLEMENT_LIMIT_REACHED",
		"getEntitlementCapacityLockKey",
	],
	entitlementRuntimeFile,
	"automatic organization provisioning must hold the shared lock through authoritative capacity checks and writes",
);
checkIncludesAll(
	entitlementLockTs,
	["getEntitlementCapacityLockKey", "pg_advisory_xact_lock"],
	entitlementLockFile,
	"all finite organization member mutations must derive the same PostgreSQL advisory-lock key",
);
checkIncludesAll(
	pluginsTs,
	[
		"withOrganizationMemberProvisioning",
		"withRuntimeOrganizationMemberCapacity",
	],
	pluginsFile,
	"SSO and SCIM automatic membership provisioning must use the atomic runtime capacity wrapper",
);
checkIncludesAll(
	indexTs,
	[
		"resolveEntitlementSubject",
		"hasOrganizationMembership",
		"getEntitlementUsage",
		"cinaauth.entitlement_enforcement.failed",
		"getEntitlementRequestPolicy",
		"evaluateEntitlementAccess",
	],
	indexFile,
	"the Auth Worker must resolve authoritative subjects and enforce policy before plugin writes",
);
checkIncludesAll(
	auditRetentionTs,
	[
		"DEFAULT_AUDIT_RETENTION_DAYS = 90",
		"getAuditRetentionPolicy",
		"policy.limits.auditRetentionDays",
	],
	auditRetentionFile,
	"audit data lifecycle must derive from the same policy as commercial access",
);
checkIncludesAll(
	indexTs,
	[
		"getAuditRetentionPolicy",
		'FROM "subscription"',
		"\"subscription\".\"status\" IN (\\'active\\', \\'trialing\\')",
		"retentionMode: retention.mode",
	],
	indexFile,
	"scheduled organization audit retention must follow active subscription policy and preserve ambiguous states",
);
checkIncludesAll(
	stripeSchemaTs,
	["referenceId:", "index: true"],
	stripeSchemaFile,
	"subscription entitlement and retention lookups must have a reference index",
);
checkIncludesAll(
	pluginsTs,
	[
		"getTurnstileConfig",
		"TURNSTILE_PROTECTED_ENDPOINTS",
		"expectedAction: TURNSTILE_ACTION",
		"allowedHostnames",
	],
	pluginsFile,
	"the server captcha plugin must validate action and hostname on every protected path",
);
checkIncludesAll(
	pluginsTs,
	[
		"getSiweRuntimeConfig",
		"if (siweRuntime.enabled)",
		"domain: siweRuntime.rpDomain",
		"uri: siweRuntime.rpUri",
		"allowedChainIds: siweRuntime.allowedChainIds",
		"legacyNonce: siweRuntime.allowLegacy",
		"allowUserCreation: siweRuntime.autoSignup",
		"recoverPersonalSignAddress",
	],
	pluginsFile,
	"SIWE must be omitted while disabled and use only the strict EOA production contract when enabled",
);
checkIncludesAll(
	capabilitiesTs,
	["getSiweRuntimeConfig", "siwe: settings.siweLoginEnabled && siwe.enabled"],
	capabilitiesFile,
	"public SIWE capability must derive from the same fail-closed runtime configuration as the plugin",
);
checkIncludesAll(
	authTs,
	[
		"emailAndPassword:",
		"enabled: social.emailPasswordLoginEnabled",
		"disableSignUp: true",
		"SECURITY_FRESH_AGE_SECONDS = 15 * 60",
		"freshAge: SECURITY_FRESH_AGE_SECONDS",
		"deleteUser:",
		"enabled: true",
		"disableImplicitLinking: true",
		"requireLocalEmailVerified: true",
		"allowDifferentEmails: false",
		"allowUnlinkingAll: false",
	],
	authFile,
	"production account lifecycle actions must require recent authentication and explicit identity linking",
);
checkIncludesAll(
	pluginsTs,
	[
		"emailOTP({",
		"disableImplicitSignUp: false",
		"disablePasswordReset: true",
		'storeOTP: "encrypted"',
		"createEmailOtpTargetRateLimitPlugin(env)",
		"allowPasswordless: true",
		"requireFreshSessionForPasswordless: true",
		'additionalSignInEndpoints: ["/sign-in/email-otp"]',
	],
	pluginsFile,
	"production email authentication must create first-time users only after encrypted OTP verification and opt into two-factor step-up",
);
checkIncludesAll(
	pluginsTs,
	["page: `${origins.accountOrigin}/sign-in`"],
	pluginsFile,
	"the OIDC account-creation prompt must use the unified Accounts entry",
);
checkIncludesAll(
	socialProviderCatalogTs,
	["disableImplicitSignUp: false", "disableSignUp: false"],
	socialProviderCatalogFile,
	"configured social providers must allow verified first-time callbacks to create users",
);
const emailOtpTargetLimitPluginIndex = pluginsTs.indexOf(
	"\n\t\tcreateEmailOtpTargetRateLimitPlugin(env),",
);
const emailOtpPluginIndex = pluginsTs.indexOf("\n\t\temailOTP({");
check(
	emailOtpTargetLimitPluginIndex >= 0 &&
		emailOtpPluginIndex > emailOtpTargetLimitPluginIndex,
	`${rel(pluginsFile)} must register target limiting before the Email OTP sender`,
);
checkIncludesAll(
	emailOtpTargetRateLimitTs,
	[
		"window: 60,",
		"max: 3,",
		"window: 24 * 60 * 60,",
		"max: 10,",
		"email.trim().toLowerCase()",
		"crypto.subtle.importKey(",
		'{ name: "HMAC", hash: "SHA-256" }',
		"createDurableObjectRateLimitStorage",
		'await enforceQuota("burst", burstRule)',
		'await enforceQuota("daily", dailyRule)',
		"EMAIL_OTP_TARGET_RATE_LIMIT_UNAVAILABLE",
		"EMAIL_OTP_TARGET_RATE_LIMITED",
	],
	emailOtpTargetRateLimitFile,
	"Email OTP targets must use HMAC-derived fail-closed burst and daily Durable Object quotas",
);
const twoFactorConfiguration =
	pluginsTs.match(/twoFactor\(\{([\s\S]*?)\n\t\t\}\),/)?.[1] ?? "";
check(
	twoFactorConfiguration.length > 0 &&
		!twoFactorConfiguration.includes("otpOptions") &&
		!twoFactorConfiguration.includes("sendOTP"),
	`${rel(pluginsFile)} must keep Email OTP as the first factor and use only independent TOTP or backup-code step-up`,
);
const twoFactorPluginIndex = pluginsTs.indexOf("\n\t\ttwoFactor({");
const oauthProviderPluginIndex = pluginsTs.indexOf("\n\t\toauthProvider({");
check(
	twoFactorPluginIndex >= 0 && oauthProviderPluginIndex > twoFactorPluginIndex,
	`${rel(pluginsFile)} must keep the two-factor authentication gate before OAuth continuation as defense in depth`,
);
check(
	!pluginsTs.includes("username()") && !pluginsTs.includes("magicLink("),
	`${rel(pluginsFile)} must not register username-password or Magic Link sign-in plugins`,
);
checkIncludesAll(
	pluginsTs,
	[
		'defaultPrefix: "cina_sk_"',
		"requireName: true",
		"startingCharactersConfig",
		"charactersLength: 12",
	],
	pluginsFile,
	"personal API keys must use a recognizable CinaAuth prefix and retain only a display-safe identifier",
);
checkIncludesAll(
	indexTs,
	[
		"FRESH_SESSION_MUTATION_PATHS",
		'"/api/auth/api-key/create"',
		'"/api/auth/api-key/update"',
		'"/api/auth/api-key/delete"',
		'"/api/auth/organization/create"',
		'"/api/auth/organization/invite-member"',
		'"/api/auth/organization/remove-member"',
		'"/api/auth/organization/update-member-role"',
		'"/api/auth/organization/leave"',
		'"/api/auth/sso/register"',
		'"/api/auth/sso/update-provider"',
		'"/api/auth/sso/delete-provider"',
		'"/api/auth/sso/request-domain-verification"',
		'"/api/auth/sso/verify-domain"',
		'"/api/auth/scim/generate-token"',
		'"/api/auth/scim/delete-provider-connection"',
		'"/api/auth/oauth2/create-client"',
		'"/api/auth/oauth2/update-client"',
		'"/api/auth/oauth2/client/rotate-secret"',
		'"/api/auth/oauth2/delete-client"',
		'"/api/auth/oauth2/delete-consent"',
		'"/api/auth/subscription/upgrade"',
		'"/api/auth/subscription/cancel"',
		'"/api/auth/subscription/restore"',
		'"/api/auth/subscription/billing-portal"',
		"disableCookieCache: true",
		"isFreshSecuritySession",
		"requiresFreshSessionForMutation",
		'app.use("/api/auth/*"',
		'code: "SESSION_NOT_FRESH"',
	],
	indexFile,
	"API key, organization, enterprise identity, OAuth client, and consent mutations must fail closed unless an authoritative recent session is present",
);
checkIncludesAll(
	superAdminGovernanceTs,
	[
		'"/api/auth/admin/set-role"',
		'"/api/auth/admin/update-user"',
		'"/api/auth/admin/remove-user"',
		'"/api/auth/delete-user"',
		'"/api/auth/delete-user/callback"',
		'"/api/auth/delete-anonymous-user"',
		'"/api/auth/scim/v2/Users/"',
		"pg_advisory_xact_lock",
		"SUPER_ADMIN_GOVERNANCE_QUEUE_LOCK_KEY",
		"assertDatabaseInvariantReady",
		"consumeSCIMRateLimit",
		"canonicalizeGovernancePath",
		"CF-Connecting-IP",
		'code: "ADMIN_GOVERNANCE_RATE_LIMITED"',
		'code: "YOU_CANNOT_REMOVE_LAST_SUPER_ADMIN"',
		'code: "ADMIN_GOVERNANCE_UNAVAILABLE"',
	],
	superAdminGovernanceFile,
	"all super-admin removal and account-deletion sinks must use authenticated, rate-limited, invariant-checked deployment governance",
);
checkIncludesAll(
	superAdminDatabaseInvariantTs,
	[
		"SUPER_ADMIN_DATABASE_INVARIANT_LOCK_KEY",
		"LANGUAGE plpgsql VOLATILE",
		"BEFORE INSERT OR UPDATE OR DELETE",
		"pg_advisory_xact_lock",
		"TG_RELID::regclass",
		"FOR KEY SHARE",
		"YOU_CANNOT_REMOVE_LAST_SUPER_ADMIN",
		"ANONYMOUS_USER_CANNOT_BE_SUPER_ADMIN",
		"ANONYMOUS_SUPER_ADMIN_MUST_BE_DEMOTED_BEFORE_DELETION",
		'admin_candidate."isAnonymous" IS NOT TRUE',
		'admin_candidate."isAnonymous" IS TRUE',
		"getSuperAdminDatabaseInvariantReadiness",
	],
	superAdminDatabaseInvariantFile,
	"the final super-admin invariant must execute inside the actual PostgreSQL user mutation and reject invalid current data",
);
check(
	superAdminGovernanceTs.includes(
		'"cinaauth:super-admin-governance:queue:v1"',
	) &&
		superAdminDatabaseInvariantTs.includes(
			'"cinaauth:super-admin-governance:invariant:v1"',
		),
	"the Worker queue and mutation-transaction super-admin invariant must use distinct advisory-lock keys",
);
checkIncludesAll(
	providerNamespaceInvariantTs,
	[
		"cinaauth_provider_namespace",
		"installProviderNamespaceInvariant",
		"getProviderNamespaceInvariantReadiness",
		"Provider namespace collision",
		'"account"',
		'"ssoProvider"',
		'"scimProvider"',
		"configuredProviderIds",
	],
	providerNamespaceInvariantFile,
	"provider ids must be claimed by a persistent transaction-local PostgreSQL invariant",
);
checkIncludesAll(
	databaseInvariantsTs,
	[
		"DATABASE_INVARIANT_IDS",
		"SUPER_ADMIN_DATABASE_INVARIANT_ID",
		"PROVIDER_NAMESPACE_INVARIANT_ID",
		"installDatabaseInvariants",
		"getDatabaseInvariantReadiness",
		"BEGIN",
		"ROLLBACK",
		"Database invariant verification failed",
	],
	databaseInvariantsFile,
	"database invariants must install transactionally and verify before commit",
);
checkIncludesAll(
	indexTs,
	[
		"handleSuperAdminGovernedRequest",
		"consumeSCIMRateLimit:",
		"query: { disableCookieCache: true }",
		"handle: () => c.var.auth.handler(c.req.raw)",
		'"cinaauth.super_admin_governance.failed"',
		"installDatabaseInvariants",
		"getDatabaseInvariantReadiness",
		"getConfiguredAccountProviderIds",
		"hasDatabaseInvariantTables",
		"requiredInvariants",
		"invariants.ok",
	],
	indexFile,
	"the production catch-all, migration, and readiness paths must preserve responses while enforcing database invariants",
);
checkIncludesAll(
	adminPluginTs,
	[
		"getAuthoritativeSessionFromCtx",
		'context.path === "/delete-user"',
		'context.path === "/delete-user/callback"',
		"delete:",
		"assertSuperAdminCanBeDeleted",
	],
	adminPluginFile,
	"the Admin plugin must guard self-service endpoints before destruction and retain a database deletion backstop",
);
checkIncludesAll(
	adminSuperAdminGuardTs,
	[
		'role?.split(",").includes(expected)',
		"internalAdapter.listUsers",
		"YOU_CANNOT_REMOVE_LAST_SUPER_ADMIN",
	],
	adminSuperAdminGuardFile,
	"all Admin deletion guards must share the exact role-membership invariant",
);
checkIncludesAll(
	accountDashboardI18n,
	[
		"Copy your API key now",
		"full secret is shown only once",
		"Connect wallet",
		"Make primary",
		"Disconnect wallet",
		"signed deletion receipt was downloaded",
		"External erasure confirmation required",
		"Recent authentication required",
		"Leave organization",
		"Plan and entitlements",
		"Protected operations remain fail-closed",
		"50 teams and 100 organization members per team",
		"Up to 25 organization-scoped role definitions",
		"Export JSON",
		"Export CSV",
		"Apply filters",
		"No cached events or exports are shown",
		"10,000 events and fail rather than truncate",
		"Fresh sign-in required for changes",
		"No cached token connection data is shown",
		"Copy this SCIM token now",
		"CinaSeek stores only a hash",
		"Sensitive values are sent",
		"Stored credentials are never loaded",
		"linked SSO account records",
		"Copy this client secret now",
		"shown only once",
		"Credential secrets stay excluded",
		"Current access mode: Unmetered.",
		"Entitlement status is temporarily unavailable.",
		"No checkout or subscription request will be sent",
	],
	accountDashboardI18nFile,
	"localized dashboard copy must preserve production safety guidance while UI components consume dictionary keys",
);
checkIncludesAll(
	accountHomeI18n,
	[
		"Sign in or create your account",
		"New wallet? We'll create your account after you verify the",
	],
	accountHomeI18nFile,
	"localized sign-in copy must preserve the unified first-user account-creation contract",
);
checkIncludesAll(
	securityCenterPageTs,
	[
		"Promise.all",
		"listSessions",
		"listUserAccounts",
		"listPasskeys",
		"listApiKeys",
		"listWallets",
		"auth.api",
		"getCapabilities",
		"dataUnavailable",
	],
	securityCenterPageFile,
	"the Security Center must fetch independent authoritative controls in parallel and fail closed per section",
);
checkIncludesAll(
	securityCenterComponentTs,
	[
		"isSessionRecent",
		"formatSecurityDate",
		"authClient.revokeOtherSessions",
		"authClient.passkey.addPasskey",
		"authClient.apiKey.create",
		"authClient.apiKey.update",
		"authClient.apiKey.delete",
		"messages.copyApiKeyNow",
		"messages.personalApiKeysDescription",
		"authClient.unlinkAccount",
		"authClient.linkSocial",
		'authClient.$fetch("/siwe/list-wallets"',
		"cinaAuthSiweProtocolClient",
		"completeWalletProof",
		'purpose: "link-wallet"',
		"walletCapabilities.methods.siwe === true",
		"identity.chainId !== 1",
		'"/siwe/set-primary-wallet"',
		'authClient.$fetch("/siwe/unlink-wallet"',
		"signSiweMessage",
		"messages.connectWallet",
		"messages.makePrimary",
		"messages.disconnectWallet",
		"PRIVACY_DELETE_ACCOUNT_PATH",
		'method: "POST"',
		'credentials: "include"',
		"deleteConfirmation === user.email",
		"PRIVACY_DELETION_READINESS_PATH",
		"parsePrivacyDeletionReadiness",
		"getPrivacyDeletionReceipt",
		"getPrivacyDeletionReceiptFilename",
		"messages.accountDeletedReceipt",
		"PRIVACY_PROCESSOR_ERASURE_PENDING",
		"PRIVACY_PROCESSOR_ERASURE_FAILED",
		"messages.externalErasureRequired",
		"messages.recentAuthenticationRequired",
	],
	securityCenterComponentFile,
	"the user-facing Security Center must protect session, authenticator, identity, and deletion actions with retention preflight and signed receipt delivery",
);
checkIncludesAll(
	securityCenterPolicyTs,
	[
		'timeZone: "UTC"',
		"formatSecurityDate",
		"formatApiKeyIdentifier",
		"isApiKeyExpired",
	],
	securityCenterPolicyFile,
	"security timestamps must be deterministic across SSR and browser hydration",
);
checkIncludesAll(
	organizationConsolePageTs,
	[
		"Promise.all",
		"listOrganizations",
		"getFullOrganization",
		"listOrganizationTeams",
		"listOrganizationRoles",
		"getEntitlements",
		"listOrganizationAudit",
		"listSSOProviders",
		"listSCIMProviderConnections",
		"canViewOrganizationAudit",
		"currentSessionCreatedAt",
		"auditUnavailable",
		"dataUnavailable",
		"advancedOrganizationDataUnavailable",
		"entitlementsUnavailable",
	],
	organizationConsolePageFile,
	"the Organization Console must load authoritative list and detail data in parallel and fail closed",
);
checkIncludesAll(
	organizationConsoleComponentTs,
	[
		"getOrganizationPermissions",
		"canManageOrganizationMember",
		"canLeaveOrganization",
		"isSessionRecent",
		"useMemberRemoveMutation",
		"useInvitationCancelMutation",
		"useOrganizationLeaveMutation",
		"InviteMemberForm",
		"CreateOrganizationForm",
		"getOrganizationInvitationUrl",
		"authClient.signOut",
		"messages.leaveOrganization",
		"OrganizationAuditCard",
		"EnterpriseConnectionsCard",
		"AdvancedMemberRoleEditor",
		"AdvancedOrganizationCard",
		"messages.planAndEntitlements",
		"initialEntitlements.features",
		"initialEntitlements.limits",
		"messages.planPolicyUnavailableDescription",
		"router.refresh",
	],
	organizationConsoleComponentFile,
	"the Organization Console must enforce role-aware and recent-session-protected member and invitation controls",
);
checkIncludesAll(
	advancedOrganizationComponentTs,
	[
		"listOrganizationTeamMembers",
		"AdvancedMemberRoleEditor",
		"getMemberRoleSelectionError",
		"targetIsFinalOwner",
		"ORGANIZATION_PERMISSION_STATEMENT",
		"getDynamicRoleDraftError",
		"recentAuthentication",
		"authoritativeOrganizationData",
		"dataUnavailable",
		"messages.teamsDescription",
		"messages.customRolesDescription",
	],
	advancedOrganizationComponentFile,
	"advanced organization UX must remain bounded, fresh-session protected, and fail closed on missing data",
);
checkIncludesAll(
	advancedOrganizationPolicyTs,
	[
		"ORGANIZATION_PERMISSION_STATEMENT",
		"ROLE_NAME_PATTERN",
		"RESERVED_ROLE_NAMES",
		"getTeamNameError",
		"toRolePermissionPayload",
		"getMemberRoleSelectionError",
		"Transfer ownership before removing the final owner role",
	],
	advancedOrganizationPolicyFile,
	"advanced organization policy must validate names, permissions, and final-owner safety independently",
);
checkIncludesAll(
	advancedOrganizationMutationTs,
	[
		'"/organization/create-team"',
		'"/organization/update-team"',
		'"/organization/remove-team"',
		'"/organization/list-team-members"',
		'"/organization/add-team-member"',
		'"/organization/remove-team-member"',
		'"/organization/create-role"',
		'"/organization/update-role"',
		'"/organization/delete-role"',
	],
	advancedOrganizationMutationFile,
	"team and dynamic-role product actions must use the authoritative organization endpoints",
);
checkIncludesAll(
	organizationAuditComponentTs,
	[
		"useOrganizationAuditPageQuery",
		"loadOrganizationAuditExport",
		"getOrganizationAuditDateRange",
		"messages.exportJson",
		"messages.exportCsv",
		"messages.applyFilters",
		"messages.activityUnavailableDescription",
		"messages.auditPagination",
	],
	organizationAuditComponentFile,
	"organization audit UX must provide authoritative filtering, pagination, and bounded JSON/CSV export",
);
checkIncludesAll(
	organizationAuditDataTs,
	[
		'"/audit/organization"',
		"ORGANIZATION_AUDIT_EXPORT_LIMIT = 10_000",
		"ORGANIZATION_AUDIT_EXPORT_PAGE_SIZE = 100",
		"Audit events changed during export",
		"ids.has(record.id)",
		"params.organizationId",
		"useOrganizationAuditPageQuery",
	],
	organizationAuditDataFile,
	"organization audit data access must remain tenant-keyed, bounded, complete, and fail closed on pagination drift",
);
checkIncludesAll(
	organizationAuditExportPolicyTs,
	[
		"cinaauth.organization-audit",
		"version: 1",
		"CSV_COLUMNS",
		"escapeCSVCell",
		"getOrganizationAuditDateRange",
		"createOrganizationAuditExportFilename",
	],
	organizationAuditExportPolicyFile,
	"organization audit exports must be versioned, CSV-safe, date-bounded, and deterministically named",
);
checkIncludesAll(
	enterpriseConnectionsComponentTs,
	[
		"recentAuthentication",
		"messages.freshSignInChanges",
		"messages.scimInventoryUnavailableDescription",
		"SSOProviderManager",
		"useSCIMTokenGenerateMutation",
		"useSCIMProviderRevokeMutation",
		"messages.copyScimTokenNow",
		"messages.copyScimTokenNowDescription",
		"router.refresh",
	],
	enterpriseConnectionsComponentFile,
	"enterprise connection management must fail closed, require recent authentication, and protect one-time SCIM secrets",
);
checkIncludesAll(
	ssoProviderManagerTs,
	[
		"recentAuthentication",
		"authoritativeOrganizationData",
		"unavailable",
		"useOIDCSSOProviderRegisterMutation",
		"useOIDCSSOProviderUpdateMutation",
		"useSAMLSSOProviderRegisterMutation",
		"useSAMLSSOProviderUpdateMutation",
		"useSSOProviderDeleteMutation",
		"useSSODomainVerificationRequestMutation",
		"useSSODomainVerificationMutation",
		"messages.ssoConfigurationDescription",
		"messages.storedCredentialsDescription",
		"messages.deleteSsoProviderDescription",
		"router.refresh",
	],
	ssoProviderManagerFile,
	"SSO provider management must cover OIDC and SAML lifecycle, fail closed, and never reload stored credentials",
);
checkIncludesAll(
	ssoProviderConsolePolicyTs,
	[
		"MAX_SAML_METADATA_BYTES",
		"PROVIDER_ID_PATTERN",
		"Issuer must be an HTTPS URL",
		"replacement client ID and client secret",
		"OIDC scopes must include openid",
		"All configured OIDC endpoints must use HTTPS",
		"getOIDCCallbackURL",
		"getSAMLCallbackURL",
		"getSAMLMetadataURL",
	],
	ssoProviderConsolePolicyFile,
	"SSO provider validation and callback contracts must remain deterministic and independently testable",
);
checkIncludesAll(
	organizationConsolePolicyTs,
	[
		'timeZone: "UTC"',
		"parseOrganizationRoles",
		"getOrganizationPermissions",
		"canManageOrganizationMember",
		"canAssignOrganizationRole",
		"canLeaveOrganization",
		"getOrganizationInvitationUrl",
	],
	organizationConsolePolicyFile,
	"organization policy and invitation-link behavior must be deterministic and independently testable",
);
checkIncludesAll(
	organizationRoleMutationTs,
	[
		"authClient.organization.updateMemberRole",
		"organizationKeys.detail()",
		"Member role updated successfully",
	],
	organizationRoleMutationFile,
	"member role changes must use the typed organization API and refresh authoritative detail data",
);
checkIncludesAll(
	organizationLeaveMutationTs,
	[
		"authClient.organization.leave",
		"organizationKeys.all()",
		"You left the organization",
	],
	organizationLeaveMutationFile,
	"leaving an organization must use the typed API and invalidate all organization data",
);
checkIncludesAll(
	enterpriseConnectionsMutationTs,
	[
		'"/sso/register"',
		'"/sso/update-provider"',
		'"/sso/delete-provider"',
		'"/sso/request-domain-verification"',
		'"/sso/verify-domain"',
		'"/scim/generate-token"',
		'"/scim/delete-provider-connection"',
		"registerOIDCSSOProvider",
		"updateOIDCSSOProvider",
		"registerSAMLSSOProvider",
		"updateSAMLSSOProvider",
		"deleteSSOProvider",
		"organizationKeys.all()",
		"domainVerificationToken",
		"scimToken",
	],
	enterpriseConnectionsMutationFile,
	"enterprise connection mutations must use authoritative endpoints and refresh organization data",
);
checkIncludesAll(
	accountVitestConfigTs,
	['"data/**/*.test.ts"'],
	accountVitestConfigFile,
	"account-portal data-layer contract tests must remain in Vitest discovery",
);
checkIncludesAll(
	developerConsolePageTs,
	[
		"Promise.all",
		"listOAuthClients",
		"listOAuthConsents",
		'redirect("/sign-in?callbackURL=/dashboard/developer")',
		"dataUnavailable",
	],
	developerConsolePageFile,
	"the Developer Console must load owned clients and current-user consents in parallel and fail closed",
);
checkIncludesAll(
	developerConsoleComponentTs,
	[
		"isSessionRecent",
		'credentials: "include"',
		'cache: "no-store"',
		'"/api/auth/oauth2/create-client"',
		'"/api/auth/oauth2/update-client"',
		'"/api/auth/oauth2/client/rotate-secret"',
		'"/api/auth/oauth2/delete-client"',
		'"/api/auth/oauth2/delete-consent"',
		"messages.copyClientSecretNow",
		"messages.copyClientSecretDescription",
		"secretAcknowledged",
		"https://auth.cinaseek.ai/api/auth/device/code",
		"https://auth.cinaseek.ai/api/auth/device/token",
	],
	developerConsoleComponentFile,
	"the Developer Console must keep mutations same-origin, gate writes on recent authentication, and protect one-time secrets",
);
checkIncludesAll(
	developerConsolePolicyTs,
	[
		"parseDeveloperRedirectUris",
		"validateDeveloperClientName",
		"BLOCKED_NATIVE_SCHEMES",
		"LOOPBACK_HOSTS",
		"url.username",
		"url.password",
		'uri.includes("#")',
		"canRotateDeveloperSecret",
	],
	developerConsolePolicyFile,
	"OAuth client redirect, naming, and secret-rotation policy must be deterministic and independently testable",
);
checkIncludesAll(
	coreRedirectUriTs,
	[
		"DANGEROUS_URL_SCHEMES",
		"u.username",
		"u.password",
		'val.includes("#")',
		"isLoopbackHost",
	],
	coreRedirectUriFile,
	"the shared server redirect-URI schema must reject dangerous schemes, credentials, fragments, and external HTTP callbacks",
);
checkIncludesAll(
	oauthRegisterTs,
	[
		"validateClientRedirectUri(",
		'applicationType === "web"',
		"!isHttps || isRedirectLoopback",
		"web clients require https redirect URIs on non-loopback hosts",
		"!isAllowedNativeHttpLoopback",
		"FORBIDDEN_NATIVE_REDIRECT_SCHEMES.has(url.protocol)",
		"!isReverseDomainPrivateUseRedirectUri(url)",
	],
	oauthRegisterFile,
	"the OAuth server must enforce web HTTPS and restrict native callbacks to valid reverse-domain schemes or exact HTTP loopback hosts",
);
checkIncludesAll(
	pluginsTs,
	[
		"canManageOrganizationBilling",
		"authorizeReference: async",
		'model: "member"',
		'field: "organizationId"',
		'field: "userId"',
	],
	pluginsFile,
	"organization subscription references must be authorized against authoritative owner or administrator membership",
);
checkIncludesAll(
	pluginsTs,
	[
		"canUseDeveloperOAuthClients",
		"clientPrivileges:",
		"user?.emailVerified === true",
		"user.isAnonymous !== true",
		"validateClient: async (clientId, ctx)",
		'model: "oauthClient"',
		'client?.tokenEndpointAuthMethod === "none"',
		"client.public !== false",
		"client.disabled !== true",
	],
	pluginsFile,
	"the Worker must authorize developer-client ownership and restrict Device Flow to registered public clients",
);
checkIncludesAll(
	developerConsoleDoc,
	[
		"https://accounts.cinaseek.ai/dashboard/developer",
		"client_secret_basic",
		"public clients and must use PKCE",
		"created within the last 15 minutes",
		"Client secrets are returned only by creation and rotation",
		"Only registered, enabled, public clients are accepted",
		"Operational acceptance",
	],
	developerConsoleDocFile,
	"the Developer Console runbook must document client profiles, server authorization, one-time secrets, and production acceptance",
);
checkIncludesAll(
	siweWalletTs,
	[
		'"/siwe/list-wallets"',
		'"/siwe/link-wallet"',
		'"/siwe/set-primary-wallet"',
		'"/siwe/unlink-wallet"',
		"freshSessionMiddleware",
		"ctx.context.session.user.id",
		"ctx.context.adapter.transaction",
		"WALLET_ALREADY_LINKED",
		"FAILED_TO_UNLINK_LAST_ACCOUNT",
	],
	siweWalletFile,
	"self-service wallets must be current-user scoped, proof-bound, transactional, and preserve a login method",
);
checkIncludesAll(
	siweProofTs,
	[
		"consumeVerificationValue",
		"parseSiweMessage",
		"nonceMatches",
		"domainMatches",
		"addressMatches",
		"chainMatches",
		"options.verifyMessage",
	],
	siweProofFile,
	"wallet login and linking must share complete single-use ERC-4361 proof verification",
);
checkIncludesAll(
	privacyCenterPluginTs,
	[
		'"/privacy/export"',
		"freshSessionMiddleware",
		"getAuthTables",
		"getPrivacySubjectSelector",
		"sanitizePrivacyExportRecord",
		"PRIVACY_EXPORT_TOO_LARGE",
		"credentialSecretsExcluded: true",
		'"cache-control": "no-store"',
		'"x-content-type-options": "nosniff"',
		"cinaauth-personal-data-",
		"writePersonalDataExport",
		"maxRecordsPerModel === null",
	],
	privacyCenterPluginFile,
	"personal exports must be subject-scoped, complete within explicit limits, secret-free, and non-cacheable",
);
checkIncludesAll(
	privacyCenterAsyncExportTs,
	[
		'"/privacy/async-export"',
		'"/privacy/async-export/status"',
		'"/privacy/async-export/download"',
		"PrivacyAsyncExportProvider",
		"freshSessionMiddleware",
		'"cache-control": "no-store"',
		"deleteSubjectExports",
	],
	privacyCenterAsyncExportFile,
	"asynchronous privacy exports must remain recent-session protected, subject-scoped, non-cacheable, and deletable",
);
checkIncludesAll(
	privacyCenterDeletionTs,
	[
		'"/privacy/deletion-readiness"',
		'"/privacy/deletion-receipt/verify"',
		"resolveBlockingHolds",
		"PRIVACY_DELETION_BLOCKED",
		"pseudonymousId",
		'algorithm: "HMAC-SHA256"',
		"constantTimeEqual",
		"PrivacyDeletionProcessor",
		"PROCESSOR_OPERATION_DOMAIN",
		"PRIVACY_PROCESSOR_ERASURE_PENDING",
		"PRIVACY_PROCESSOR_ERASURE_FAILED",
		"evidenceDigest",
		"purgeNoLaterThan",
		'ctx.setHeader("cache-control", "no-store")',
	],
	privacyCenterDeletionFile,
	"account deletion must recheck holds and return a pseudonymous, tamper-evident, non-cacheable receipt contract",
);
checkIncludesAll(
	pluginsTs,
	[
		"import { privacyCenter }",
		"privacyCenter({",
		'policyVersion: "2026-08-10"',
		'code: "cloudflare-delivery-queues-1d"',
		"maximumRetentionDays: 1",
		'code: "security-audit-90d"',
		"maximumRetentionDays: 90",
		'code: "planetscale-postgres-backups-2d"',
		"maximumRetentionDays: 2",
		"createRequiredPrivacyDeletionProcessor",
	],
	pluginsFile,
	"the production Worker must enable the Privacy Center plugin with a versioned 90-day security-audit exception",
);
checkIncludesAll(
	privacyCenterPageTs,
	["auth.api.getSession", 'redirect("/sign-in")', "isSessionRecent"],
	privacyCenterPageFile,
	"the Privacy Center page must enforce server-side authentication and pass only recent-session state",
);
checkIncludesAll(
	privacyCenterComponentTs,
	[
		"PRIVACY_EXPORT_PATH",
		'credentials: "include"',
		'cache: "no-store"',
		"URL.createObjectURL",
		"URL.revokeObjectURL",
		"PRIVACY_ASYNC_EXPORT_PATH",
		"parsePrivacyAsyncExportStatus",
		"AbortController",
		"messages.credentialSecretsExcluded",
		'Link href="/dashboard/security#delete-account"',
	],
	privacyCenterComponentFile,
	"the Privacy Center UI must download only on interaction without persisting export contents",
);
checkIncludesAll(
	privacyCenterPolicyTs,
	[
		'"/api/auth/privacy/export"',
		'"/api/auth/privacy/deletion-readiness"',
		'"/api/auth/delete-user"',
		"getPersonalDataExportFilename",
		"getPrivacyDeletionReceipt",
		"getPrivacyDeletionReceiptFilename",
		"PRIVACY_EXPORT_CATEGORIES",
		"/^cinaauth-personal-data-/i",
		"cinaseek-personal-data-",
		"cinaseek-deletion-receipt-",
	],
	privacyCenterPolicyFile,
	"privacy download policy must constrain export and signed deletion receipt parsing and filenames",
);
checkIncludesAll(
	privacyCenterDoc,
	[
		"privacyCenter",
		"maxRecordsPerModel",
		"PRIVACY_EXPORT_TOO_LARGE",
		"Cache-Control: no-store",
		"Credential exclusion",
		"Deletion readiness",
		"Signed deletion receipt",
		"PRIVACY_DELETION_BLOCKED",
		"HMAC-SHA256",
		"Required external processors",
		"PRIVACY_PROCESSOR_ERASURE_PENDING",
		"evidenceId",
		"purgeNoLaterThan",
		"check:planetscale-backups",
	],
	privacyCenterDocFile,
	"public Privacy Center documentation must describe export safeguards, holds, retention exceptions, and signed receipts",
);
checkIncludesAll(
	sessionRouteTs,
	[
		"freshSessionMiddleware",
		"getAuthoritativeSessionFromCtx(ctx)",
		"sessionAge < 0",
	],
	sessionRouteFile,
	"fresh-session authorization must bypass stateful cookie cache and reject future timestamps",
);
checkIncludesAll(
	authApiTs,
	[
		"createAuthProxyResponse",
		"resolveAuthClientBaseURL",
		"shouldSkipOAuthProxy",
		'"/api/auth/audit/organization"',
		'"/api/auth/sso/providers"',
		'"/api/auth/scim/list-provider-connections"',
		'proxied.headers.set("x-skip-oauth-proxy", "1")',
	],
	authApiFile,
	"the account portal must expose its same-origin Auth Worker facade and keep Generic OAuth state on that origin",
);
checkIncludesAll(
	accountAuthRuntimeConfigTs,
	[
		'bindingPolicy === "false"',
		"UNAVAILABLE_CINAAUTH_API_URL",
		"AUTH_SERVICE_UNAVAILABLE",
		'"Cache-Control": "no-store"',
		"resolveAuthRuntimeConfiguration",
		"resolveAuthClientRuntimeBaseURL",
	],
	accountAuthRuntimeConfigFile,
	"the Account Portal must permit public Auth fallback only by exact local opt-in and otherwise fail closed",
);
checkIncludesAll(
	accountAuthTransportTs,
	[
		"getCloudflareContext",
		"fetchAuthServiceRequest",
		"unavailableAuthFetcher",
		"runtimeConfiguration.publicFallbackAllowed",
		"createAuthServiceUnavailableResponse",
		"AUTH_WORKER",
	],
	accountAuthTransportFile,
	"server-side Account Auth traffic must require the Service Binding without falling back after binding or context failures",
);
checkIncludesAll(
	accountDiagnoseRouteTs,
	[
		"fetchAuthServiceRequest",
		'probeAuthService("/"',
		'probeAuthService("/api/auth/get-session"',
		"createAuthServiceUnavailableResponse",
		'cache: "no-store"',
	],
	accountDiagnoseRouteFile,
	"Account diagnostics must probe Auth through the binding-aware server transport and fail closed",
);
check(
	!accountDiagnoseRouteTs.includes("httpbin.org") &&
		!accountDiagnoseRouteTs.includes("process.env.NODE_ENV") &&
		!accountDiagnoseRouteTs.includes("CINAAUTH_URL:"),
	`${rel(accountDiagnoseRouteFile)} must not expose environment details or use an unrelated public diagnostic probe`,
);
checkIncludesAll(
	accountMcpRouteTs,
	[
		"fetchAuthServiceRequest",
		"jwksFetch: loadAuthJwks",
		"jwksCacheKey: AUTH_JWKS_CACHE_KEY",
		"AUTH_TRANSPORT_UNAVAILABLE_CODE",
		"withAuthAvailability",
		"createAuthServiceUnavailableResponse",
	],
	accountMcpRouteFile,
	"MCP token verification must load JWKS through the binding-aware server transport",
);
check(
	!accountMcpRouteTs.includes("jwksUrl:"),
	`${rel(accountMcpRouteFile)} must not bypass the Auth Service Binding with a public JWKS URL`,
);
checkIncludesAll(
	oauthConfigTs,
	[
		"parseProductionGenericOAuthConfig",
		"genericOAuthRedirectURI",
		"accountOrigin",
		"/api/auth/oauth2/callback/",
		'url.protocol === "https:"',
		"PROVIDER_ID_PATTERN",
	],
	oauthConfigFile,
	"production Generic OAuth providers must use validated HTTPS endpoints and the account-origin callback",
);
checkIncludesAll(
	oauthProductionDoc,
	[
		"https://accounts.cinaseek.ai",
		"oneTapClientId",
		"Authorized JavaScript origin",
		"权威能力响应启用 One Tap",
		"只有 `/sign-in` 一个“登录或创建账号”入口",
		"disableImplicitSignUp: false",
		"disableSignUp: false",
		"https://accounts.cinaseek.ai/api/auth/callback/google",
		"https://accounts.cinaseek.ai/api/auth/oauth2/callback/<providerId>",
		"GENERIC_OAUTH_CONFIG",
		"requireIssuerValidation",
		"Wrangler stdin",
		"真实供应商成功与失败路径端到端证据",
	],
	oauthProductionDocFile,
	"the OAuth runbook must pin production origins, callbacks, secret handling, and E2E acceptance",
);
checkIncludesAll(
	oauthProviderButtonsTs,
	[
		"oneTapClient",
		"createAuthClient",
		"data?.oneTap === true",
		"data.oneTapClientId",
		"googleOneTapClient.oneTap",
		"authClient.signIn.social",
		"provider: provider.id",
		"callbackURL",
		"formatOAuthProviderName(provider.id)",
	],
	oauthProviderButtonsFile,
	"the account portal must route every social provider through the standard redirect flow",
);
check(
	!authClientTs.includes("oneTapClient"),
	"the shared account auth client must keep One Tap isolated to the capability-gated sign-in component",
);
checkIncludesAll(
	pluginsTs,
	[
		"options.authenticationSettings?.googleOneTapEnabled === true",
		"options.googleOneTapClientId",
		"oneTap({",
		"clientId: options.googleOneTapClientId",
	],
	pluginsFile,
	"the Auth Worker must register One Tap only from complete runtime configuration",
);
checkIncludesAll(
	accountOAuthBuildCheck,
	[
		"https://auth.cinaseek.ai/api/auth/capabilities",
		"evaluateGoogleAuthenticationBuild",
		"evaluateReownBuild",
		"evaluatePlannedReownBuild",
		"evaluatePlannedSiweRelease",
		"evaluateDeployedWalletReadiness",
		"evaluatePortalCompatibility",
		"evaluateConfigurableAuthenticationRelease",
		"CINAAUTH_EMAIL_AUTH_GATE",
		'gate === "portal-compatible"',
		'gate === "runtime-configurable"',
		'response.headers.get("cache-control")',
		"the live Auth capability response is not no-store",
		"CINAAUTH_PLANNED_WORKER_CONFIG",
		"CINAAUTH_ACCOUNT_BUILD_READINESS_URL",
		"CINAAUTH_ACCOUNT_TARGET_ORIGIN",
		"resolveAccountBuildReadinessTarget",
		"const expectedReadinessUrl = `${origin}/api/build-readiness`",
		'cache: "no-store"',
		"deployed = await fetchBuildReadiness(readinessURL)",
		"const plannedResult = evaluatePlannedSiweRelease({",
		"the deployed Account Portal Reown Project ID does not match production",
		"the planned Auth Worker CINAAUTH_SIWE_ENABLED value must be exactly true or false",
		"the planned Auth Worker enables SIWE but production has no exact 32-hex REOWN_PROJECT_ID",
		"the production Auth Worker advertises an incomplete Google One Tap capability",
		"the production Auth Worker advertises SIWE but the account build has no valid REOWN_PROJECT_ID",
	],
	accountOAuthBuildCheckFile,
	"the account deployment gates must fail when planned or live server capabilities lack matching client build inputs",
);
const plannedAccountCheckStart = accountOAuthBuildCheck.indexOf(
	"if (plannedWorkerConfig)",
);
const plannedEmailGateIndex = accountOAuthBuildCheck.indexOf(
	"if (emailAuthGate)",
	plannedAccountCheckStart,
);
const plannedAccountReturnIndex = accountOAuthBuildCheck.indexOf(
	"\n\t\treturn;",
	plannedAccountCheckStart,
);
check(
	plannedAccountCheckStart >= 0 &&
		plannedEmailGateIndex > plannedAccountCheckStart &&
		plannedAccountReturnIndex > plannedEmailGateIndex,
	`${rel(accountOAuthBuildCheckFile)} planned-release branch must execute the configured email-auth gate before returning`,
);
check(
	!accountOAuthBuildCheck.includes("DEFAULT_BUILD_READINESS_URL"),
	`${rel(accountOAuthBuildCheckFile)} must derive readiness from the validated deployment target instead of a production fallback`,
);
checkIncludesAll(
	accountBuildReadiness,
	[
		'siweProtocol: "cinaauth-siwe-v2"',
		'walletUi: "reown-appkit-v1"',
		'walletUiEnabled: walletUiEnabled === "true"',
		"reownProjectId: ready ? reownProjectId : null",
		'"Cache-Control": "no-store, max-age=0"',
		'"CDN-Cache-Control": "no-store"',
		"status: readiness.ready ? 200 : 503",
	],
	accountBuildReadinessFile,
	"the public Account Portal marker must fail closed, stay uncached, and identify the exact deployed SIWE v2 Reown bundle",
);
checkIncludesAll(
	accountBuildReadinessRoute,
	[
		'export const dynamic = "force-dynamic"',
		"process.env.NEXT_PUBLIC_REOWN_PROJECT_ID",
		"process.env.NEXT_PUBLIC_SIWE_WALLET_UI_ENABLED",
		"createAccountBuildReadinessResponse",
		"export function GET()",
	],
	accountBuildReadinessRouteFile,
	"the App Router endpoint must use the default OpenNext server bundle and expose only the dynamic handler around the tested readiness helper",
);
check(
	!accountBuildReadinessRoute.includes(
		"export const buildAccountBuildReadiness",
	) &&
		!accountBuildReadinessRoute.includes(
			"export const createAccountBuildReadinessResponse",
		) &&
		!accountBuildReadinessRoute.includes('export const runtime = "edge"'),
	`${rel(accountBuildReadinessRouteFile)} must not export non-route helpers or opt into an unsupported edge bundle`,
);
checkIncludesAll(
	authProxyPackageTs,
	[
		"response.headers.getSetCookie()",
		"splitSetCookieHeader",
		'headers.append("set-cookie", setCookie)',
	],
	authProxyPackageFile,
	"the shared auth proxy must preserve every upstream session cookie",
);
checkIncludesAll(
	authClientTs,
	[
		"resolveAuthClientBaseURL",
		'typeof window === "undefined" ? undefined : window.location.origin',
		"apiKeyClient()",
	],
	authClientFile,
	"browser auth calls must stay same-origin so the Demo receives its session cookies",
);
checkIncludesAll(
	globalCss,
	["--space-2xl: 40px", "--space-5xl: 96px"],
	globalCssFile,
	"design-system spacing tokens must not override Tailwind max-width utilities",
);
check(
	!globalCss.includes("--spacing-2xl") && !globalCss.includes("--spacing-5xl"),
	"apps/account-portal/app/globals.css must not shadow Tailwind max-width tokens with spacing values",
);
checkIncludesAll(
	authProxyRouteTs,
	["createAuthProxyResponse", "return createAuthProxyResponse(response)"],
	authProxyRouteFile,
	"every auth proxy method must use the multi-cookie-safe response builder",
);
checkIncludesAll(
	auditCaptureTs,
	[
		'"/delete-user"',
		'"/unlink-account"',
		'"/revoke-other-sessions"',
		'"/passkey/verify-registration"',
		'"/api-key/create"',
		'"/siwe/link-wallet"',
		'"/siwe/set-primary-wallet"',
		'"/siwe/unlink-wallet"',
		'"user.account_delete"',
		'"identity.unlink"',
		'"session.revoke_others"',
		'"passkey.create"',
		'"api_key.create"',
		'"api_key.update"',
		'"api_key.delete"',
		'"siwe.bind"',
		'"siwe.set_primary"',
		'"siwe.unbind"',
		'"/organization/create"',
		'"/organization/update-member-role"',
		'"/organization/leave"',
		'"/organization/create-team"',
		'"org.create"',
		'"org.member_role_update"',
		'"org.member_leave"',
		"resolveOrganizationAuditTarget",
	],
	auditCaptureFile,
	"self-service and organization high-risk mutations must emit stable audit actions with tenant targets",
);
checkIncludesAll(
	auditRoutesTs,
	[
		'"/audit/organization"',
		'field: "organizationId"',
		'where("targetType", "eq", "organization")',
		'where("targetId", "eq", ctx.query.organizationId)',
		"organizationAllowedRoles",
		"Math.min(Math.max(Math.trunc(requestedLimit), 1), 100)",
	],
	auditRoutesFile,
	"organization audit reads must be role-gated, tenant-filtered, and bounded",
);
checkIncludesAll(
	auditPluginTs,
	["listOrganizationAudit", "organizationAllowedRoles", '"owner"', '"admin"'],
	auditPluginFile,
	"the audit plugin must default tenant audit access to organization owners and admins",
);
checkIncludesAll(
	customSessionTs,
	["getSetCookieHeaders", "getSetCookieHeaders(session.headers)"],
	customSessionFile,
	"custom sessions must read refreshed cookies through the runtime-safe adapter",
);
checkIncludesAll(
	customSessionCookieHeadersTs,
	["headers.getSetCookie", "splitSetCookieHeader"],
	customSessionCookieHeadersFile,
	"valid session reads must work in Cloudflare runtimes without Headers.getSetCookie",
);
checkIncludesAll(
	authCapabilitiesTs,
	[
		"cloudflare-turnstile",
		"getCaptchaRequestHeaders",
		'"x-captcha-response"',
		"protectedEndpoints",
	],
	authCapabilitiesFile,
	"the Demo must validate the public captcha payload and build the verification header",
);
checkIncludesAll(
	authApiTs,
	["getCapabilities", "AUTH_WEB_ENDPOINTS.capabilities"],
	authApiFile,
	"server-rendered capability reads must use the authoritative Auth Worker binding contract",
);
checkIncludesAll(
	billingConsolePolicyTs,
	["Billing unavailable", 'action !== "checkout" || billingEnabled'],
	billingConsolePolicyFile,
	"paid checkout must fail closed while billing is unavailable",
);
checkIncludesAll(
	accountDashboardPageTs,
	[
		"getCapabilities",
		"getEntitlements",
		"getBillingUiState",
		"billingEnabled={billing.billingEnabled}",
		"entitlements={entitlements}",
	],
	accountDashboardPageFile,
	"the account dashboard must gate subscription APIs on authoritative billing and entitlement state",
);
checkIncludesAll(
	subscriptionCardTs,
	[
		"useSubscriptionListQuery(billingEnabled)",
		"messages.unmeteredAccess",
		"messages.entitlementsUnavailable",
		"messages.billingNotReady",
	],
	subscriptionCardFile,
	"the subscription card must not query or offer mutations while billing is disabled",
);
checkIncludesAll(
	pricingPageTs,
	[
		'export const dynamic = "force-dynamic"',
		"getCapabilities",
		"billingEnabled={capabilities.billing === true}",
	],
	pricingPageFile,
	"the pricing page must dynamically load live billing capability through the Auth Worker contract",
);
checkIncludesAll(
	pricingComponentTs,
	[
		"getBillingActionState",
		"disabled={!actionState.enabled}",
		'plan.action === "checkout"',
		'"bg-ink text-white shadow-l4"',
		'plan.isPopular ? "text-white" : "text-ink"',
	],
	pricingComponentFile,
	"pricing checkout must remain disabled unless live billing capability is enabled and the featured plan must remain high contrast",
);
checkIncludesAll(
	turnstileComponentTs,
	[
		"https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
		"useTurnstileChallenge",
		'"expired-callback"',
		'"timeout-callback"',
		"window.turnstile?.remove",
	],
	turnstileComponentFile,
	"the Demo must manage the complete explicit Turnstile widget lifecycle",
);
for (const { file, content } of protectedForms) {
	checkIncludesAll(
		content,
		["TurnstileChallenge", "captcha.headers", "captcha.reset()"],
		file,
		"protected auth forms must submit and then discard the single-use captcha token",
	);
}

check(
	packageJson.scripts?.["check:production"] ===
		"node ./scripts/verify-production-config.mjs",
	`${rel(packageFile)} must expose check:production`,
);
check(
	packageJson.scripts?.["check:siwe-staging-foundation"] ===
		"node ./scripts/verify-siwe-staging.mjs --foundation",
	`${rel(packageFile)} must expose the non-deployable SIWE staging foundation gate`,
);
check(
	packageJson.scripts?.["test:siwe-staging-inventory"] ===
		"node --test ./scripts/siwe-staging-inventory.test.mjs ./scripts/verify-siwe-staging.test.mjs",
	`${rel(packageFile)} must expose the SIWE staging inventory contract tests`,
);
check(
	packageJson.scripts?.["build:dependencies"] ===
		'pnpm --filter "@cinaauth/auth-api-worker^..." run build',
	`${rel(packageFile)} must rebuild every runtime workspace dependency before Worker bundling`,
);
check(
	packageJson.scripts?.build?.startsWith(
		"pnpm run build:dependencies && wrangler deploy --dry-run",
	) === true,
	`${rel(packageFile)} build must prevent stale workspace dist artifacts from entering the Worker bundle`,
);
check(
	packageJson.scripts?.deploy ===
		"pnpm run build:dependencies && wrangler deploy",
	`${rel(packageFile)} deploy must rebuild workspace dependencies before publishing`,
);
check(
	packageJson.scripts?.check?.includes("pnpm run check:production"),
	`${rel(packageFile)} check script must run check:production before deploy gates`,
);
check(
	packageJson.scripts?.check?.includes(
		"pnpm run check:siwe-staging-foundation && pnpm run test:siwe-staging-inventory",
	),
	`${rel(packageFile)} check script must reject partial staging config and run its inventory contract tests`,
);
checkIncludesAll(
	siweStagingInventory,
	[
		"parseStagingInventory",
		"verifyStagingInventory",
		"assertNoDeployableStagingConfig",
		"SIWE_STAGING_REOWN_PROJECT_ID",
		"siweAllowedChainIds",
		"siweAutoSignup",
		"production-collision",
	],
	siweStagingInventoryFile,
	"the staging inventory validator must keep resource isolation, dedicated secret names, and fixed SIWE safety values fail closed",
);
checkIncludesAll(
	siweStagingInventoryTest,
	[
		"accepts a complete isolated inventory",
		"rejects production identifier reuse",
		"binds the inventory to the protected staging Reown identity digest",
		"requires staging-specific GitHub secret names",
		"foundation mode rejects partial Wrangler environments",
	],
	siweStagingInventoryTestFile,
	"the staging inventory tests must cover completeness, production collisions, secret-name isolation, and partial config rejection",
);
checkIncludesAll(
	verifySiweStaging,
	[
		"--foundation",
		"--inventory",
		"SIWE_PRODUCTION_REOWN_PROJECT_ID_SHA256",
		"SIWE_STAGING_REOWN_PROJECT_ID_SHA256",
		"no deployable staging environment or workflow is present",
		"Deployment remains disabled",
	],
	verifySiweStagingFile,
	"the staging CLI must distinguish its non-deployable foundation and inventory-only modes",
);
checkIncludesAll(
	verifySiweStagingTest,
	[
		"defaults to the non-deployable foundation gate",
		"rejects ambiguous, missing, and future deployment arguments",
	],
	verifySiweStagingTestFile,
	"the staging CLI parser must fail closed on ambiguous or unsupported deployment arguments",
);
check(
	packageJson.scripts?.test === "vitest run",
	`${rel(packageFile)} must expose a vitest test script`,
);
check(
	packageJson.scripts?.["check:cloudflare"] ===
		"node ./scripts/check-cloudflare-remote.mjs",
	`${rel(packageFile)} must expose check:cloudflare`,
);
check(
	packageJson.scripts?.["check:planetscale-backups"] ===
		"node ./scripts/check-planetscale-backups.mjs",
	`${rel(packageFile)} must expose check:planetscale-backups`,
);
check(
	packageJson.scripts?.["configure:delivery-queues"] ===
		"node ./scripts/configure-delivery-queues.mjs",
	`${rel(packageFile)} must expose configure:delivery-queues`,
);
check(
	packageJson.scripts?.check?.includes("pnpm run test:delivery-queues"),
	`${rel(packageFile)} check script must run the delivery Queue safety tests`,
);
check(
	packageJson.scripts?.check?.includes("pnpm run test:runtime-capabilities"),
	`${rel(packageFile)} check script must run live optional-capability safety tests`,
);
check(
	packageJson.scripts?.check?.includes("pnpm run test:backup-audit"),
	`${rel(packageFile)} check script must run the PlanetScale backup audit tests`,
);
check(
	packageJson.scripts?.["acceptance:production-lifecycle"] ===
		"node ./scripts/run-production-lifecycle-acceptance.mjs",
	`${rel(packageFile)} must expose the opt-in production lifecycle acceptance script`,
);
check(
	packageJson.scripts?.["test:production-lifecycle-acceptance"] ===
		"node --test ./scripts/run-production-lifecycle-acceptance.test.mjs",
	`${rel(packageFile)} must expose production lifecycle acceptance safety tests`,
);
check(
	packageJson.scripts?.check?.includes(
		"pnpm run test:production-lifecycle-acceptance",
	),
	`${rel(packageFile)} check script must run production lifecycle acceptance safety tests`,
);
check(
	packageJson.scripts?.["provision:secrets"] ===
		"node ./scripts/provision-secrets.mjs",
	`${rel(packageFile)} must expose provision:secrets`,
);
check(
	packageJson.scripts?.["test:provision-secrets"] ===
		"node --test ./scripts/provision-secrets.test.mjs" &&
		packageJson.scripts?.check?.includes("pnpm run test:provision-secrets"),
	`${rel(packageFile)} must expose and run the bulk secret provisioning tests`,
);
check(
	packageJson.scripts?.check?.includes("pnpm run test"),
	`${rel(packageFile)} check script must run Worker regression tests`,
);
check(
	packageJson.devDependencies?.vitest === "catalog:vitest",
	`${rel(packageFile)} must depend on the workspace Vitest catalog`,
);
check(
	typeof packageJson.dependencies?.pg === "string",
	`${rel(packageFile)} must depend directly on pg for Hyperdrive PostgreSQL`,
);

check(wrangler.name === "cinaauth-api", "Worker name must be cinaauth-api");
check(wrangler.main === "src/index.ts", "Worker main must be src/index.ts");
check(
	typeof wrangler.compatibility_date === "string" &&
		/^\d{4}-\d{2}-\d{2}$/.test(wrangler.compatibility_date),
	"wrangler.json must set an explicit compatibility_date",
);
check(
	Array.isArray(wrangler.compatibility_flags) &&
		wrangler.compatibility_flags.includes("nodejs_compat"),
	"wrangler.json must enable nodejs_compat",
);
check(
	wrangler.upload_source_maps === true,
	"wrangler.json must upload source maps",
);
check(
	wrangler.observability?.enabled === true &&
		typeof wrangler.observability?.head_sampling_rate === "number" &&
		wrangler.observability.head_sampling_rate > 0 &&
		wrangler.observability.head_sampling_rate <= 1,
	"wrangler.json must enable observability with a valid head_sampling_rate",
);
check(
	wrangler.version_metadata?.binding === "VERSION_METADATA",
	"wrangler.json must bind Worker version metadata as VERSION_METADATA",
);

checkExactSecretsStoreBindings(
	wrangler,
	wranglerFile,
	expectedSecretsStoreBindings.auth,
);
checkExactSecretsStoreBindings(
	deliveryWrangler,
	deliveryWranglerFile,
	expectedSecretsStoreBindings.delivery,
);
checkExactSecretsStoreBindings(
	privacyErasureWrangler,
	privacyErasureWranglerFile,
	expectedSecretsStoreBindings.privacyErasure,
);
checkExactSecretsStoreBindings(
	adminWranglerConfig,
	adminWranglerFile,
	expectedSecretsStoreBindings.admin,
);
checkIncludesAll(
	deploymentDoc,
	[
		"Secrets Store V2 is active",
		SECRETS_STORE_ID,
		"CINAADMIN_OIDC_TRANSACTION_SECRET_STORE_V2",
		"CINAAUTH_DELIVERY_CONFIG_KEK_STORE",
		"CINAAUTH_ERASURE_CONFIG_KEK_STORE",
		"binding-first",
		"does not fall back to a V1 Worker secret",
		"reports `active: true`",
		"Account Secrets Store Edit",
		"`workers` scope",
		"Two-phase bootstrap and post-deploy control plane",
		"/api/admin/configuration/delivery/stage",
		"/api/admin/configuration/erasure/stage",
		"CINAAUTH_ERASURE_SERVICE",
		"X-CinaAuth-Timestamp",
		"X-CinaAuth-Nonce",
		"300 seconds",
		"terminal `completed` or `failed` audit outcome",
	],
	deploymentDocFile,
	"Auth deployment docs must define active binding-first secrets, exact mappings, two-phase bootstrap, and the post-deploy control plane",
);
checkIncludesAll(
	adminConfigurationTs,
	[
		'phase: "requested" | "completed" | "failed"',
		'phase: "failed"',
		'code: "AUDIT_TERMINAL_WRITE_FAILED"',
		"`v1=${signature}`",
		'"X-CinaAuth-Nonce": input.idempotencyKey',
		'"X-CinaAuth-Timestamp": timestamp',
		"`${timestamp}.${input.idempotencyKey}.${input.body}`",
	],
	adminConfigurationFile,
	"Auth configuration mutations must produce redacted terminal audit outcomes and time-bind signed child requests",
);
checkIncludesAll(
	indexTs,
	[
		'event.phase === "failed" ? "failure" : "success"',
		"failureCode: event.failureCode",
		"failureStatus: event.failureStatus",
	],
	indexFile,
	"Auth must persist failed configuration outcomes as authoritative audit failures",
);
checkIncludesAll(
	privacyErasureManagement,
	[
		"MANAGEMENT_SIGNATURE_ALLOWED_SKEW_SECONDS = 300",
		'request.headers.get("x-cinaauth-nonce")',
		'request.headers.get("x-cinaauth-timestamp")',
		"`${timestamp}.${nonce}.${body}`",
		"value.idempotencyKey !== nonce",
	],
	privacyErasureManagementFile,
	"Privacy configuration management must reject stale or nonce-mismatched signed requests",
);
check(
	!deploymentDoc.includes("Secrets Store V2 is **staged only**") &&
		!deploymentDoc.includes("--allow-erasure-not-ready") &&
		!deploymentDoc.includes("ready before the provisioning script"),
	`${rel(deploymentDocFile)} must not document staged V2 or child operational readiness as an Auth structural-deploy prerequisite`,
);
checkIncludesAll(
	deliveryDeployment,
	[
		SECRETS_STORE_ID,
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET_STORE_V2",
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET_V2",
		"CINAAUTH_DELIVERY_CONFIG_KEK_STORE",
		"CINAAUTH_DELIVERY_CONFIG_KEK_V1",
		"`workers` scope",
		"structurally healthy",
		"operational state",
		"ACTIVE",
		"NEXT",
		"PREVIOUS",
	],
	deliveryDeploymentFile,
	"Delivery deployment docs must define active Secrets Store bindings, encrypted versioned configuration, and split readiness",
);
checkIncludesAll(
	privacyErasureDeployment,
	[
		SECRETS_STORE_ID,
		"CINAAUTH_ERASURE_WEBHOOK_SECRET_STORE_V2",
		"CINAAUTH_ERASURE_WEBHOOK_SECRET_V2",
		"CINAAUTH_ERASURE_CONFIG_KEK_STORE",
		"CINAAUTH_ERASURE_CONFIG_KEK_V1",
		"Structural readiness",
		"Operational readiness",
		"ACTIVE/NEXT/PREVIOUS",
		"domain-separated HKDF/HMAC",
		"legacy unkeyed idempotency cache rows",
		"authenticated Auth",
		"control plane",
	],
	privacyErasureDeploymentFile,
	"Privacy Erasure deployment docs must define active Secrets Store bindings, encrypted target versions, and split readiness",
);

const hyperdrive = wrangler.hyperdrive?.find(
	(binding) => binding.binding === "HYPERDRIVE",
);
check(Boolean(hyperdrive), "wrangler.json must bind Hyperdrive as HYPERDRIVE");
check(
	typeof hyperdrive?.id === "string" &&
		/^[0-9a-f]{32}$/i.test(hyperdrive.id) &&
		hyperdrive.id !== "00000000000000000000000000000000",
	"HYPERDRIVE binding must contain a concrete non-placeholder config ID",
);
const deliveryService = wrangler.services?.find(
	(binding) => binding.binding === "CINAAUTH_DELIVERY_SERVICE",
);
const erasureService = wrangler.services?.find(
	(binding) => binding.binding === "CINAAUTH_ERASURE_SERVICE",
);
const cinatokenIdentityService = wrangler.services?.find(
	(binding) => binding.binding === "CINATOKEN_IDENTITY_EVENTS_SERVICE",
);
check(
	deliveryService?.service === "cinaauth-delivery",
	"wrangler.json must bind CINAAUTH_DELIVERY_SERVICE to cinaauth-delivery",
);
check(
	wrangler.services?.length === 3 &&
		erasureService?.service === "cinaauth-privacy-erasure" &&
		cinatokenIdentityService?.service === "cinatoken-admin",
	"wrangler.json must bind delivery, erasure, and CinaToken identity services to their authoritative Workers",
);
const rateLimiter = wrangler.durable_objects?.bindings?.find(
	(binding) => binding.name === "RATE_LIMITER",
);

const legacyD1 = wrangler.d1_databases?.find(
	(binding) => binding.binding === "LEGACY_D1",
);
check(
	legacyD1?.database_name === "cinaauth-db" &&
		legacyD1?.database_id === "b5063da6-673d-41e3-93c7-e63b089aaf28",
	"wrangler.json must retain cinaauth-db as the LEGACY_D1 rollback source",
);
check(
	rateLimiter?.class_name === "RateLimitDurableObject",
	"wrangler.json must bind RATE_LIMITER to RateLimitDurableObject",
);
check(
	wrangler.exports?.RateLimitDurableObject?.type === "durable-object" &&
		wrangler.exports?.RateLimitDurableObject?.storage === "sqlite",
	"RateLimitDurableObject must be declared with SQLite storage",
);

check(
	wrangler.vars?.CINAAUTH_URL === "https://auth.cinaseek.ai",
	"CINAAUTH_URL must point at https://auth.cinaseek.ai",
);
check(
	wrangler.vars?.CINAAUTH_ACCOUNT_ORIGIN === "https://accounts.cinaseek.ai" &&
		wrangler.vars?.CINAAUTH_ADMIN_ORIGIN === "https://admin.cinaseek.ai" &&
		wrangler.vars?.CINAAUTH_PASSKEY_RP_ID === "cinaseek.ai" &&
		wrangler.vars?.CINAAUTH_LEGACY_ACCOUNT_ORIGIN ===
			"https://demo-auth.cinagroup.com" &&
		wrangler.vars?.CINAAUTH_OIDC_DEMO_ENVIRONMENT === "production" &&
		wrangler.vars?.CINAAUTH_OIDC_DEMO_ORIGIN ===
			"https://oidc-demo.cinaseek.ai" &&
		wrangler.vars?.CINAAUTH_OIDC_DEMO_CLIENT_ID === "cinaauth-oidc-demo",
	"Tracked production browser origins, Passkey RP ID, and OIDC demo profile must remain explicit and exact",
);
check(
	wrangler.vars?.CINAAUTH_CUTOVER_STATE === "live",
	"Tracked production config must use live cutover state; first cutover deploy overrides it to maintenance",
);
check(
	wrangler.vars?.CINAAUTH_SIWE_ENABLED === "true" &&
		wrangler.vars?.CINAAUTH_SIWE_ALLOWED_CHAIN_IDS === "1" &&
		wrangler.vars?.CINAAUTH_SIWE_RP_DOMAIN === "accounts.cinaseek.ai" &&
		wrangler.vars?.CINAAUTH_SIWE_RP_URI === "https://accounts.cinaseek.ai" &&
		wrangler.vars?.CINAAUTH_SIWE_ALLOW_LEGACY === "false" &&
		wrangler.vars?.CINAAUTH_SIWE_AUTO_SIGNUP === "true",
	"Tracked production SIWE config must enable the governed Stage Two rollout, bind Accounts as RP, allow only Ethereum mainnet, forbid legacy requests, and enable verified-wallet account creation",
);
const forbiddenVars = [
	"CINAAUTH_SECRET",
	"CINAAUTH_MIGRATION_TOKEN",
	"CINAAUTH_DELIVERY_WEBHOOK_URL",
	"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
	"CINAAUTH_PRIVACY_EXPORT_KEY",
	"CINAAUTH_ERASURE_WEBHOOK_URL",
	"CINAAUTH_ERASURE_WEBHOOK_SECRET",
	"OAUTH_PAIRWISE_SECRET",
	"CLOUDFLARE_TURNSTILE_SECRET_KEY",
	"STRIPE_SECRET_KEY",
	"STRIPE_WEBHOOK_SECRET",
	"CINAAUTH_ENTITLEMENT_CONFIG",
	"CINAUTH_ADMIN_SERVICE_KEY",
	"CINAAUTH_D1_MIGRATION_TOKEN",
].filter((name) => Object.hasOwn(wrangler.vars ?? {}, name));
check(
	forbiddenVars.length === 0,
	`Secret-like values must not be stored in wrangler.json vars: ${forbiddenVars.join(", ")}`,
);

const producer = wrangler.queues?.producers?.find(
	(item) => item.binding === "CINAAUTH_DELIVERY_QUEUE",
);
check(
	Boolean(producer),
	"wrangler.json must bind CINAAUTH_DELIVERY_QUEUE producer",
);
check(
	producer?.queue === "cinaauth-delivery",
	"CINAAUTH_DELIVERY_QUEUE must produce to cinaauth-delivery",
);
const consumer = wrangler.queues?.consumers?.find(
	(item) => item.queue === "cinaauth-delivery",
);
check(Boolean(consumer), "wrangler.json must consume cinaauth-delivery");
check(
	consumer?.dead_letter_queue === "cinaauth-delivery-dlq",
	"cinaauth-delivery consumer must use cinaauth-delivery-dlq",
);
check(
	consumer?.max_concurrency > 0 && consumer.max_concurrency <= 5,
	"Queue consumer max_concurrency must be capped at 5 or lower",
);
check(
	consumer?.max_batch_size > 0 && consumer.max_batch_size <= 10,
	"Queue consumer max_batch_size must be capped at 10 or lower",
);
check(
	consumer?.max_retries >= 3,
	"Queue consumer should retry transient downstream failures",
);

const privacyProducer = wrangler.queues?.producers?.find(
	(item) => item.binding === "CINAAUTH_PRIVACY_EXPORT_QUEUE",
);
const identityProducer = wrangler.queues?.producers?.find(
	(item) => item.binding === "CINATOKEN_IDENTITY_EVENTS_QUEUE",
);
check(
	Array.isArray(wrangler.triggers?.crons) &&
		wrangler.triggers.crons.includes("* * * * *") &&
		wrangler.triggers.crons.includes("0 3 * * *"),
	"Auth Worker must schedule both minute-level identity outbox dispatch and daily retention",
);
check(
	identityProducer?.queue === "cinaauth-cinatoken-identity-events",
	"CINATOKEN_IDENTITY_EVENTS_QUEUE must produce to cinaauth-cinatoken-identity-events",
);
const identityConsumer = wrangler.queues?.consumers?.find(
	(item) => item.queue === "cinaauth-cinatoken-identity-events",
);
check(
	identityConsumer?.dead_letter_queue ===
		"cinaauth-cinatoken-identity-events-dlq",
	"CinaToken identity event consumer must use its dedicated DLQ",
);
check(
	identityConsumer?.max_retries >= 10,
	"CinaToken identity event delivery must retry transient failures at least ten times",
);
checkIncludesAll(
	organizationIdentityOutboxInvariantTs,
	[
		"cinaauth_cinatoken_identity_outbox",
		"cinaauth_cinatoken_identity_clock",
		"AFTER INSERT OR UPDATE OR DELETE",
		'AFTER UPDATE OF "email"',
		"pg_advisory_xact_lock",
		"clock_timestamp()",
		"INTERVAL '1 millisecond'",
		'ON CONFLICT ("dedupe_key") DO NOTHING',
		"backfill:organization:",
		"backfill:membership:",
	],
	organizationIdentityOutboxInvariantFile,
	"organization identity writes and bootstrap must be transactionally captured and ordered",
);
checkIncludesAll(
	organizationIdentityEventsTs,
	[
		"FOR UPDATE SKIP LOCKED",
		"OUTBOX_LEASE_MS = 120_000",
		"OUTBOX_BATCH_BYTES = 230 * 1024",
		"CINATOKEN_IDENTITY_EVENTS_QUEUE.sendBatch",
		"markOrganizationIdentityOutboxQueued",
		"replayOrganizationIdentityOutbox",
		"ORGANIZATION_IDENTITY_OUTBOX_RETENTION_DAYS = 30",
	],
	organizationIdentityEventsFile,
	"scheduled identity dispatch must use bounded leases, durable Queue batches, replay, and retention",
);
checkIncludes(
	databaseInvariantsTs,
	"ORGANIZATION_IDENTITY_OUTBOX_INVARIANT_ID",
	databaseInvariantsFile,
	"the outbox schema must be installed and verified by the governed migration",
);
checkIncludesAll(
	indexTs,
	[
		"/api/operations/cinatoken-identity-outbox/replay",
		"isAuthorizedMigrationRequest",
		"parseOrganizationIdentityOutboxReplayInput",
	],
	indexFile,
	"identity outbox replay must remain a validated operations-only action",
);
check(
	!pluginsTs.includes("createOrganizationIdentityHooks") &&
		!pluginsTs.includes("enqueueOrganizationMembershipSnapshot"),
	"organization identity production must not retain non-transactional post-commit hooks",
);
check(
	privacyProducer?.queue === "cinaauth-privacy-export",
	"CINAAUTH_PRIVACY_EXPORT_QUEUE must produce to cinaauth-privacy-export",
);
const privacyConsumer = wrangler.queues?.consumers?.find(
	(item) => item.queue === "cinaauth-privacy-export",
);
check(
	privacyConsumer?.dead_letter_queue === "cinaauth-privacy-export-dlq",
	"privacy export consumer must use cinaauth-privacy-export-dlq",
);
check(
	privacyConsumer?.max_batch_size > 0 && privacyConsumer.max_batch_size <= 2,
	"privacy export queue must keep batches at two jobs or fewer",
);
const privacyBucket = wrangler.r2_buckets?.find(
	(item) => item.binding === "CINAAUTH_PRIVACY_EXPORTS",
);
check(
	privacyBucket?.bucket_name === "cinaauth-privacy-exports",
	"wrangler.json must bind the private CinaAuth privacy export R2 bucket",
);

const route = wrangler.routes?.find(
	(item) => item.pattern === "auth.cinaseek.ai" && item.custom_domain === true,
);
check(
	Boolean(route),
	"wrangler.json must expose auth.cinaseek.ai as a Custom Domain",
);

checkIncludesAll(
	indexTs,
	[
		"missing_cinaauth_secret",
		"weak_cinaauth_secret",
		"missing_hyperdrive_binding",
		"missing_legacy_d1_binding",
		"missing_version_metadata",
		"missing_cinaauth_migration_token",
		"weak_cinaauth_migration_token",
		"missing_delivery_queue",
		"missing_delivery_service",
		"missing_delivery_webhook_url",
		"invalid_delivery_webhook_url",
		"missing_delivery_webhook_secret",
		"weak_delivery_webhook_secret",
		"invalid_cinaauth_cutover_state",
		"parseAuthOriginConfig",
		"originConfig.issues",
	],
	indexFile,
	"runtime readiness must cover required production inputs",
);
checkIncludesAll(
	indexTs,
	[
		"withNoStore(",
		"await handleSuperAdminGovernedRequest({",
		"handle: () => c.var.auth.handler(c.req.raw)",
	],
	indexFile,
	"every catch-all auth response must pass through super-admin governance and disable intermediary caching",
);
check(
	(indexTs.match(/c\.var\.auth\.handler\(c\.req\.raw\)/g) ?? []).length === 1,
	`${rel(indexFile)} must delegate the raw catch-all request to auth.handler only through the governed handler callback`,
);
const impersonationGuardRegistration = indexTs.indexOf(
	"createImpersonationMutationGuardMiddleware<AppEnv>({",
);
const impersonationGuardUseRegistration = indexTs.lastIndexOf(
	"app.use(",
	impersonationGuardRegistration,
);
const directAuthRouteRegistrations = [
	...indexTs.matchAll(
		/app\.(?:use|get|post|put|patch|delete)\(\s*["']\/api\/auth/g,
	),
].map((match) => match.index);
const onAuthRouteRegistrations = [
	...indexTs.matchAll(/app\.on\([\s\S]{0,500}?["']\/api\/auth/g),
].map((match) => match.index);
const firstAuthRouteRegistration = Math.min(
	...directAuthRouteRegistrations,
	...onAuthRouteRegistrations,
);
check(
	impersonationGuardRegistration >= 0 &&
		impersonationGuardUseRegistration >= 0 &&
		firstAuthRouteRegistration === impersonationGuardUseRegistration,
	"the impersonation mutation middleware must be registered before every concrete /api/auth route",
);
const siweBodyLimitRegistration = indexTs.indexOf(
	"createSiweRequestBodyLimitMiddleware<AppEnv>()",
);
const siweBodyLimitUseRegistration = indexTs.lastIndexOf(
	"app.use(",
	siweBodyLimitRegistration,
);
const concreteAuthRouteRegistrations = [
	...indexTs.matchAll(
		/app\.(?:get|post|put|patch|delete)\(\s*["']\/api\/auth/g,
	),
].map((match) => match.index);
const firstConcreteAuthRouteRegistration = Math.min(
	...concreteAuthRouteRegistrations,
	...onAuthRouteRegistrations,
);
check(
	siweBodyLimitRegistration >= 0 &&
		siweBodyLimitUseRegistration > impersonationGuardUseRegistration &&
		siweBodyLimitUseRegistration < firstConcreteAuthRouteRegistration,
	"the SIWE request body limit must follow impersonation protection and precede every concrete /api/auth route",
);
checkIncludesAll(
	impersonationMutationGuardTs,
	[
		"createImpersonationMutationGuardMiddleware",
		"IMPERSONATION_MUTATING_GET_PATHS",
		"Cache-Control",
		"no-store",
	],
	impersonationMutationGuardFile,
	"the impersonation mutation boundary must remain fail-closed and no-store",
);
check(
	!impersonationMutationGuardTs.includes(
		'"/api/auth/email-otp/check-verification-otp"',
	),
	"the state-changing email OTP verification check must not be classified as a read-only impersonation exception",
);
checkIncludesAll(
	indexTs,
	[
		'app.get("/api/ready"',
		'app.get("/api/migrate"',
		'app.post("/api/migrate"',
		'app.post("/api/migrate/scim-provider-ownership"',
		'app.get("/api/migrate/d1"',
		'app.post("/api/migrate/d1"',
		"getCutoverState",
		"Cache-Control",
		"no-store",
		"secureEqual",
		"REQUIRED_DATABASE_TABLES",
		'"durable-object"',
		"getVersionMetadata",
		"version: getVersionMetadata",
		"export const getRuntimeConfigIssues",
		"export const isAuthorizedMigrationRequest",
		"export const getMigrationFeatureSelection",
		'feature === "organization-advanced"',
		"invalid_migration_feature",
	],
	indexFile,
	"protected operations and no-store responses must stay wired",
);
checkIncludesAll(
	scimOwnershipMigrationTs,
	[
		"BEGIN ISOLATION LEVEL SERIALIZABLE",
		"SET LOCAL statement_timeout",
		"provider_has_accounts",
		"provider_already_owned",
		"provider_id_collision",
		"owner_not_authorized",
		"RESERVED_ACCOUNT_PROVIDER_IDS",
		'"credential"',
		'"email-otp"',
		'FROM "ssoProvider"',
		"reservedProviderIds",
		'\"organizationId\" IS NULL',
		'\"userId\" IS NULL',
		'INSERT INTO \"auditLog\"',
		"createSCIMOwnershipToken",
		"storedToken",
	],
	scimOwnershipMigrationFile,
	"legacy SCIM ownership claims must stay namespace-safe, explicit, zero-account, non-rebinding, token-rotating, and audited",
);
checkIncludesAll(
	indexTs,
	[
		"getProductionSocialProviders",
		"getConfiguredAccountProviderIds",
		"parseProductionGenericOAuthConfig",
		"reservedProviderIds",
		'case "provider_id_collision"',
		'if (result.status !== "provider_id_collision")',
	],
	indexFile,
	"the SCIM ownership migration route must reject configured account-provider collisions before mutation or audit",
);
const migrationAuthorizationStart = indexTs.indexOf(
	"export const isAuthorizedMigrationRequest",
);
const migrationAuthorizationEnd = indexTs.indexOf(
	"export const getMigrationFeatureSelection",
	migrationAuthorizationStart,
);
const migrationAuthorizationSource = indexTs.slice(
	migrationAuthorizationStart,
	migrationAuthorizationEnd,
);
checkIncludesAll(
	migrationAuthorizationSource,
	["CINAAUTH_MIGRATION_TOKEN", "CINAAUTH_D1_MIGRATION_TOKEN"],
	indexFile,
	"migration and readiness authorization must use only dedicated migration credentials",
);
check(
	!migrationAuthorizationSource.includes("CINAUTH_ADMIN_SERVICE_KEY"),
	"Migration/readiness authorization must not fall back to CINAUTH_ADMIN_SERVICE_KEY",
);

checkIncludesAll(
	pluginsTs,
	[
		"advancedOrganization?: boolean",
		"organizationAccessControl",
		"organizationRoles",
		"maximumRolesPerOrganization: (organizationId) =>",
		"maximumMembersPerTeam: ({ organizationId }) =>",
		"maximumTeams: ({ organizationId }) =>",
		'keyPairConfig: { alg: "ES256" }',
		"JWT_ROTATION_INTERVAL_SECONDS",
		"JWT_GRACE_PERIOD_SECONDS",
	],
	pluginsFile,
	"advanced organization schema must remain an explicit plugin mode",
);

checkIncludesAll(
	authTs,
	[
		"createDurableObjectRateLimitStorage",
		"AUTH_RATE_LIMIT_RULES",
		"createDatabase(env)",
		"createAuthPlugins(",
		"advancedOrganization: true",
		"authenticationSettings: social",
		"googleOneTapClientId: social.googleOneTapClientId",
		"social.genericProviders",
		"waitUntil(",
		"runWithExecutionCtx",
		"cf-connecting-ip",
		"resolveSocialSignInConfig(env, accountOrigin)",
		"social.socialProviders",
	],
	authFile,
	"auth runtime must keep rate limits shared and background work safe",
);

checkIncludesAll(
	authRoutingTs,
	[
		'"/.well-known/openid-configuration"',
		'"/.well-known/oauth-authorization-server"',
		"/api/auth${OPENID_CONFIGURATION_PATH}",
		"createCanonicalDiscoveryRequest",
	],
	authRoutingFile,
	"issuer-root discovery and API compatibility aliases must reach the Auth handler",
);
checkIncludesAll(
	indexTs,
	[
		"isAuthHandlerRequestPath(pathname)",
		"AUTH_DISCOVERY_PATHS",
		"createCanonicalDiscoveryRequest(c.req.raw)",
	],
	indexFile,
	"the Worker must expose OIDC discovery outside the /api/auth catch-all",
);
checkIncludesAll(
	siweRequestBodyLimitTs,
	[
		"SIWE_LEGACY_NONCE_REQUEST_BODY_LIMIT_BYTES = 2 * 1024",
		"SIWE_CHALLENGE_REQUEST_BODY_LIMIT_BYTES = 18 * 1024",
		"SIWE_PROOF_REQUEST_BODY_LIMIT_BYTES = 20 * 1024",
		"SIWE_LEGACY_NONCE_PATHS.has(canonicalPathname)",
		"return SIWE_LEGACY_NONCE_REQUEST_BODY_LIMIT_BYTES",
		"canonicalPathname === SIWE_CHALLENGE_PATH",
		'"/api/auth/siwe/challenge"',
		'"/api/auth/siwe/nonce"',
		'"/api/auth/siwe/get-nonce"',
		'"/api/auth/siwe/verify"',
		'"/api/auth/siwe/link-wallet"',
		"request.clone().body",
		"bytesRead > limitBytes",
		"cancelBody(request.body",
		'code: "REQUEST_BODY_TOO_LARGE"',
		"413",
		'response.headers.set("Cache-Control", "no-store")',
	],
	siweRequestBodyLimitFile,
	"SIWE challenge and proof endpoints must enforce raw streamed byte limits without trusting Content-Length or consuming accepted bodies",
);
checkIncludesAll(
	indexTs,
	[
		'from "./siwe-request-body-limit"',
		'app.use("/api/auth/*", createSiweRequestBodyLimitMiddleware<AppEnv>())',
		"handle: () => c.var.auth.handler(c.req.raw)",
	],
	indexFile,
	"the SIWE raw-body boundary must run before the Auth catch-all consumes the preserved request",
);
checkIncludesAll(
	deploymentDoc,
	[
		"`challenge` accepts at most 18 KiB",
		"maximum 16 KiB signed",
		"`nonce` and `get-nonce` requests remain capped at",
		"2 KiB",
		"`verify` and `link-wallet` remain capped at 20 KiB",
		"UTF-8 bytes",
		"missing, chunked, or forged",
		"REQUEST_BODY_TOO_LARGE",
	],
	deploymentDocFile,
	"the SIWE runbook must document raw-body limits, header-independent counting, and the no-store 413 contract",
);

checkIncludesAll(
	authClientTs,
	["dynamicAccessControl: { enabled: true }", "teams: { enabled: true }"],
	authClientFile,
	"account client must expose the same advanced organization contract as Auth",
);

checkIncludesAll(
	databaseTs,
	["new Pool", "env.HYPERDRIVE.connectionString", "max: 5"],
	databaseFile,
	"PostgreSQL must connect through the Hyperdrive binding",
);
checkIncludesAll(
	d1MigrationTs,
	[
		"LEGACY_D1_TABLES",
		"BEGIN",
		"ROLLBACK",
		"ON CONFLICT",
		"information_schema.columns",
		"sourceRows",
		"targetRows",
		"cinaauth_cutover_history",
	],
	d1MigrationFile,
	"D1 cutover must be schema-checked, transactional, idempotent, and count-verified",
);
checkIncludesAll(
	rateLimitTs,
	[
		"extends DurableObject<CloudflareBindings>",
		"rate_limit_buckets",
		"async consume(",
		"CREATE INDEX",
	],
	rateLimitFile,
	"Durable Object rate limiting must be atomic and bounded",
);
checkIncludesAll(
	rateLimitStorageTs,
	[
		'"/sign-in/*": { window: 60, max: 5 }',
		'"/email-otp/send-verification-otp": { window: 60, max: 10 }',
		'"/siwe/challenge": { window: 60, max: 10 }',
		'"/siwe/verify": { window: 60, max: 10 }',
		'"/siwe/link-wallet": { window: 60, max: 10 }',
		"...EMAIL_OTP_SEND_RATE_LIMIT_RULES",
		"...SIWE_RATE_LIMIT_RULES",
		"crypto.subtle.digest",
		"getByName",
		"consume:",
	],
	rateLimitStorageFile,
	"CinaAuth login, Email OTP, and SIWE proof endpoints must use deterministically sharded DO storage",
);

checkIncludesAll(
	deliveryTs,
	[
		"export const deliverToWebhook",
		"export const enqueueDelivery",
		"export const getDeliveryProviderCapabilities",
		"export const getRequiredDeliveryProvider",
		"export const handleDeliveryBatch",
		"CINAAUTH_DELIVERY_SERVICE.fetch",
		'"cinaauth.delivery.provider_not_ready"',
		"AbortSignal.timeout(3_000)",
		"X-CinaAuth-Delivery-Id",
		"X-CinaAuth-Delivery-Timestamp",
		"X-CinaAuth-Delivery-Signature",
		"crypto.subtle.sign",
		"message.ack()",
		"message.retry(",
	],
	deliveryFile,
	"delivery queue must sign webhook payloads and handle per-message failures",
);

checkIncludesAll(
	indexTs,
	[
		"getRequiredDeliveryProvider(pathname)",
		'code: "DELIVERY_PROVIDER_UNAVAILABLE"',
		"delivery[requiredDeliveryProvider]",
	],
	indexFile,
	"delivery-producing Auth endpoints must fail closed before entering the auth handler",
);

checkIncludesAll(
	privacyExportTs,
	[
		"createR2PrivacyExportProvider",
		"writePersonalDataExport",
		"TransformStream<Uint8Array",
		"ssecKey:",
		"customerKey",
		"handlePrivacyExportBatch",
		"sweepExpiredPrivacyExports",
		"message.ack()",
		"message.retry(",
		"cinaseek-personal-data-",
	],
	privacyExportFile,
	"privacy export generation must stream through Queue into per-object SSE-C encrypted R2 objects with retry and retention handling",
);

checkIncludesAll(
	privacyDeletionRuntimeTs,
	[
		"createWebhookPrivacyDeletionProcessor",
		"createRequiredPrivacyDeletionProcessor",
		"hasPrivacyDeletionProcessorRuntime",
		'protocol === "https:"',
		"crypto.subtle.sign",
		"`v1=${await signBody(body, secret)}`",
		'"X-CinaAuth-Operation-Id"',
		'"X-CinaAuth-Signature"',
		'status: "pending"',
		"retryAfterSeconds",
		"invalid erasure evidence",
	],
	privacyDeletionRuntimeFile,
	"external processor erasure calls must be HTTPS, HMAC-signed, idempotent, retryable, and fail closed on invalid evidence",
);

checkIncludesAll(
	pluginsTs,
	[
		"createRequiredPrivacyDeletionProcessor",
		"processors: [createRequiredPrivacyDeletionProcessor(env)]",
	],
	pluginsFile,
	"production account deletion must retain a fail-closed processor even when its runtime is incomplete",
);

check(
	privacyErasurePackage.name === "@cinaauth/privacy-erasure-worker" &&
		privacyErasurePackage.scripts?.["provision:secrets"] ===
			"node ./scripts/provision-secrets.mjs" &&
		privacyErasurePackage.scripts?.["check:cloudflare"] ===
			"node ./scripts/check-cloudflare-remote.mjs",
	"Privacy Erasure Worker must expose independent validation, provisioning, and deployment scripts",
);
check(
	privacyErasureWrangler.name === "cinaauth-privacy-erasure" &&
		privacyErasureWrangler.routes?.some(
			(route) =>
				route.pattern === "cinaauth-erasure.cinagroup.com" &&
				route.custom_domain === true,
		) &&
		privacyErasureWrangler.durable_objects?.bindings?.some(
			(binding) =>
				binding.name === "ERASURE_COORDINATOR" &&
				binding.class_name === "ErasureCoordinator",
		) &&
		privacyErasureWrangler.migrations?.some(
			(migration) =>
				migration.tag === "v1" &&
				migration.new_sqlite_classes?.includes("ErasureCoordinator"),
		),
	"Privacy Erasure Worker must use its Custom Domain and a migrated SQLite Durable Object",
);
checkIncludesAll(
	privacyErasureIndex,
	[
		'const ERASE_PATH = "/cinaauth/privacy/erase"',
		"readAuthenticatedOperation",
		"ERASURE_COORDINATOR.getByName",
		'"Cache-Control": "no-store"',
		'"ERASURE_RUNTIME_NOT_READY"',
		'"ERASURE_TARGET_UNAVAILABLE"',
	],
	privacyErasureIndexFile,
	"erasure ingress must remain authenticated, non-cacheable, per-operation coordinated, and fail closed",
);
checkIncludesAll(
	privacyErasureCoordinator,
	[
		"extends DurableObject<PrivacyErasureEnv>",
		"erasure_operations",
		"erasure_targets",
		"subject_digest",
		"evidence_digest",
		"lease_token",
		"Promise.allSettled",
		'status !== "pending"',
	],
	privacyErasureCoordinatorFile,
	"erasure coordination must persist non-PII evidence and skip completed targets under a lease",
);
checkIncludesAll(
	privacyErasureProtocol,
	[
		"MAX_BODY_BYTES",
		"verifyBodySignature",
		"timingSafeEqual",
		'url.protocol !== "https:"',
		"AbortSignal.timeout",
		"targets_empty",
	],
	privacyErasureProtocolFile,
	"erasure protocol parsing must bound bodies, verify HMACs, require HTTPS targets, and reject empty target sets",
);
checkIncludesAll(
	privacyErasureProvision,
	[
		"CINAAUTH_ERASURE_STORAGE_SECRET",
		"CINAAUTH_ERASURE_TARGETS",
		"--include-legacy-webhook",
		"--include-legacy-targets",
		'fileURLToPath(import.meta.resolve("wrangler"))',
		"process.execPath",
		"input: `${env[name]}\\n`",
		'stdio: ["pipe", "inherit", "inherit"]',
	],
	privacyErasureProvisionFile,
	"erasure provisioning must keep only the storage key required and make legacy webhook/targets explicit stdin-only migration inputs",
);
checkIncludesAll(
	privacyErasureRemote,
	[
		"/workers/scripts/${config.name}/settings",
		'{ binding: "ERASURE_COORDINATOR", className: "ErasureCoordinator" }',
		'{ binding: "ERASURE_CONFIG", className: "ErasureConfigDurableObject" }',
		"/workers/durable_objects/namespaces/${binding.namespace_id}",
		"durableNamespace.use_sqlite !== true",
		"/workers/scripts/${config.name}/deployments",
		'version.resources?.script_runtime?.migration_tag !== "v2"',
		"CINAAUTH_ERASURE_CONFIG_KEK_STORE",
		"body.runtimeConfig?.structuralReady !== true",
		"body.runtimeConfig?.operationalReady !== false",
		"Readiness must not expose target URLs or secret fields",
	],
	privacyErasureRemoteFile,
	"remote erasure acceptance must verify both SQLite DOs, active Store bindings, fail-closed bootstrap, and redacted readiness",
);
checkIncludesAll(
	privacyErasureDeployment,
	[
		"Raw",
		"user IDs, emails",
		"CINAAUTH_ERASURE_STORAGE_SECRET",
		"CINAAUTH_ERASURE_TARGETS",
		"/internal/config/erasure/stage",
		"X-CinaAuth-Operation-Id",
		"privacy-center policy",
	],
	privacyErasureDeploymentFile,
	"erasure deployment docs must define persistence, dynamic bootstrap, target, and policy-version contracts",
);

checkIncludesAll(
	configureDeliveryQueues,
	[
		"cinaauth-delivery",
		"cinaauth-delivery-dlq",
		"cinaauth-cinatoken-identity-events",
		"cinaauth-cinatoken-identity-events-dlq",
		"--message-retention-period-secs",
		"DELIVERY_QUEUE_RETENTION_SECONDS",
		"backlog_count",
		"Refusing to reduce Queue",
	],
	configureDeliveryQueuesFile,
	"delivery resources must be provisioned repeatably with bounded Queue and DLQ retention",
);

checkIncludesAll(
	configurePrivacyExport,
	[
		"cinaauth-privacy-exports",
		"cinaauth-privacy-export-dlq",
		"--message-retention-period-secs",
		"86400",
		"--expire-days",
		"privacy-exports/",
	],
	configurePrivacyExportFile,
	"privacy export resources must be provisioned repeatably with bounded Queue and R2 retention",
);

checkIncludesAll(
	checkPlanetScaleBackups,
	[
		"PLANETSCALE_SERVICE_TOKEN_ID",
		"PLANETSCALE_SERVICE_TOKEN",
		"read_backups",
		"backup-policies",
		'query: { all: true, state: "success" }',
		"protected from deletion",
		"purgeNoLaterThan",
		"deleted_at",
		"physical-media sanitization certificate",
	],
	checkPlanetScaleBackupsFile,
	"PlanetScale backup evidence must be read-only, receipt-aware, and explicit about its assurance boundary",
);

checkIncludesAll(
	envTs,
	[
		"extends Cloudflare.Env",
		"CINAAUTH_SECRET: string",
		"CINAAUTH_DELIVERY_QUEUE: Queue<DeliveryMessage>",
		"CINAAUTH_ERASURE_SERVICE: Fetcher",
		"VERSION_METADATA: WorkerVersionMetadata",
		"CINAAUTH_MIGRATION_TOKEN?: string",
		"CINAAUTH_D1_MIGRATION_TOKEN?: string",
		"CINAAUTH_CUTOVER_STATE?",
		"CINAAUTH_SIWE_ENABLED?: string",
		"CINAAUTH_SIWE_ALLOWED_CHAIN_IDS?: string",
		"CINAAUTH_SIWE_RP_DOMAIN?: string",
		"CINAAUTH_SIWE_RP_URI?: string",
		"CINAAUTH_SIWE_ALLOW_LEGACY?: string",
		"CINAAUTH_SIWE_AUTO_SIGNUP?: string",
		"LEGACY_D1: D1Database",
		"CINAAUTH_DELIVERY_WEBHOOK_URL?: string",
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET?: string",
		"CINAAUTH_PRIVACY_EXPORT_QUEUE: Queue<PrivacyExportMessage>",
		"CINAAUTH_PRIVACY_EXPORTS: R2Bucket",
		"CINAAUTH_PRIVACY_EXPORT_KEY?: string",
		"CINAAUTH_ERASURE_WEBHOOK_URL?: string",
		"CINAAUTH_ERASURE_WEBHOOK_SECRET?: string",
		"CINAAUTH_ENTITLEMENT_CONFIG?: string",
	],
	envFile,
	"binding types must stay aligned with Worker runtime inputs",
);

checkIncludesAll(
	siweRuntimeConfigTs,
	[
		'env.CINAAUTH_SIWE_ENABLED !== "true"',
		"Number.isSafeInteger(chainId)",
		'url.protocol === "https:"',
		'env.CINAAUTH_SIWE_ALLOW_LEGACY !== "false"',
		'env.CINAAUTH_SIWE_AUTO_SIGNUP !== "false"',
		'env.CINAAUTH_SIWE_AUTO_SIGNUP !== "true"',
		'autoSignup: env.CINAAUTH_SIWE_AUTO_SIGNUP === "true"',
		'walletType: "eoa-only"',
	],
	siweRuntimeConfigFile,
	"SIWE production configuration must parse explicit non-secret controls and fail closed",
);

checkIncludesAll(
	workflow,
	[
		"workflow_dispatch:",
		"restore_rehearsal_completed:",
		"restore_rehearsal_reference:",
		"backup_reference:",
		"operator_attestation:",
		"DEPLOY CINAAUTH PRODUCTION",
		"authorize-production",
		"PLANETSCALE_SERVICE_TOKEN_ID",
		"PLANETSCALE_SERVICE_TOKEN",
		"node workers/auth-api/scripts/check-planetscale-backups.mjs",
		"report.activeBackups",
		"pnpm run check",
		"pnpm run check:cloudflare",
		"pnpm run provision:secrets",
		"pnpm run build",
		"cloudflare/wrangler-action@v3",
		"deploy-delivery",
		"Deploy Delivery Worker",
		"workers/delivery",
		"deploy-privacy-erasure",
		"Deploy Privacy Erasure Worker",
		"workers/privacy-erasure",
		"Verify Delivery Worker structural bootstrap",
		"Verify Privacy Erasure structural bootstrap",
		"--allow-not-ready",
		"needs: authorize-production",
		"needs: [authorize-production, preflight-account-portal]",
		"needs: [deploy-delivery, deploy-privacy-erasure, preflight-account-portal]",
		"deploy-account-portal",
		"deploy-admin-console",
		"uses: ./.github/workflows/deploy-account-portal.yml",
		"uses: ./.github/workflows/deploy-admin-console.yml",
		"needs: deploy-worker",
		"deployment_mode: central",
		"secrets: inherit",
		"CLOUDFLARE_API_TOKEN",
		"CLOUDFLARE_ACCOUNT_ID",
		"Verify preserved Cloudflare Worker secret inventory",
		"node scripts/check-cloudflare-preserved-secrets.mjs",
		"CINAAUTH_HYPERDRIVE_ID",
		"pnpm run configure:hyperdrive",
		"pnpm run configure:delivery-queues",
		"pnpm run configure:privacy-export",
		"CINAAUTH_MIGRATION_TOKEN",
		'test "${#CINAAUTH_MIGRATION_TOKEN}" -ge 32',
		"CINAAUTH_ENTITLEMENT_CONFIG",
		"https://cinaauth-delivery.cinagroup.com/cinaauth/delivery",
		"Provision Auth Worker mutable and configured optional secrets",
		"run: pnpm run provision:secrets",
		"https://auth.cinaseek.ai/api/migrate",
		"-X POST 'https://auth.cinaseek.ai/api/migrate?feature=organization-advanced'",
		"https://auth.cinaseek.ai/api/ready",
	],
	workflowFile,
	"backend CI must require manual recovery evidence and a live backup audit before deploying child Workers, Auth migrations, and reusable frontends",
);
const centralTrigger = workflow.slice(
	workflow.indexOf("on:"),
	workflow.indexOf("permissions:"),
);
check(
	!centralTrigger.includes("\n  push:") &&
		!centralTrigger.includes("\n  workflow_call:"),
	`${rel(workflowFile)} must expose workflow_dispatch as its only production entrypoint`,
);
const authorizationJob = workflowJobBlock(
	workflow,
	"authorize-production",
	"preflight-account-portal",
);
checkIncludesAll(
	authorizationJob,
	[
		"environment: production",
		"needs: validate-deployment-contract",
		"inputs.restore_rehearsal_completed",
		"inputs.restore_rehearsal_reference",
		"inputs.backup_reference",
		"inputs.operator_attestation",
		"refs/heads/main",
		"PLANETSCALE_SERVICE_TOKEN_ID",
		"PLANETSCALE_SERVICE_TOKEN",
		"node workers/auth-api/scripts/check-planetscale-backups.mjs",
		"report.activeBackups",
		"Verify preserved Cloudflare Worker secret inventory",
		"CLOUDFLARE_API_TOKEN",
		"CLOUDFLARE_ACCOUNT_ID",
		"node scripts/check-cloudflare-preserved-secrets.mjs",
	],
	workflowFile,
	"the pre-write production job must fail closed on environment approval, recovery evidence, the attested active backup, and read-only PlanetScale credentials",
);
check(
	!authorizationJob.includes("cloudflare/wrangler-action") &&
		!authorizationJob.includes("command: deploy") &&
		!authorizationJob.includes("-X POST") &&
		!authorizationJob.includes("secret put") &&
		!authorizationJob.includes("secret bulk"),
	`${rel(workflowFile)} production authorization must remain read-only`,
);
const accountPreflightJob = workflowJobBlock(
	workflow,
	"preflight-account-portal",
	"deploy-delivery",
);
checkIncludesAll(
	accountPreflightJob,
	[
		"needs: authorize-production",
		"environment: production",
		"working-directory: apps/account-portal",
		"CINAAUTH_PLANNED_WORKER_CONFIG: ../../workers/auth-api/wrangler.json",
		"CINAAUTH_ACCOUNT_BUILD_READINESS_URL: https://accounts.cinaseek.ai/api/build-readiness",
		"CINAAUTH_CAPABILITIES_URL: https://accounts.cinaseek.ai/api/auth/capabilities",
		"CINAAUTH_EMAIL_AUTH_GATE: portal-compatible",
		"REOWN_PROJECT_ID: ${{ secrets.REOWN_PROJECT_ID }}",
		"NEXT_PUBLIC_REOWN_PROJECT_ID: ${{ secrets.REOWN_PROJECT_ID }}",
		"Configure wallet UI rollout from tracked Auth config",
		"NEXT_PUBLIC_SIWE_WALLET_UI_ENABLED",
		"pnpm run test:oauth-build",
		"pnpm run check:oauth-build",
		"pnpm run typecheck",
		"pnpm run build:cf",
		"lib/auth-runtime-config.test.ts",
		"lib/auth-runtime-routes.test.ts",
		"lib/auth.test.ts",
		"lib/auth-card-sign-in-contract.test.ts",
		"lib/auth-ui-phase1-contract.test.ts",
		"lib/auth-ui-phase2-contract.test.ts",
		"lib/sign-in-step-up-contract.test.ts",
		"lib/two-factor-navigation.test.ts",
		"lib/two-factor-recovery.test.ts",
		"lib/reown-wallet-gate.test.ts",
		"lib/reown-wallet-cookie.test.ts",
		"lib/siwe-wallet-protocol.test.ts",
		"lib/reown-wallet-source-contract.test.ts",
		"lib/account-build-readiness.test.ts",
	],
	workflowFile,
	"the planned SIWE client configuration and Account Portal bundle must pass before any Cloudflare deployment",
);
check(
	!accountPreflightJob.includes("vars.REOWN_PROJECT_ID"),
	`${rel(workflowFile)} Account Portal preflight must consume the configured repository secret, not a GitHub variable`,
);
check(
	!accountPreflightJob.includes("cloudflare/wrangler-action") &&
		!accountPreflightJob.includes("command: deploy") &&
		!accountPreflightJob.includes("pnpm run deploy"),
	`${rel(workflowFile)} Account Portal preflight must remain read-only`,
);
for (const [job, nextJob] of [
	["deploy-delivery", "deploy-privacy-erasure"],
	["deploy-privacy-erasure", "deploy-worker"],
]) {
	checkIncludes(
		workflowJobBlock(workflow, job, nextJob),
		"needs: [authorize-production, preflight-account-portal]",
		workflowFile,
		`${job} must wait for recovery authorization and the Account Portal preflight`,
	);
}
const authWorkerDeploymentJob = workflowJobBlock(
	workflow,
	"deploy-worker",
	"deploy-account-portal",
);
checkIncludes(
	authWorkerDeploymentJob,
	"needs: [deploy-delivery, deploy-privacy-erasure, preflight-account-portal]",
	workflowFile,
	"Auth Worker deployment must wait for the Account Portal preflight",
);
checkIncludesAll(
	authWorkerDeploymentJob,
	[
		"- name: Install dependencies",
		"- name: Build Auth workspace dependencies",
		"- name: Configure Hyperdrive binding",
		"- name: Check Worker types and bindings",
	],
	workflowFile,
	"Auth Worker deployment must build workspace dependencies before configuration and type checks",
);
check(
	/^\s+run: pnpm run build:dependencies\s*$/m.test(authWorkerDeploymentJob),
	`${rel(workflowFile)} Auth Worker dependency build step must run exactly pnpm run build:dependencies`,
);
const authInstallIndex = authWorkerDeploymentJob.indexOf(
	"- name: Install dependencies",
);
const authWorkspaceBuildIndex = authWorkerDeploymentJob.indexOf(
	"- name: Build Auth workspace dependencies",
);
const authHyperdriveConfigIndex = authWorkerDeploymentJob.indexOf(
	"- name: Configure Hyperdrive binding",
);
const authWorkerCheckIndex = authWorkerDeploymentJob.indexOf(
	"- name: Check Worker types and bindings",
);
check(
	authInstallIndex >= 0 &&
		authWorkspaceBuildIndex > authInstallIndex &&
		authHyperdriveConfigIndex > authWorkspaceBuildIndex &&
		authWorkerCheckIndex > authHyperdriveConfigIndex,
	`${rel(workflowFile)} Auth Worker must install dependencies, build its workspace dependency closure, configure Hyperdrive, then check Worker types and bindings`,
);
checkIncludesAll(
	deploymentDoc,
	[
		"Production deployment has no `push` trigger",
		"restore_rehearsal_completed",
		"restore_rehearsal_reference",
		"backup_reference",
		"operator_attestation",
		"DEPLOY CINAAUTH PRODUCTION",
		"PLANETSCALE_SERVICE_TOKEN_ID",
		"PLANETSCALE_SERVICE_TOKEN",
		"read_backups",
		"GitHub `production` environment",
		"workflow does not create,",
		"modify, or delete a PlanetScale branch",
	],
	deploymentDocFile,
	"the deployment runbook must describe the manual recovery attestation, live backup gate, production environment, and automation boundary",
);
for (const [job, nextJob] of [
	["deploy-delivery", "deploy-privacy-erasure"],
	["deploy-privacy-erasure", "deploy-worker"],
	["deploy-worker", "deploy-account-portal"],
]) {
	checkIncludes(
		workflowJobBlock(workflow, job, nextJob),
		"environment: production",
		workflowFile,
		`${job} is a production deployment job`,
	);
}
check(
	[
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
		"CINAAUTH_ERASURE_WEBHOOK_SECRET",
		"CINAADMIN_OIDC_CLIENT_SECRET",
		"CINAADMIN_OIDC_BRIDGE_SECRET",
		"CINAAUTH_ERASURE_TARGETS",
		"CINAAUTH_SECRET",
		"CINAAUTH_PRIVACY_EXPORT_KEY",
		"CINAAUTH_ERASURE_STORAGE_SECRET",
		"RESEND_API_KEY",
		"RESEND_EMAIL_FROM",
		"CLOUDFLARE_EMAIL_API_TOKEN",
		"CLOUDFLARE_EMAIL_FROM",
		"TWILIO_ACCOUNT_SID",
		"TWILIO_AUTH_TOKEN",
		"TWILIO_FROM_NUMBER",
	].every((name) => !workflow.includes(name)),
	`${rel(workflowFile)} must not require active Store values or post-deploy provider/target configuration as deployment secrets`,
);
checkIncludesAll(
	accountWorkflow,
	[
		"workflow_call",
		"environment: production",
		"apps/account-portal",
		"accounts.cinaseek.ai",
		"NEXT_PUBLIC_CINAAUTH_API_URL: https://accounts.cinaseek.ai",
		"REOWN_PROJECT_ID: ${{ secrets.REOWN_PROJECT_ID }}",
		"NEXT_PUBLIC_REOWN_PROJECT_ID: ${{ secrets.REOWN_PROJECT_ID }}",
		"Configure wallet UI rollout from tracked Auth config",
		"NEXT_PUBLIC_SIWE_WALLET_UI_ENABLED",
		"pnpm run test:oauth-build",
		"pnpm run check:oauth-build",
		"Verify live configurable authentication contract",
		"CINAAUTH_CAPABILITIES_URL: https://accounts.cinaseek.ai/api/auth/capabilities",
		"CINAAUTH_EMAIL_AUTH_GATE: runtime-configurable",
		"lib/auth-runtime-config.test.ts",
		"lib/auth-runtime-routes.test.ts",
		"lib/auth.test.ts",
		"lib/auth-card-sign-in-contract.test.ts",
		"lib/auth-ui-phase1-contract.test.ts",
		"lib/auth-ui-phase2-contract.test.ts",
		"lib/sign-in-step-up-contract.test.ts",
		"lib/two-factor-navigation.test.ts",
		"lib/two-factor-recovery.test.ts",
		"lib/reown-wallet-gate.test.ts",
		"lib/reown-wallet-cookie.test.ts",
		"lib/siwe-wallet-protocol.test.ts",
		"lib/reown-wallet-source-contract.test.ts",
		"lib/account-build-readiness.test.ts",
		"CINAAUTH_MIGRATION_TOKEN",
		'test "${#CINAAUTH_MIGRATION_TOKEN}" -ge 32',
		"Wait for governed Auth readiness",
		"super-admin-governance-v1",
		"provider-namespace-registry-v1",
		"ready.database?.invariants?.ok",
		"pnpm run typecheck",
		"pnpm run build:cf",
		"pnpm run test:deploy-cf",
		"pnpm run deploy:cf --deployment-target=production",
		"demo-auth.cinagroup.com",
	],
	accountWorkflowFile,
	"account portal CI must remain a reusable production-environment unit with governed readiness and redirect smoke coverage",
);
check(
	!accountWorkflow.includes("NEXT_PUBLIC_GOOGLE_CLIENT_ID"),
	`${rel(accountWorkflowFile)} must not expose the Google OAuth client ID to the Account Portal bundle`,
);
check(
	accountWorkflow.indexOf("CINAAUTH_EMAIL_AUTH_GATE: runtime-configurable") >=
		0 &&
		accountWorkflow.indexOf("CINAAUTH_EMAIL_AUTH_GATE: runtime-configurable") <
			accountWorkflow.indexOf(
				"pnpm run deploy:cf --deployment-target=production",
			),
	`${rel(accountWorkflowFile)} must verify the live configurable authentication contract before the Account Portal write`,
);
check(
	!accountWorkflow.includes("vars.REOWN_PROJECT_ID"),
	`${rel(accountWorkflowFile)} must consume the configured repository secret, not a GitHub variable`,
);
check(
	!accountWorkflow.includes("CINAAUTH_DEMO_SECRET") &&
		!accountWorkflow.includes("wrangler secret put") &&
		!accountWorkflow.includes("push:"),
	`${rel(accountWorkflowFile)} must not provision a duplicate Auth secret or expose an automatic production trigger`,
);
checkIncludesAll(
	accountWorkflow,
	[
		"workflow_call:",
		"workflow_dispatch:",
		"deployment_mode:",
		"Validate reusable Account deployment mode",
		"if: inputs.deployment_mode != ''",
		"if: inputs.deployment_mode == ''",
		"if: inputs.deployment_mode == 'central'",
		"DEPLOY CINAAUTH ACCOUNT PORTAL PHASE ONE",
		"GITHUB_REF",
		"refs/heads/main",
		"CINAAUTH_PLANNED_WORKER_CONFIG: ../../workers/auth-api/wrangler.json",
		"CINAAUTH_SIWE_ENABLED",
		"Verify deployed Account wallet readiness parity",
		"readiness.schemaVersion !== 1",
		"readiness.ready !== expectedReady",
		"cinaauth-siwe-v2",
		"reown-appkit-v1",
		"readiness.walletUiEnabled !== expectedWalletUiEnabled",
		"readiness.reownProjectId !== expectedProjectId",
	],
	accountWorkflowFile,
	"the Account Portal must preserve its attested Phase One entrypoint and verify every deployed wallet marker against the tracked release",
);
const accountTrigger = accountWorkflow.slice(
	accountWorkflow.indexOf("on:"),
	accountWorkflow.indexOf("permissions:"),
);
const accountWorkflowCallStart = accountTrigger.indexOf("  workflow_call:");
const accountWorkflowDispatchStart = accountTrigger.indexOf(
	"  workflow_dispatch:",
);
check(
	accountWorkflowCallStart !== -1 &&
		accountWorkflowDispatchStart > accountWorkflowCallStart &&
		accountTrigger
			.slice(accountWorkflowCallStart, accountWorkflowDispatchStart)
			.includes("deployment_mode:") &&
		!accountTrigger
			.slice(accountWorkflowDispatchStart)
			.includes("deployment_mode:") &&
		!accountWorkflow.includes("if: github.event_name"),
	`${rel(accountWorkflowFile)} must expose central mode only to workflow_call and keep direct dispatch on the Phase One path`,
);
check(
	(
		accountWorkflow.match(
			/run: pnpm run deploy:cf --deployment-target=production/g,
		) ?? []
	).length === 1 &&
		!accountWorkflow.includes("cloudflare/wrangler-action@v3") &&
		!accountWorkflow.includes("command: deploy"),
	`${rel(accountWorkflowFile)} must deploy the Account Portal exactly once`,
);
check(
	accountPackage.name === "@cinaauth/account-portal" &&
		adminPackage.name === "@cinaauth/admin-console",
	"frontend workspace package names must reflect the account/admin deployment split",
);
checkIncludesAll(
	accountWrangler,
	[
		'pattern = "accounts.cinaseek.ai"',
		'pattern = "demo-auth.cinagroup.com"',
		'binding = "AUTH_WORKER"',
		'service = "cinaauth-api"',
		'CINAAUTH_REQUIRE_AUTH_WORKER_BINDING = "true"',
		'NEXT_PUBLIC_CINAAUTH_API_URL = "https://accounts.cinaseek.ai"',
	],
	accountWranglerFile,
	"account portal must keep Service Binding and the legacy redirect host",
);
checkIncludesAll(
	accountMiddleware,
	[
		"demo-auth.cinagroup.com",
		"accounts.cinaseek.ai",
		"NextResponse.redirect(accountURL, 308)",
		"buildAccountSignInPath",
		"ACCOUNT_RETURN_PATH_HEADER",
		"request.nextUrl.pathname",
		"request.nextUrl.search",
	],
	accountMiddlewareFile,
	"legacy traffic must permanently redirect and protected account routes must preserve a same-origin post-login callback",
);
checkIncludesAll(
	accountSignInExperience,
	[
		"callbackURL: sanitizeAccountCallbackURL(callbackURL)",
		'params.get("callbackURL") ?? params.get("callbackUrl")',
		'value.startsWith("//")',
		"https://accounts.cinaseek.ai",
	],
	accountSignInExperienceFile,
	"account sign-in return targets must use the canonical callback key, retain the legacy device alias, and stay on the Accounts origin",
);
checkIncludesAll(
	accountEmailOtpFlow,
	[
		"requiresExistingEmailOtpUser",
		"return false",
		"completeEmailOtpAuthentication",
		"hasSignedOidcCreatePrompt",
	],
	accountEmailOtpFlowFile,
	"ordinary email authentication must permit OTP-gated first-time users while preserving signed OIDC creation",
);
checkIncludesAll(
	accountSignInPage,
	["SignInPageShell"],
	accountSignInPageFile,
	"the Account Portal must expose a single sign-in-or-create entry",
);
checkIncludesAll(
	accountSignInPageShell,
	["messages.signInPageTitle"],
	accountSignInPageShellFile,
	"the Account Portal sign-in shell must render its localized unified-entry title",
);
checkIncludesAll(
	accountSignInComponent,
	[
		"completeEmailOtpAuthentication",
		"hasSignedOidcCreatePrompt",
		"created: true",
		"messages.newWalletAccount",
	],
	accountSignInComponentFile,
	"the unified entry must preserve create-prompt continuation and explain first-wallet account creation",
);
checkIncludesAll(
	accountLegacyAuthRedirect,
	["buildUnifiedSignUpRedirect", "buildUnifiedSignInRedirect(input)"],
	accountLegacyAuthRedirectFile,
	"legacy sign-up links must use the private sanitized signed-query redirect for the unified entry",
);
for (const [file, source] of [
	[accountLegacySignUpPageFile, accountLegacySignUpPage],
	[accountLegacyEmailSignUpPageFile, accountLegacyEmailSignUpPage],
]) {
	checkIncludesAll(
		source,
		["buildUnifiedSignUpRedirect", "redirect("],
		file,
		"legacy sign-up pages must redirect to the unified account entry",
	);
	check(
		!source.includes("<AuthShell") && !source.includes("<EmailOtpForm"),
		`${rel(file)} must not retain a separate registration UI`,
	);
}
checkIncludesAll(
	legacyAdminPage,
	["permanentRedirect", "https://admin.cinaseek.ai"],
	legacyAdminPageFile,
	"the account portal must not retain a second admin console",
);
checkIncludesAll(
	adminWrangler,
	[
		'"pattern": "admin.cinaseek.ai"',
		'"binding": "AUTH_WORKER"',
		'"service": "cinaauth-api"',
		'"CINAUTH_AUTH_URL": "https://accounts.cinaseek.ai"',
	],
	adminWranglerFile,
	"admin console must call the authoritative Auth Worker through Service Binding",
);
checkIncludesAll(
	adminFetcher,
	["getCloudflareContext", "AUTH_WORKER", "fetchAuthRequest"],
	adminFetcherFile,
	"admin server reads and mutations must resolve the Service Binding",
);
checkIncludesAll(
	adminOidcContract,
	[
		'ADMIN_OIDC_CLIENT_ID = "cinaseek-admin-console"',
		"ADMIN_OIDC_REDIRECT_URI",
		"ADMIN_OIDC_RESOURCE",
	],
	adminOidcContractFile,
	"Admin OIDC identifiers and exact redirect URI must be shared",
);
checkIncludesAll(
	adminOidcClient,
	[
		"ClientSecretBasic",
		"calculatePKCECodeChallenge",
		"validateApplicationLevelSignature",
		"processUserInfoResponse",
		"resource: ADMIN_OIDC_RESOURCE",
	],
	adminOidcClientFile,
	"Admin must implement confidential Authorization Code, PKCE, and OIDC validation",
);
checkIncludesAll(
	adminOidcLogin,
	[
		"generateRandomState",
		"generateRandomNonce",
		"generateRandomCodeVerifier",
		"httpOnly: true",
		'sameSite: "lax"',
	],
	adminOidcLoginFile,
	"Admin OIDC start route must bind PKCE and nonce to an HttpOnly transaction",
);
checkIncludesAll(
	adminOidcCallback,
	[
		"/api/auth/admin-oidc/session",
		"CINAADMIN_OIDC_BRIDGE_SECRET",
		"toHostOnlyCookie",
		"admin_forbidden",
	],
	adminOidcCallbackFile,
	"Admin callback must bridge tokens server-side and enforce administrator role",
);
checkIncludesAll(
	adminProvisionSecrets,
	[
		"CINAADMIN_OIDC_CLIENT_SECRET",
		"CINAADMIN_OIDC_BRIDGE_SECRET",
		"CINAADMIN_OIDC_TRANSACTION_SECRET",
		"spawnSync",
		"input: value",
	],
	adminProvisionSecretsFile,
	"Admin OIDC secrets must be provisioned through stdin",
);
checkIncludesAll(
	authWebContract,
	[
		"ADMIN_CONSOLE_ROLES",
		"ADMIN_PERMISSION_STATEMENT",
		"ADMIN_ROLE_PERMISSIONS",
	],
	authWebContractFile,
	"role names and permissions must remain a shared cross-deployment contract",
);
checkIncludesAll(
	adminWorkflow,
	[
		"workflow_call",
		"environment: production",
		"apps/admin-console",
		"admin.cinaseek.ai",
		"pnpm run cf-typegen",
		"pnpm run typecheck",
		"pnpm run test",
		"pnpm run build:cf",
		"cloudflare/wrangler-action@v3",
		"CINAAUTH_MIGRATION_TOKEN",
		"Wait for governed Auth readiness",
		"super-admin-governance-v1",
		"provider-namespace-registry-v1",
		"ready.database?.invariants?.ok",
	],
	adminWorkflowFile,
	"admin console CI must remain a reusable production-environment unit after governed Auth readiness",
);
check(
	!adminWorkflow.includes("CINAADMIN_OIDC_CLIENT_SECRET") &&
		!adminWorkflow.includes("CINAADMIN_OIDC_BRIDGE_SECRET") &&
		!adminWorkflow.includes("CINAADMIN_OIDC_TRANSACTION_SECRET") &&
		!adminWorkflow.includes("provision:secrets") &&
		!adminWorkflow.includes("workflow_dispatch:") &&
		!adminWorkflow.includes("push:"),
	`${rel(adminWorkflowFile)} must use active Store bindings without V1 OIDC provisioning or bypassing the central production gate`,
);
check(
	accountWorkflow.indexOf("Wait for governed Auth readiness") <
		accountWorkflow.indexOf("Deploy account portal"),
	`${rel(accountWorkflowFile)} must verify governed Auth readiness before deployment`,
);
check(
	adminWorkflow.indexOf("Wait for governed Auth readiness") <
		adminWorkflow.indexOf("Deploy admin console"),
	`${rel(adminWorkflowFile)} must verify Auth readiness before deployment`,
);
check(
	workflow.indexOf("deploy-worker:") <
		workflow.indexOf("deploy-account-portal:") &&
		workflow.indexOf("deploy-worker:") <
			workflow.indexOf("deploy-admin-console:"),
	`${rel(workflowFile)} must serialize both frontend workflows after Auth`,
);
check(
	!workflow.includes("https://auth.cinagroup.com") &&
		!workflow.includes("wrangler d1 time-travel"),
	`${rel(workflowFile)} must not retain the retired auth domain or D1 recovery commands`,
);

checkIncludesAll(
	remotePreflight,
	[
		"fileURLToPath(import.meta.url)",
		'join(workerDir, "wrangler.json")',
		"MAX_ATTEMPTS",
		"describeFetchError",
		"CINAAUTH_REQUIRE_ALL_PLUGIN_INPUTS",
		"CLOUDFLARE_TURNSTILE_SITE_KEY",
		"CLOUDFLARE_TURNSTILE_SECRET_KEY",
		"DEFAULT_TURNSTILE_WIDGET_NAME",
		"checkTurnstileResource",
		"Turnstile Sites Write",
		"GOOGLE_CLIENT_ID",
		"GOOGLE_CLIENT_SECRET",
		"GITHUB_CLIENT_ID",
		"GITHUB_CLIENT_SECRET",
		"GENERIC_OAUTH_CONFIG",
		"STRIPE_SECRET_KEY",
		"STRIPE_WEBHOOK_SECRET",
		"STRIPE_DEFAULT_PRICE_ID",
		"CINAAUTH_ENTITLEMENT_CONFIG",
		"CLOUDFLARE_API_TOKEN",
		"CF_API_TOKEN",
		"CLOUDFLARE_ACCOUNT_ID",
		"/hyperdrive/configs",
		"caching?.disabled",
		"/d1/database/",
		"/r2/buckets",
		"checkPrivacyExportBucket",
		"/queues",
		"MAX_QUEUE_RETENTION_SECONDS",
		"message_retention_period",
		"/workers/scripts/",
		"checkWorkerBindings",
		"SIWE_RUNTIME_VARIABLE_NAMES",
		'item.type === "plain_text"',
		"must match the tracked non-secret SIWE config",
		"CINAAUTH_DELIVERY_SERVICE",
		"CINAAUTH_ERASURE_SERVICE",
		"cinaauth-privacy-erasure",
		"SECRETS_STORE_BINDINGS",
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET_STORE_V2",
		"CINAAUTH_ERASURE_WEBHOOK_SECRET_STORE_V2",
		"CINAADMIN_OIDC_CLIENT_SECRET_STORE_V2",
		"CINAADMIN_OIDC_BRIDGE_SECRET_STORE_V2",
		'item.type === "secrets_store_secret"',
		"/workers/domains",
		"CINAAUTH_SECRET",
		"CINAAUTH_MIGRATION_TOKEN",
		"CINAAUTH_DELIVERY_WEBHOOK_URL",
		"CINAAUTH_PRIVACY_EXPORT_KEY",
		"CINAAUTH_ERASURE_WEBHOOK_URL",
		"checkAuthReadiness",
		"evaluateRuntimeCapabilities",
		"configuredValues: config.vars ?? {}",
		"evaluateDeliveryCapabilityParity",
		"DELIVERY_READY_URL",
		'new URL("/api/auth/capabilities", origin)',
	],
	remotePreflightFile,
	"Cloudflare remote preflight must verify deploy prerequisites without printing secret values",
);
checkIncludesAll(
	authReadinessCheck,
	[
		'new URL("/api/ready", origin)',
		"migrationToken",
		"authorizedReadiness",
		"Authorized auth readiness is unreachable",
		"!authorizedReadiness.ok",
		"Cache-Control: no-store",
		"body.secretsStore?.active !== true",
		'body.secretsStore?.source !== "secrets-store-v2"',
		"body.database?.ok",
		'body.cutover?.state !== "live"',
	],
	authReadinessCheckFile,
	"Auth readiness verification must fail closed on unreachable or non-success authorized responses",
);
const remoteRequiredSecrets =
	remotePreflight.match(
		/const REQUIRED_WORKER_SECRETS = \[([\s\S]*?)\];/,
	)?.[1] ?? "";
check(
	[
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
		"CINAAUTH_ERASURE_WEBHOOK_SECRET",
		"CINAADMIN_OIDC_CLIENT_SECRET",
		"CINAADMIN_OIDC_BRIDGE_SECRET",
	].every((name) => !remoteRequiredSecrets.includes(`"${name}"`)),
	`${rel(remotePreflightFile)} must not require legacy V1 shared secrets when active V2 bindings exist`,
);
checkIncludesAll(
	runtimeCapabilitiesCheck,
	[
		"Live authentication capabilities must use the runtime-configurable schema version 5",
		"Live One Tap capability requires an enabled Google provider and public client id",
		"Disabled One Tap capability must not expose a Google client id",
		"Turnstile secrets are configured but the live captcha capability is disabled",
		"Stripe billing inputs are configured but the live billing capability is disabled",
		"Live SIWE capability must remain disabled while the deployment kill switch is off",
		"Live Email OTP cannot be enabled without an active Delivery Worker email provider",
		"Live email-password capability must be a boolean runtime setting",
		"Live magic-link capability must remain disabled because the method is not deployed",
		"Live phone OTP capability does not match Delivery Worker readiness",
		"Live username-password capability must remain disabled because the method is not deployed",
	],
	runtimeCapabilitiesCheckFile,
	"remote preflight must fail when configured optional secrets are rejected by the live runtime",
);

checkIncludesAll(
	deliveryRemotePreflight,
	[
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
		"custom_domain",
		"/workers/domains",
		"Detailed delivery readiness was not checked",
		"body.providers?.email",
		"body.providers?.sms",
		"body.replay?.kv",
	],
	deliveryRemotePreflightFile,
	"Delivery remote acceptance must validate both providers and the replay store when authorized",
);
checkIncludesAll(
	cloudflareEdgeMitigation,
	[
		"status !== 403",
		'contentType !== "text/html"',
		'headers.get("cf-mitigated")',
		'=== "challenge"',
		'headers.get("cf-ray")',
		"bodyRayId === headerRayId",
		"attention required",
		"you have been blocked",
		"cloudflare\\s+ray\\s+id",
	],
	cloudflareEdgeMitigationFile,
	"the shared Cloudflare mitigation classifier must require strict 403 HTML edge evidence",
);
checkIncludesAll(
	cloudflareEdgeMitigationTest,
	[
		"ordinary JSON 403 responses",
		"without a Cloudflare Ray",
		"generic HTML and non-403 branded pages",
		'"content-type": "application/json"',
	],
	cloudflareEdgeMitigationTestFile,
	"the Cloudflare mitigation contract must reject application and ambiguous responses",
);
for (const [remotePreflight, file] of [
	[deliveryRemotePreflight, deliveryRemotePreflightFile],
	[privacyErasureRemote, privacyErasureRemoteFile],
]) {
	checkIncludesAll(
		remotePreflight,
		[
			"classifyCloudflareEdgeMitigation",
			"!allowEdgeMitigation || response.status !== 403",
			"allowEdgeMitigation",
			"edge-mitigated/unverified",
			"readiness was not verified",
			"edgeMitigatedEndpoints.length > 0",
		],
		file,
		"stateful Worker probes may continue past only identifiable edge mitigation after successful control-plane checks",
	);
}
checkIncludesAll(
	deliveryRemotePreflight,
	[
		"Remote Delivery Worker has no active 100% deployment",
		"DeliveryProviderConfig",
		'handler.handlers?.includes("class")',
		'migration_tag !== "v1"',
		"Custom Domain ${hostname} is missing",
		"remoteDomain.environment !== undefined",
		'remoteDomain.environment !== "production"',
		"const domainVerified = await checkZoneAndRoute()",
		"checkPublicEndpoints(failures.length === 0 && domainVerified)",
	],
	deliveryRemotePreflightFile,
	"Delivery edge mitigation requires an active version, SQLite Durable Object contract, and exact live domain",
);
checkIncludes(
	privacyErasureRemote,
	"checkPublicEndpoints(failures.length === 0)",
	privacyErasureRemoteFile,
	"Privacy Erasure edge mitigation requires failure-free Worker, binding, and domain checks",
);
checkIncludesAll(
	privacyErasureRemote,
	["remote.environment !== undefined", 'remote.environment !== "production"'],
	privacyErasureRemoteFile,
	"Privacy Erasure edge mitigation requires the exact production Custom Domain environment",
);
check(
	deliveryPackage.scripts?.["acceptance:providers"] ===
		"node ./scripts/run-provider-acceptance.mjs",
	`${rel(deliveryPackageFile)} must expose the opt-in provider acceptance script`,
);
check(
	deliveryWrangler.routes?.some(
		(route) =>
			route.pattern === "cinaauth-delivery.cinagroup.com" &&
			route.custom_domain === true,
	),
	`${rel(deliveryWranglerFile)} must bind the delivery hostname as a Custom Domain`,
);
checkIncludesAll(
	deliveryAcceptance,
	[
		'process.argv.includes("--send")',
		"CINAAUTH_ACCEPTANCE_EMAIL",
		"CINAAUTH_ACCEPTANCE_PHONE",
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
		'kind: "email-otp"',
		'kind: "magic-link"',
		'kind: "password-reset"',
		'kind: "phone-otp"',
		'kind: "phone-reset-otp"',
		"X-CinaAuth-Delivery-Signature",
		"replay-kv: duplicate suppressed",
	],
	deliveryAcceptanceFile,
	"provider acceptance must be explicit, signed, cover every delivery type, and verify replay protection",
);
check(
	!deliveryAcceptance.includes("console.log(email)") &&
		!deliveryAcceptance.includes("console.log(phoneNumber)") &&
		!deliveryAcceptance.includes("console.log(secret)"),
	`${rel(deliveryAcceptanceFile)} must not print acceptance targets or secret values`,
);

checkIncludesAll(
	productionLifecycleAcceptance,
	[
		'argv.includes("--run")',
		"CINAAUTH_ACCEPTANCE_ADMIN_COOKIE",
		"@acceptance.invalid",
		'path: "/api/auth/admin/create-user"',
		'path: "/api/auth/admin/impersonate-user"',
		'path: "/api/auth/admin/remove-user"',
		'path: "/api/auth/get-session"',
		"finally",
		"AggregateError",
		"session-revocation-validated",
		"cleaned: true",
	],
	productionLifecycleAcceptanceFile,
	"production lifecycle acceptance must be explicit, synthetic, session-backed, and fail closed on cleanup",
);
check(
	!productionLifecycleAcceptance.includes("log(adminCookie)") &&
		!productionLifecycleAcceptance.includes("log(impersonatedCookie)") &&
		!productionLifecycleAcceptance.includes("log(email)") &&
		!productionLifecycleAcceptance.includes("log(userId)"),
	`${rel(productionLifecycleAcceptanceFile)} must not print cookies or synthetic identity values`,
);

checkIncludesAll(
	configureHyperdrive,
	[
		"CINAAUTH_HYPERDRIVE_ID",
		"00000000000000000000000000000000",
		"writeFileSync",
		"Configured the HYPERDRIVE binding ID",
	],
	configureHyperdriveFile,
	"Hyperdrive configuration must require a concrete ID without database credentials",
);

check(
	packageJson.scripts?.["configure:turnstile"] ===
		"node ./scripts/configure-turnstile.mjs",
	`${rel(packageFile)} must expose the idempotent Turnstile configuration script`,
);
checkIncludesAll(
	configureTurnstile,
	[
		"CinaAuth Production",
		"auth.cinaseek.ai",
		"accounts.cinaseek.ai",
		"demo-auth.cinagroup.com",
		"admin.cinaseek.ai",
		'widget.mode !== "managed"',
		'widget.clearance_level !== "no_clearance"',
		"CLOUDFLARE_API_TOKEN",
		"CLOUDFLARE_ACCOUNT_ID",
		"CLOUDFLARE_TURNSTILE_SECRET_KEY",
		"CLOUDFLARE_TURNSTILE_SITE_KEY",
		"spawnSync",
		'stdio: ["pipe", "inherit", "inherit"]',
		"secretValuesPrinted: false",
	],
	configureTurnstileFile,
	"Turnstile automation must be idempotent, domain-bound, and provision secrets through stdin",
);
check(
	!configureTurnstile.includes("console.log(widget.secret)") &&
		!configureTurnstile.includes("process.argv.push"),
	`${rel(configureTurnstileFile)} must not print or pass Turnstile secrets in arguments`,
);

checkIncludesAll(
	deploymentTargetParser,
	[
		'const VALID_DEPLOYMENT_TARGETS = new Set(["production", "siwe-staging"])',
		'"--env"',
		'"--config"',
		'"--cwd"',
		'"--name"',
		'"--env-file"',
		"getTargetOccurrenceCount(args) !== 1",
		'env.CLOUDFLARE_ENV !== undefined && env.CLOUDFLARE_ENV !== ""',
		'deploymentTarget === "siwe-staging" ? ["--env", "staging"] : []',
		"childEnv: omitCloudflareEnvironment(env)",
	],
	deploymentTargetParserFile,
	"Cloudflare writes must select exactly one logical target, reject ambient and raw Wrangler target overrides, and keep production on the top-level configuration",
);

for (const [consumer, file, stagingMessage] of [
	[
		provisionSecrets,
		provisionSecretsFile,
		"SIWE staging secret provisioning is disabled",
	],
	[
		deliveryProvision,
		deliveryProvisionFile,
		"siwe-staging Delivery secret provisioning is not available",
	],
	[
		privacyErasureProvision,
		privacyErasureProvisionFile,
		"siwe-staging Privacy Erasure secret provisioning is not available",
	],
]) {
	checkIncludesAll(
		consumer,
		[
			"cloudflare-deployment-target.mjs",
			"parseCloudflareDeploymentTarget",
			"target.passthroughArgs",
			stagingMessage,
			"...target.wranglerArgs",
			"env: target.childEnv",
		],
		file,
		"secret provisioning must use the shared explicit deployment-target guard and fail closed before staging side effects",
	);
}

checkIncludesAll(
	accountDeploy,
	[
		"cloudflare-deployment-target.mjs",
		"parseCloudflareDeploymentTarget",
		"target.passthroughArgs.length !== 0",
		'target.deploymentTarget === "siwe-staging"',
		"target.childEnv.npm_execpath",
		"const childEnv = { ...target.childEnv }",
	],
	accountDeployFile,
	"Account Portal deployment must use the shared target guard before resolving pnpm or executing OpenNext/Wrangler",
);
check(
	!accountDeploy.includes("CLOUDFLARE_ENV") &&
		!accountDeploy.includes('"--env"') &&
		!accountDeploy.includes("'--env'"),
	`${rel(accountDeployFile)} must not duplicate or bypass shared Wrangler environment selection`,
);

const expectedDeploymentContractTest =
	"node --test ./scripts/cloudflare-deployment-target.test.mjs ./scripts/check-cloudflare-preserved-secrets.test.mjs ./scripts/cloudflare-edge-mitigation.test.mjs ./.github/workflows/deployment-workflows.test.mjs ./workers/auth-api/scripts/provision-secrets.test.mjs ./workers/delivery/scripts/provision-secrets.test.mjs ./workers/privacy-erasure/scripts/provision-secrets.test.mjs ./apps/account-portal/deploy-cf.test.mjs";
check(
	repoPackage.scripts?.["test:cloudflare-deployment-contracts"] ===
		expectedDeploymentContractTest,
	`${rel(repoPackageFile)} must expose the complete Cloudflare deployment-target contract suite`,
);
for (const [workerPackage, file] of [
	[deliveryPackage, deliveryPackageFile],
	[privacyErasurePackage, privacyErasurePackageFile],
]) {
	check(
		workerPackage.scripts?.["test:provision-secrets"] ===
			"node --test ./scripts/provision-secrets.test.mjs" &&
			workerPackage.scripts?.check?.includes("pnpm run test:provision-secrets"),
		`${rel(file)} must expose and run its deployment-target secret provisioner tests`,
	);
}
check(
	accountPackage.scripts?.["deploy:cf"] === "node deploy-cf.mjs" &&
		accountPackage.scripts?.["test:deploy-cf"] ===
			"node --test ./deploy-cf.test.mjs",
	`${rel(accountPackageFile)} must expose the guarded Account deploy command and its tests`,
);

const productionProvisionCommands = [
	...workflow.matchAll(/^\s*run:\s+(pnpm run provision:secrets[^\r\n]*)/gm),
].map((match) => match[1]);
check(
	productionProvisionCommands.length === 1 &&
		productionProvisionCommands.every(
			(command) =>
				/--deployment-target=production(?:\s|$)/.test(command) &&
				!command.includes("-- --deployment-target") &&
				!/(?:--env(?:\s|=)|CLOUDFLARE_ENV)/.test(command),
		),
	`${rel(workflowFile)} must select the top-level production target for the Auth secret provisioner`,
);
checkIncludesAll(
	workflow,
	[
		"scripts/cloudflare-deployment-target.test.mjs",
		"scripts/check-cloudflare-preserved-secrets.test.mjs",
		"scripts/cloudflare-edge-mitigation.test.mjs",
		".github/workflows/deployment-workflows.test.mjs",
		"workers/auth-api/scripts/provision-secrets.test.mjs",
		"workers/delivery/scripts/provision-secrets.test.mjs",
		"workers/privacy-erasure/scripts/provision-secrets.test.mjs",
		"apps/account-portal/deploy-cf.test.mjs",
	],
	workflowFile,
	"production authorization must be preceded by the complete local deployment-target contract suite",
);
checkIncludes(
	ciWorkflow,
	"run: pnpm run test:cloudflare-deployment-contracts",
	ciWorkflowFile,
	"pull requests must exercise all Cloudflare deployment-target contracts",
);
checkIncludes(
	localDeploymentScript,
	"pnpm --dir apps/account-portal run deploy:cf --deployment-target=production",
	localDeploymentScriptFile,
	"the local production orchestrator must select the guarded top-level Account target",
);

checkIncludesAll(
	preservedSecretCheck,
	[
		"PRESERVED_SECRET_INVENTORIES",
		'workerName: "cinaauth-api"',
		'workerName: "cinaauth-privacy-erasure"',
		"CINAAUTH_SECRET",
		"CINAAUTH_PRIVACY_EXPORT_KEY",
		"CINAAUTH_ERASURE_STORAGE_SECRET",
		"/workers/scripts/",
		' method: "GET"'.trim(),
		"CLOUDFLARE_API_TOKEN",
		"CLOUDFLARE_ACCOUNT_ID",
	],
	preservedSecretCheckFile,
	"the pre-write gate must verify only preserved Worker secret names through Cloudflare's read-only inventory API",
);
check(
	!preservedSecretCheck.includes('method: "POST"') &&
		!preservedSecretCheck.includes('method: "PUT"') &&
		!preservedSecretCheck.includes('method: "DELETE"') &&
		!preservedSecretCheck.includes("secret put") &&
		!preservedSecretCheck.includes("secret bulk") &&
		!preservedSecretCheck.includes("response.text"),
	`${rel(preservedSecretCheckFile)} must remain a metadata-only read without a secret-value or write path`,
);

checkIncludesAll(
	provisionSecrets,
	[
		"CINAAUTH_MIGRATION_TOKEN",
		"CINAAUTH_DELIVERY_WEBHOOK_URL",
		"CINAAUTH_ERASURE_WEBHOOK_URL",
		"CANONICAL_ERASURE_WEBHOOK_URL",
		"https://cinaauth-erasure.cinagroup.com/cinaauth/privacy/erase",
		"FIXED_SECRETS[name] ?? env[name]",
		"CLOUDFLARE_TURNSTILE_SITE_KEY",
		"CLOUDFLARE_TURNSTILE_SECRET_KEY",
		"CINAAUTH_ENTITLEMENT_CONFIG",
		"must be configured together",
		'fileURLToPath(import.meta.resolve("wrangler"))',
		"process.execPath",
		"Object.fromEntries",
		"JSON.stringify(values)",
		"wrangler",
		"secret",
		"bulk",
		"spawnSyncImpl",
		"stdio",
		"pipe",
	],
	provisionSecretsFile,
	"Auth secret provisioning must write mutable required and configured optional values through one Wrangler bulk stdin call",
);
check(
	!provisionSecrets.includes("CINAAUTH_SECRET") &&
		!provisionSecrets.includes("CINAAUTH_PRIVACY_EXPORT_KEY") &&
		!provisionSecrets.includes("process.argv.push") &&
		!provisionSecrets.includes("echo ") &&
		!provisionSecrets.includes("fetch(") &&
		!provisionSecrets.includes('"put"') &&
		!provisionSecrets.includes("writeFile") &&
		!provisionSecrets.includes("mkdtemp") &&
		!provisionSecrets.includes("CINAAUTH_DELIVERY_WEBHOOK_SECRET") &&
		!provisionSecrets.includes("CINAAUTH_ERASURE_WEBHOOK_SECRET") &&
		!provisionSecrets.includes("CINAADMIN_OIDC_CLIENT_SECRET") &&
		!provisionSecrets.includes("CINAADMIN_OIDC_BRIDGE_SECRET"),
	`${rel(provisionSecretsFile)} must not select preserved stateful values, pass values in arguments, write temporary files, probe child readiness, or provision active V2 shared secrets as V1 Worker secrets`,
);
check(
	!provisionSecrets.includes(
		'assertHttpsUrl(env, "CINAAUTH_ERASURE_WEBHOOK_URL")',
	),
	`${rel(provisionSecretsFile)} must pin the erasure webhook instead of accepting an operator URL override`,
);
check(
	workflow.includes("CLOUDFLARE_TURNSTILE_SITE_KEY") &&
		workflow.includes("CLOUDFLARE_TURNSTILE_SECRET_KEY") &&
		workflow.includes("run: pnpm run provision:secrets") &&
		!workflow.includes("node - <<") &&
		!workflow.includes("wrangler secret bulk") &&
		!workflow.includes("npx wrangler"),
	`${rel(workflowFile)} must delegate Auth bulk provisioning to the tested provisioner without duplicating inline selection logic`,
);

checkIncludesAll(
	deploymentDoc,
	[
		"configure:delivery-queues",
		"24-hour retention",
		"CINAAUTH_SECRET",
		"CINAAUTH_MIGRATION_TOKEN",
		"CINAAUTH_DELIVERY_WEBHOOK_URL",
		"CINAAUTH_ERASURE_WEBHOOK_URL",
		"Active Secrets Store V2 bindings",
		"binding-first",
		"CINAAUTH_DELIVERY_CONFIG_KEK_STORE",
		"CINAAUTH_ERASURE_CONFIG_KEK_STORE",
		"Two-phase bootstrap and post-deploy control plane",
		"CINAAUTH_ERASURE_SERVICE",
		"pnpm --dir workers/auth-api run check:production",
		"pnpm --dir workers/auth-api run check:cloudflare",
		"CINAAUTH_HYPERDRIVE_ID",
		"configure:hyperdrive",
		"configure:turnstile",
		"Turnstile Sites Write",
		"pnpm --dir workers/auth-api run provision:secrets",
		"auth.cinaseek.ai",
		"env.HYPERDRIVE.connectionString",
		"RateLimitDurableObject",
		"CINAAUTH_REQUIRE_ALL_PLUGIN_INPUTS=1",
		"CLOUDFLARE_TURNSTILE_SITE_KEY",
		"CLOUDFLARE_TURNSTILE_SECRET_KEY",
		"`CINAAUTH_SIWE_ENABLED=true` is the planned Stage Two activation configuration.",
		"CINAAUTH_SIWE_ENABLED=false",
		"CINAAUTH_SIWE_ALLOWED_CHAIN_IDS",
		"CINAAUTH_SIWE_RP_DOMAIN=accounts.cinaseek.ai",
		"CINAAUTH_SIWE_RP_URI=https://accounts.cinaseek.ai",
		"CINAAUTH_SIWE_ALLOW_LEGACY=false",
		"CINAAUTH_SIWE_AUTO_SIGNUP=true",
		"Production enables account creation for an unknown",
		"Account Portal preflight",
		"planned `CINAAUTH_SIWE_ENABLED`",
		"32-hex-character `REOWN_PROJECT_ID`",
		"A disabled rollout does not require a Project ID.",
		"repeats the live capability parity check",
		"Email authentication and runtime cutover",
		"reset endpoints remain disabled",
		"3 requests per 60 seconds",
		"10 requests per 24 hours",
		"`CINAAUTH_SECRET`-keyed HMAC",
		"raw email address",
		"fails closed",
		"verified sender",
		"not GitHub Secrets",
		"methods.emailOtp=true",
		"CINAAUTH_EMAIL_AUTH_GATE=portal-compatible",
		"CINAAUTH_EMAIL_AUTH_GATE=runtime-configurable",
		"email_password_login_enabled",
		"google_one_tap_enabled",
		"Capability version 5",
		"operator change can make",
		"ownership-proving OTP",
		"unproven credential",
		"revokes its old sessions",
		"independent TOTP",
		"backup-code challenge",
		"pre-cutover version",
		"two separate production runs",
		"same-run enable attempt fails closed",
		"exact Project ID",
		"/api/migrate",
		"/api/migrate/d1",
		"/api/migrate/scim-provider-ownership",
		"requiredInvariants",
		"database.invariants",
		"delete-anonymous-user",
		"60 attempts per",
		"multi-row",
		"already_migrated",
		"plaintext `scimToken` is returned",
		"configured social or Generic",
		"before an ownership update, token rotation, or migration audit",
		"maintenance",
		"cinaauth_cutover_history",
		"/api/ready",
		"D1 Time Travel protects only the retained rollback source",
		"VERSION_METADATA",
		"X-CinaAuth-Delivery-Signature",
	],
	deploymentDocFile,
	"Worker deployment doc must cover production setup and verification",
);

checkIncludesAll(
	chineseDeploymentDoc,
	[
		"auth.cinaseek.ai",
		"CINAAUTH_HYPERDRIVE_ID",
		"Hyperdrive",
		"PostgreSQL",
		"RATE_LIMITER",
		"CINAAUTH_MIGRATION_TOKEN",
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
		"/api/migrate",
		"/api/migrate/d1",
		"CINAAUTH_D1_MIGRATION_TOKEN",
		"CINAAUTH_CUTOVER_STATE",
		"LEGACY_D1",
		"/api/ready",
		"pnpm --dir workers/auth-api run check:production",
		"CINAAUTH_REQUIRE_ALL_PLUGIN_INPUTS=1",
		"VERSION_METADATA",
		"X-CinaAuth-Delivery-Signature",
		"accounts.cinaseek.ai/api/auth/get-session",
	],
	chineseDeploymentDocFile,
	"Cloudflare deployment guide must document the same production gates",
);
checkIncludesAll(
	functionalDesign,
	[
		"个人 API Key 的生产约束",
		"`cina_sk_` 品牌前缀",
		"完整密钥只在创建响应和一次性确认弹窗中出现",
		"绕过 Cookie 缓存的权威数据库会话",
		"登录时间不超过 15 分钟",
		"`POST /siwe/link-wallet`",
		"`GET /siwe/list-wallets`",
		"`POST /siwe/set-primary-wallet`",
		"`POST /siwe/unlink-wallet`",
		"现有 `/siwe/verify` 是登录端点",
		"`/dashboard/privacy`",
		"机器可读 JSON 导出",
		"不静默截断",
		"`privacy.export` 审计 action",
	],
	functionalDesignFile,
	"the functional design must document the production API key, wallet, and privacy security contracts",
);

checkIncludesAll(
	gitignore,
	[
		".dev.vars",
		".dev.vars.*",
		"!.dev.vars.example",
		".env.*",
		"!.env.example",
		"cinaauth-db-*.sql",
	],
	gitignoreFile,
	"local Wrangler and environment secrets must be ignored while examples stay tracked",
);
checkIncludesAll(
	siweStagingDoc,
	[
		"CINAAUTH_REQUIRE_AUTH_WORKER_BINDING",
		"CINAAUTH_ACCOUNT_ORIGIN",
		"CINAAUTH_ADMIN_ORIGIN",
		"CINAAUTH_PASSKEY_RP_ID",
		"--env staging",
		"AUTH_WORKER -> cinaauth-api-staging",
		"NEXT_PUBLIC_REOWN_PROJECT_ID",
		"CINAAUTH_SIWE_AUTO_SIGNUP=false",
		"synthetic data",
		"check:siwe-staging-foundation",
		"test:siwe-staging-inventory",
		"SIWE_STAGING_REOWN_PROJECT_ID",
		"There is no checked-in staging inventory instance",
	],
	siweStagingDocFile,
	"the SIWE staging runbook must preserve resource isolation, fail-closed transport, and real-wallet acceptance prerequisites",
);
checkIncludesAll(
	deploymentDoc,
	["../../docs/SIWE_STAGING.md", "CINAAUTH_ACCOUNT_ORIGIN"],
	deploymentDocFile,
	"the production runbook must link the isolated staging contract and document its explicit origin profile",
);
check(existsSync(devVarsExampleFile), ".dev.vars.example must exist");
checkIncludesAll(
	devVarsExample,
	[
		"CINAAUTH_SECRET=",
		"CINAAUTH_MIGRATION_TOKEN=",
		"CINAAUTH_DELIVERY_WEBHOOK_URL=",
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET=",
	],
	devVarsExampleFile,
	"local development must document required runtime secrets",
);
check(
	!/cfut_[A-Za-z0-9_-]+/.test(devVarsExample),
	".dev.vars.example must not contain Cloudflare API tokens",
);

if (failures.length > 0) {
	console.error("Production config verification failed:");
	for (const failure of failures) {
		console.error(`- ${failure}`);
	}
	process.exit(1);
}

console.log(`Production config verification passed (${passed} checks).`);

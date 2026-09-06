const SCOPE_TO_DOMAIN = new Map(
	Object.entries({
		// core
		core: "core",
		api: "core",
		client: "core",
		cookies: "core",
		crypto: "core",
		account: "core",
		session: "core",
		instrumentation: "core",
		"last-login-method": "core",
		"redis-storage": "core",

		// database
		db: "database",
		adapters: "database",
		"drizzle-adapter": "database",
		"prisma-adapter": "database",
		"kysely-adapter": "database",
		"mongo-adapter": "database",
		"memory-adapter": "database",

		// oauth
		"oauth-proxy": "oauth",
		"one-tap": "oauth",
		"generic-oauth": "oauth",
		"social-provider": "oauth",

		// credentials
		"magic-link": "credentials",
		"email-otp": "credentials",
		"phone-number": "credentials",
		phone: "credentials",
		username: "credentials",
		anonymous: "credentials",
		siwe: "credentials",
		passkey: "credentials",

		// identity
		"oauth-provider": "identity",
		"oidc-provider": "identity",
		mcp: "identity",
		"device-authorization": "identity",
		cimd: "identity",

		// organization
		organization: "organization",
		admin: "organization",
		access: "organization",

		// security
		"two-factor": "security",
		"2fa": "security",
		captcha: "security",
		haveibeenpwned: "security",
		"rate-limiter": "security",

		// enterprise
		sso: "enterprise",
		scim: "enterprise",

		// payments
		stripe: "payments",
		"api-key": "payments",

		// platform
		expo: "platform",
		electron: "platform",

		// devtools
		cli: "devtools",
		telemetry: "devtools",
		i18n: "devtools",
		"test-utils": "devtools",
		"open-api": "devtools",

		// devops (filtered from release notes)
		build: "devops",
		ci: "devops",
		deps: "devops",
		"deps-dev": "devops",
		knip: "devops",

		// docs (filtered from release notes)
		docs: "docs",
		blog: "docs",
		landing: "docs",
	} as const),
);

const PATH_TO_DOMAIN = [
	["packages/oauth-provider/", "identity"],
	["packages/cinaauth/src/plugins/oidc-provider/", "identity"],
	["packages/cinaauth/src/plugins/mcp/", "identity"],
	["packages/cinaauth/src/plugins/device-authorization/", "identity"],
	["packages/cimd/", "identity"],
	["packages/cinaauth/src/plugins/magic-link/", "credentials"],
	["packages/cinaauth/src/plugins/email-otp/", "credentials"],
	["packages/cinaauth/src/plugins/phone-number/", "credentials"],
	["packages/cinaauth/src/plugins/username/", "credentials"],
	["packages/cinaauth/src/plugins/anonymous/", "credentials"],
	["packages/cinaauth/src/plugins/siwe/", "credentials"],
	["packages/passkey/", "credentials"],
	["packages/cinaauth/src/plugins/two-factor/", "security"],
	["packages/cinaauth/src/api/rate-limiter/", "security"],
	["packages/cinaauth/src/plugins/captcha/", "security"],
	["packages/cinaauth/src/plugins/haveibeenpwned/", "security"],
	["packages/cinaauth/src/plugins/organization/", "organization"],
	["packages/cinaauth/src/plugins/admin/", "organization"],
	["packages/cinaauth/src/plugins/access/", "organization"],
	["packages/cinaauth/src/plugins/generic-oauth/", "oauth"],
	["packages/cinaauth/src/plugins/oauth-proxy/", "oauth"],
	["packages/cinaauth/src/plugins/one-tap/", "oauth"],
	["packages/cinaauth/src/oauth2/", "oauth"],
	["packages/core/src/social-providers/", "oauth"],
	["packages/core/src/oauth2/", "oauth"],
	["packages/sso/", "enterprise"],
	["packages/scim/", "enterprise"],
	["packages/stripe/", "payments"],
	["packages/api-key/", "payments"],
	["packages/cinaauth/src/db/", "database"],
	["packages/cinaauth/src/adapters/", "database"],
	["packages/drizzle-adapter/", "database"],
	["packages/prisma-adapter/", "database"],
	["packages/mongo-adapter/", "database"],
	["packages/kysely-adapter/", "database"],
	["packages/memory-adapter/", "database"],
	["packages/expo/", "platform"],
	["packages/electron/", "platform"],
	["packages/cinaauth/src/integrations/", "platform"],
	["packages/cli/", "devtools"],
	["packages/cinaauth/src/plugins/open-api/", "devtools"],
	["packages/telemetry/", "devtools"],
	["packages/i18n/", "devtools"],
	["packages/test-utils/", "devtools"],
	// Session-related plugins → core
	["packages/cinaauth/src/plugins/jwt/", "core"],
	["packages/cinaauth/src/plugins/bearer/", "core"],
	["packages/cinaauth/src/plugins/multi-session/", "core"],
	["packages/cinaauth/src/plugins/custom-session/", "core"],
	["packages/redis-storage/", "core"],
	// Catch-all for cinaauth and core packages
	["packages/cinaauth/", "core"],
	["packages/core/", "core"],
	// Non-user-facing
	["docs/", "docs"],
	["demo/", "docs"],
	[".github/", "devops"],
	["e2e/", "devops"],
] as const;

function classifyDomain(filePath: string): string | undefined {
	for (const [prefix, domain] of PATH_TO_DOMAIN) {
		if (filePath.startsWith(prefix)) return domain;
	}
	return undefined;
}

export function resolveDomain(
	scope: string | undefined,
	changedFiles: string[],
): string {
	if (scope) {
		const domain = SCOPE_TO_DOMAIN.get(scope);
		if (domain) return domain;
	}

	const counts: Record<string, number> = {};
	for (const file of changedFiles) {
		const domain = classifyDomain(file);
		if (domain) {
			counts[domain] = (counts[domain] ?? 0) + 1;
		}
	}

	const domains = Object.keys(counts);
	if (domains.length === 0) return "devops";
	if (domains.length >= 3) return "core";

	return domains.sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0))[0]!;
}

export function mapTypeToBump(
	type: string,
	breaking: boolean,
): "patch" | "minor" | "major" | "skip" {
	if (breaking) return "minor";
	switch (type) {
		case "fix":
		case "perf":
		case "refactor":
			return "patch";
		case "feat":
			return "minor";
		case "chore":
		case "docs":
		case "ci":
		case "test":
		case "style":
		case "build":
			return "skip";
		default:
			return "patch";
	}
}

export const DOMAIN_ORDER = [
	"core",
	"database",
	"oauth",
	"credentials",
	"identity",
	"organization",
	"security",
	"enterprise",
	"payments",
	"platform",
	"devtools",
] as const;

export const FILTERED_DOMAINS = new Set(["docs", "devops"]);

export function isMaintenanceBranch(branch: string): boolean {
	return /^v[0-9]+\.[0-9]+\.x$/u.test(branch);
}

const SCOPE_TO_PACKAGE = new Map(
	Object.entries({
		cimd: "@cinaauth/cimd",
		sso: "@cinaauth/sso",
		scim: "@cinaauth/scim",
		passkey: "@cinaauth/passkey",
		"oauth-provider": "@cinaauth/oauth-provider",
		stripe: "@cinaauth/stripe",
		"api-key": "@cinaauth/api-key",
		expo: "@cinaauth/expo",
		electron: "@cinaauth/electron",
		i18n: "@cinaauth/i18n",
		"test-utils": "@cinaauth/test-utils",
		"drizzle-adapter": "@cinaauth/drizzle-adapter",
		"prisma-adapter": "@cinaauth/prisma-adapter",
		"kysely-adapter": "@cinaauth/kysely-adapter",
		"mongo-adapter": "@cinaauth/mongo-adapter",
		"memory-adapter": "@cinaauth/memory-adapter",
		"redis-storage": "@cinaauth/redis-storage",
		cli: "auth",
	} as const),
);

/**
 * Maps file path prefixes to npm package names.
 * Order matters: more specific paths must come before catch-alls.
 */
const PATH_TO_PACKAGE = [
	["packages/cimd/", "@cinaauth/cimd"],
	["packages/sso/", "@cinaauth/sso"],
	["packages/scim/", "@cinaauth/scim"],
	["packages/passkey/", "@cinaauth/passkey"],
	["packages/oauth-provider/", "@cinaauth/oauth-provider"],
	["packages/stripe/", "@cinaauth/stripe"],
	["packages/api-key/", "@cinaauth/api-key"],
	["packages/expo/", "@cinaauth/expo"],
	["packages/electron/", "@cinaauth/electron"],
	["packages/i18n/", "@cinaauth/i18n"],
	["packages/redis-storage/", "@cinaauth/redis-storage"],
	["packages/test-utils/", "@cinaauth/test-utils"],
	["packages/telemetry/", "@cinaauth/telemetry"],
	["packages/drizzle-adapter/", "@cinaauth/drizzle-adapter"],
	["packages/prisma-adapter/", "@cinaauth/prisma-adapter"],
	["packages/kysely-adapter/", "@cinaauth/kysely-adapter"],
	["packages/mongo-adapter/", "@cinaauth/mongo-adapter"],
	["packages/memory-adapter/", "@cinaauth/memory-adapter"],
	// Catch-all: everything in cinaauth or core maps to the main package
	["packages/cinaauth/", "cinaauth"],
	["packages/core/", "cinaauth"],
	["packages/cli/", "auth"],
] as const;

export function resolvePackage(
	scope: string | undefined,
	changedFiles: string[],
): string {
	if (scope) {
		const pkg = SCOPE_TO_PACKAGE.get(scope);
		if (pkg) return pkg;
	}

	const counts: Record<string, number> = {};
	for (const file of changedFiles) {
		for (const [prefix, pkg] of PATH_TO_PACKAGE) {
			if (file.startsWith(prefix)) {
				counts[pkg] = (counts[pkg] ?? 0) + 1;
				break;
			}
		}
	}

	const packages = Object.keys(counts);
	if (packages.length === 0) return "cinaauth";

	// If files span multiple external packages, return the one with the most hits.
	// If all files are in cinaauth, return cinaauth.
	return packages.sort((a, b) => {
		// Prefer non-cinaauth packages (they're more specific)
		const aIsCore = a === "cinaauth" ? 1 : 0;
		const bIsCore = b === "cinaauth" ? 1 : 0;
		if (aIsCore !== bIsCore) return aIsCore - bIsCore;
		return (counts[b] ?? 0) - (counts[a] ?? 0);
	})[0]!;
}

export function classifyChangeType(
	type: string,
	breaking: boolean,
): "breaking" | "feat" | "fix" {
	if (breaking) return "breaking";
	if (type === "feat") return "feat";
	return "fix";
}

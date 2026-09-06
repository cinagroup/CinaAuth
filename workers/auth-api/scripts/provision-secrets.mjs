import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseCloudflareDeploymentTarget } from "../../../scripts/cloudflare-deployment-target.mjs";

const REQUIRED_SECRETS = [
	"CINAAUTH_MIGRATION_TOKEN",
	"CINAAUTH_DELIVERY_WEBHOOK_URL",
];

export const CANONICAL_ERASURE_WEBHOOK_URL =
	"https://cinaauth-erasure.cinagroup.com/cinaauth/privacy/erase";
const FIXED_SECRETS = {
	CINAAUTH_ERASURE_WEBHOOK_URL: CANONICAL_ERASURE_WEBHOOK_URL,
};

const OPTIONAL_SECRETS = [
	"OAUTH_PAIRWISE_SECRET",
	"GENERIC_OAUTH_CONFIG",
	"GOOGLE_CLIENT_ID",
	"GOOGLE_CLIENT_SECRET",
	"GITHUB_CLIENT_ID",
	"GITHUB_CLIENT_SECRET",
	"CLOUDFLARE_TURNSTILE_SITE_KEY",
	"CLOUDFLARE_TURNSTILE_SECRET_KEY",
	"STRIPE_SECRET_KEY",
	"STRIPE_WEBHOOK_SECRET",
	"STRIPE_DEFAULT_PRICE_ID",
	"STRIPE_DEFAULT_PLAN_NAME",
	"CINAAUTH_ENTITLEMENT_CONFIG",
	"CINAUTH_ADMIN_SERVICE_KEY",
];

const STRONG_SECRETS = new Set(["CINAAUTH_MIGRATION_TOKEN"]);

const hasValue = (env, name) => {
	const value = env[name];
	return typeof value === "string" && value.length > 0;
};

const assertStrong = (env, name) => {
	if (!hasValue(env, name)) {
		throw new Error(`Missing required environment variable ${name}`);
	}
	if (STRONG_SECRETS.has(name) && env[name].length < 32) {
		throw new Error(`${name} must be at least 32 characters`);
	}
};

const assertHttpsUrl = (env, name) => {
	try {
		const url = new URL(env[name]);
		if (url.protocol !== "https:") {
			throw new Error(`${name} must be an HTTPS URL`);
		}
	} catch (error) {
		if (
			error instanceof Error &&
			error.message.endsWith("must be an HTTPS URL")
		) {
			throw error;
		}
		throw new Error(`${name} must be a valid HTTPS URL`);
	}
};

const assertPaired = (env, first, second) => {
	if (hasValue(env, first) !== hasValue(env, second)) {
		throw new Error(`${first} and ${second} must be configured together`);
	}
};

const assertConfiguredTogether = (env, names) => {
	const configured = names.filter((name) => hasValue(env, name));
	if (configured.length !== 0 && configured.length !== names.length) {
		throw new Error(`${names.join(", ")} must be configured together`);
	}
};

const getSelectedSecretNames = (env) => {
	for (const name of REQUIRED_SECRETS) {
		assertStrong(env, name);
	}
	assertHttpsUrl(env, "CINAAUTH_DELIVERY_WEBHOOK_URL");
	assertPaired(
		env,
		"CLOUDFLARE_TURNSTILE_SITE_KEY",
		"CLOUDFLARE_TURNSTILE_SECRET_KEY",
	);
	if (
		hasValue(env, "GOOGLE_CLIENT_SECRET") &&
		!hasValue(env, "GOOGLE_CLIENT_ID")
	) {
		throw new Error("GOOGLE_CLIENT_SECRET requires GOOGLE_CLIENT_ID");
	}
	assertPaired(env, "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET");
	assertConfiguredTogether(env, [
		"STRIPE_SECRET_KEY",
		"STRIPE_WEBHOOK_SECRET",
		"STRIPE_DEFAULT_PRICE_ID",
		"CINAAUTH_ENTITLEMENT_CONFIG",
	]);
	return [
		...REQUIRED_SECRETS,
		...Object.keys(FIXED_SECRETS),
		...OPTIONAL_SECRETS.filter((name) => hasValue(env, name)),
	];
};

const getDryRun = (args) => {
	let dryRun = false;
	for (const arg of args) {
		if (arg !== "--dry-run") {
			throw new Error("Only --dry-run is allowed after --deployment-target");
		}
		if (dryRun) {
			throw new Error("--dry-run may be provided at most once");
		}
		dryRun = true;
	}
	return dryRun;
};

export const runProvisionSecrets = (options = {}) => {
	const target = parseCloudflareDeploymentTarget({
		args: options.args ?? process.argv.slice(2),
		env: options.env ?? process.env,
	});
	const dryRun = getDryRun(target.passthroughArgs);
	if (target.deploymentTarget === "siwe-staging") {
		throw new Error(
			"SIWE staging secret provisioning is disabled until the isolated staging inventory and Wrangler environment are complete",
		);
	}

	const env = options.env ?? process.env;
	const names = getSelectedSecretNames(env);
	if (dryRun) {
		const log = options.log ?? console.log;
		for (const name of names) log(`Would provision ${name}`);
		log(
			"Auth Worker mutable and configured optional secret provisioning dry run complete. Preserved stateful secrets are not selected.",
		);
		return;
	}

	const log = options.log ?? console.log;
	const spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
	const wranglerCli =
		options.wranglerCli ?? fileURLToPath(import.meta.resolve("wrangler"));
	const values = Object.fromEntries(
		names.map((name) => [name, FIXED_SECRETS[name] ?? env[name]]),
	);
	const result = spawnSyncImpl(
		process.execPath,
		// Stage a version so rollback/gradual deployments do not trigger error
		// 10215 or activate application code during secret provisioning.
		[wranglerCli, "versions", "secret", "bulk", ...target.wranglerArgs],
		{
			input: `${JSON.stringify(values)}\n`,
			stdio: ["pipe", "inherit", "inherit"],
			env: target.childEnv,
		},
	);
	if (result.error) {
		throw new Error("Failed to start Wrangler");
	}
	if (result.status !== 0) {
		const error = new Error("Wrangler versions secret bulk failed");
		error.exitCode = result.status ?? 1;
		throw error;
	}
	log(
		`Staged ${names.length} mutable or configured optional Auth Worker secrets in one versioned bulk operation. Preserved stateful secrets were not selected.`,
	);
};

const isMain =
	typeof process.argv[1] === "string" &&
	pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (isMain) {
	try {
		runProvisionSecrets();
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode =
			error && typeof error === "object" && "exitCode" in error
				? Number(error.exitCode)
				: 1;
	}
}

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runProvisionSecrets } from "./provision-secrets.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const scriptFile = join(scriptDir, "provision-secrets.mjs");
const optionalSecretNames = [
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

const createCoreEnv = () => {
	const env = Object.fromEntries(
		Object.entries({
			...process.env,
			CINAAUTH_MIGRATION_TOKEN: "b".repeat(32),
			CINAAUTH_DELIVERY_WEBHOOK_URL:
				"https://cinaauth-delivery.cinagroup.com/cinaauth/delivery",
		}).filter(([name]) => name !== "CLOUDFLARE_ENV"),
	);
	for (const legacyName of [
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
		"CINAAUTH_ERASURE_WEBHOOK_SECRET",
		"CINAADMIN_OIDC_CLIENT_SECRET",
		"CINAADMIN_OIDC_BRIDGE_SECRET",
	]) {
		delete env[legacyName];
	}
	for (const optionalName of optionalSecretNames) delete env[optionalName];
	return env;
};

test("dry-run provisions only mutable Auth-owned Worker secrets when V2 bindings are active", () => {
	const result = spawnSync(
		process.execPath,
		[scriptFile, "--deployment-target", "production", "--dry-run"],
		{
			cwd: scriptDir,
			encoding: "utf8",
			env: createCoreEnv(),
		},
	);

	assert.equal(result.status, 0, result.stderr);
	for (const name of [
		"CINAAUTH_MIGRATION_TOKEN",
		"CINAAUTH_DELIVERY_WEBHOOK_URL",
		"CINAAUTH_ERASURE_WEBHOOK_URL",
	]) {
		assert.match(
			result.stdout,
			new RegExp(`Would provision ${name}(?:\\r?\\n|$)`),
		);
	}
	for (const preserved of ["CINAAUTH_SECRET", "CINAAUTH_PRIVACY_EXPORT_KEY"]) {
		assert.doesNotMatch(result.stdout, new RegExp(preserved));
	}
	for (const legacyName of [
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
		"CINAAUTH_ERASURE_WEBHOOK_SECRET",
		"CINAADMIN_OIDC_CLIENT_SECRET",
		"CINAADMIN_OIDC_BRIDGE_SECRET",
	]) {
		assert.doesNotMatch(result.stdout, new RegExp(legacyName));
	}
});

test("provisioner does not probe child operational readiness", () => {
	const source = readFileSync(scriptFile, "utf8");
	assert.doesNotMatch(source, /fetch\s*\(/);
	assert.doesNotMatch(source, /allow-erasure-not-ready/);
	assert.doesNotMatch(source, /CINAAUTH_SKIP_DELIVERY_READY_CHECK/);
});

test("requires exactly one explicit target and permits only one dry-run passthrough", () => {
	const cases = [
		{
			args: [],
			message: /Exactly one --deployment-target/,
		},
		{
			args: ["--deployment-target", "preview"],
			message: /must be production or siwe-staging/,
		},
		{
			args: [
				"--deployment-target",
				"production",
				"--deployment-target=production",
			],
			message: /Exactly one --deployment-target/,
		},
		{
			args: ["--deployment-target", "production", "--env", "staging"],
			message: /--env is not allowed/,
		},
		{
			args: ["--deployment-target", "production", "--config=escape.json"],
			message: /--config is not allowed/,
		},
		{
			args: ["--deployment-target", "production", "--dry-run", "--dry-run"],
			message: /--dry-run may be provided at most once/,
		},
		{
			args: ["--deployment-target", "production", "--unsafe-extra"],
			message: /Only --dry-run is allowed/,
		},
	];

	for (const { args, message } of cases) {
		const calls = [];
		const messages = [];
		assert.throws(
			() =>
				runProvisionSecrets({
					args,
					env: {},
					log: (value) => messages.push(value),
					spawnSyncImpl: (...call) => {
						calls.push(call);
						return { status: 0 };
					},
					wranglerCli: "C:\\test-only\\wrangler.js",
				}),
			message,
		);
		assert.deepEqual(calls, []);
		assert.deepEqual(messages, []);
	}
});

test("rejects ambient CLOUDFLARE_ENV without leaking its value", () => {
	const secretMarker = "secret-ambient-target-marker";
	let thrown;
	try {
		runProvisionSecrets({
			args: ["--deployment-target", "production", "--dry-run"],
			env: { CLOUDFLARE_ENV: secretMarker },
		});
	} catch (error) {
		thrown = error;
	}

	assert.ok(thrown instanceof Error);
	assert.match(thrown.message, /CLOUDFLARE_ENV must be unset or empty/);
	assert.doesNotMatch(thrown.message, new RegExp(secretMarker));
});

test("staging fails closed before secret validation, Wrangler resolution, spawn, or logging", () => {
	const effects = [];
	const options = {
		args: ["--deployment-target", "siwe-staging", "--dry-run"],
		env: {},
		get log() {
			effects.push("log-resolved");
			return (message) => effects.push(["log", message]);
		},
		get spawnSyncImpl() {
			effects.push("spawn-resolved");
			return (...call) => {
				effects.push(["spawn", call]);
				return { status: 0 };
			};
		},
		get wranglerCli() {
			effects.push("wrangler-resolved");
			return "C:\\test-only\\wrangler.js";
		},
	};

	assert.throws(
		() => runProvisionSecrets(options),
		/isolated staging inventory and Wrangler environment are complete/,
	);
	assert.deepEqual(effects, []);
	assert.doesNotMatch(
		JSON.stringify(effects),
		/cinaauth-erasure\.cinagroup\.com/,
	);
});

test("production dry-run requires an explicit target and never resolves or spawns Wrangler", () => {
	const calls = [];
	const messages = [];
	const options = {
		args: ["--deployment-target=production", "--dry-run"],
		env: createCoreEnv(),
		log: (message) => messages.push(message),
		get spawnSyncImpl() {
			calls.push("spawn-resolved");
			return () => ({ status: 0 });
		},
		get wranglerCli() {
			calls.push("wrangler-resolved");
			return "C:\\test-only\\wrangler.js";
		},
	};

	runProvisionSecrets(options);

	assert.deepEqual(calls, []);
	assert.match(messages.at(-1), /dry run complete/);
});

/** @see https://developers.cloudflare.com/workers/configuration/secrets/ */
test("stages mutable secrets in one versioned stdin bulk call without activating code after rollback", () => {
	const env = {
		...createCoreEnv(),
		CLOUDFLARE_ENV: "",
		CINAAUTH_SECRET: "preserved-auth-secret-value-000001",
		CINAAUTH_PRIVACY_EXPORT_KEY: "preserved-export-key-value-00001",
		OAUTH_PAIRWISE_SECRET: "optional-pairwise-value",
	};
	const calls = [];
	const messages = [];
	const wranglerCli = "C:\\test-only\\wrangler.js";

	runProvisionSecrets({
		args: ["--deployment-target", "production"],
		env,
		log: (message) => messages.push(message),
		spawnSyncImpl: (command, args, options) => {
			calls.push({ command, args, options });
			return { status: 0 };
		},
		wranglerCli,
	});

	assert.equal(calls.length, 1);
	assert.equal(calls[0].command, process.execPath);
	assert.deepEqual(calls[0].args, [wranglerCli, "versions", "secret", "bulk"]);
	assert.deepEqual(calls[0].options.stdio, ["pipe", "inherit", "inherit"]);
	assert.equal(Object.hasOwn(calls[0].options.env, "CLOUDFLARE_ENV"), false);
	assert.deepEqual(JSON.parse(calls[0].options.input), {
		CINAAUTH_MIGRATION_TOKEN: env.CINAAUTH_MIGRATION_TOKEN,
		CINAAUTH_DELIVERY_WEBHOOK_URL: env.CINAAUTH_DELIVERY_WEBHOOK_URL,
		CINAAUTH_ERASURE_WEBHOOK_URL:
			"https://cinaauth-erasure.cinagroup.com/cinaauth/privacy/erase",
		OAUTH_PAIRWISE_SECRET: env.OAUTH_PAIRWISE_SECRET,
	});
	assert.equal(
		Object.hasOwn(JSON.parse(calls[0].options.input), "CINAAUTH_SECRET"),
		false,
	);
	assert.equal(
		Object.hasOwn(
			JSON.parse(calls[0].options.input),
			"CINAAUTH_PRIVACY_EXPORT_KEY",
		),
		false,
	);
	assert.doesNotMatch(calls[0].args.join(" "), /optional-pairwise-value/);
	assert.doesNotMatch(messages.join("\n"), /optional-pairwise-value/);
});

test("pins the erasure webhook to the canonical production endpoint", () => {
	const env = {
		...createCoreEnv(),
		CINAAUTH_ERASURE_WEBHOOK_URL:
			"https://operator-controlled.example/cinaauth/privacy/erase",
	};
	const calls = [];
	const messages = [];

	runProvisionSecrets({
		args: ["--deployment-target", "production"],
		env,
		log: (message) => messages.push(message),
		spawnSyncImpl: (command, args, options) => {
			calls.push({ command, args, options });
			return { status: 0 };
		},
		wranglerCli: "C:\\test-only\\wrangler.js",
	});

	assert.equal(calls.length, 1);
	assert.equal(
		JSON.parse(calls[0].options.input).CINAAUTH_ERASURE_WEBHOOK_URL,
		"https://cinaauth-erasure.cinagroup.com/cinaauth/privacy/erase",
	);
	assert.doesNotMatch(calls[0].options.input, /operator-controlled\.example/);
	assert.doesNotMatch(messages.join("\n"), /operator-controlled\.example/);
});

test("spawn startup failures do not echo secret-bearing error details", () => {
	const secretMarker = "top-secret-spawn-error-marker";
	let thrown;
	try {
		runProvisionSecrets({
			args: ["--deployment-target", "production"],
			env: createCoreEnv(),
			spawnSyncImpl: () => ({ error: new Error(secretMarker) }),
			wranglerCli: "C:\\test-only\\wrangler.js",
		});
	} catch (error) {
		thrown = error;
	}

	assert.ok(thrown instanceof Error);
	assert.match(thrown.message, /Failed to start Wrangler/);
	assert.doesNotMatch(thrown.message, new RegExp(secretMarker));
});

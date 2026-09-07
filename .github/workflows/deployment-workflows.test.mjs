import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const readWorkflow = (name) =>
	readFileSync(new URL(name, import.meta.url), "utf8");

const rootPackage = JSON.parse(
	readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
);
const knip = readFileSync(new URL("../../knip.jsonc", import.meta.url), "utf8");
const central = readWorkflow("deploy-cloudflare.yml");
const ci = readWorkflow("ci.yml");
const e2e = readWorkflow("e2e.yml");
const preview = readWorkflow("preview.yml");
const account = readWorkflow("deploy-account-portal.yml");
const admin = readWorkflow("deploy-admin-console.yml");
const oidcClient = readWorkflow("deploy-oidc-client-demo.yml");
const localDeploy = readFileSync(
	new URL("../../deploy-cloudflare.sh", import.meta.url),
	"utf8",
);
const edgeMitigationClassifier = readFileSync(
	new URL("../../scripts/cloudflare-edge-mitigation.mjs", import.meta.url),
	"utf8",
);
const deliveryRemotePreflight = readFileSync(
	new URL(
		"../../workers/delivery/scripts/check-cloudflare-remote.mjs",
		import.meta.url,
	),
	"utf8",
);
const privacyRemotePreflight = readFileSync(
	new URL(
		"../../workers/privacy-erasure/scripts/check-cloudflare-remote.mjs",
		import.meta.url,
	),
	"utf8",
);

const productionWorkflows = [
	["deploy-cloudflare.yml", central],
	["deploy-account-portal.yml", account],
	["deploy-admin-console.yml", admin],
	["deploy-oidc-client-demo.yml", oidcClient],
];

const jobBlock = (source, job, nextJob) => {
	const start = source.indexOf(`  ${job}:`);
	assert.notEqual(start, -1, `missing ${job} job`);
	const end = nextJob ? source.indexOf(`  ${nextJob}:`, start + 1) : -1;
	return source.slice(start, end === -1 ? undefined : end);
};

const pnpmSetupBlocks = (source) => {
	const lines = source.split("\n");
	const blocks = [];
	for (let index = 0; index < lines.length; index += 1) {
		if (!lines[index].includes("uses: pnpm/action-setup@")) continue;
		const indentation = lines[index].match(/^\s*/)?.[0].length ?? 0;
		let end = index + 1;
		while (end < lines.length) {
			const line = lines[end];
			if (line.trim().length > 0) {
				const nextIndentation = line.match(/^\s*/)?.[0].length ?? 0;
				if (nextIndentation < indentation) break;
			}
			end += 1;
		}
		blocks.push(lines.slice(index, end).join("\n"));
	}
	return blocks;
};

/** @see https://www.better-auth.com/docs/guides/1-7-upgrade-guide */
test("central deployment migrates the enabled organization schema before checking Auth", () => {
	const previewStart = central.indexOf(
		"      - name: Preview Worker migrations",
	);
	const applyStart = central.indexOf("      - name: Apply Worker migrations");
	const readyStart = central.indexOf("      - name: Check Worker readiness");
	assert.ok(
		previewStart > 0 && applyStart > previewStart && readyStart > applyStart,
	);
	for (const step of [
		central.slice(previewStart, applyStart),
		central.slice(applyStart, readyStart),
	]) {
		const migrationURL = step.match(
			/https:\/\/auth\.cinaseek\.ai\/api\/migrate[^\s"']*/,
		)?.[0];
		assert.ok(
			migrationURL,
			"migration step must call the protected migration route",
		);
		assert.equal(
			new URL(migrationURL).searchParams.get("feature"),
			"organization-advanced",
		);
	}
});

test("production workflows use the root packageManager pnpm version", () => {
	assert.match(rootPackage.packageManager, /^pnpm@\d+\.\d+\.\d+(?:[-+].+)?$/);
	for (const [name, source] of productionWorkflows) {
		const setupBlocks = pnpmSetupBlocks(source);
		assert.ok(setupBlocks.length > 0, `${name} must install pnpm`);
		for (const block of setupBlocks) {
			assert.doesNotMatch(
				block,
				/^\s+version:/m,
				`${name} must let package.json packageManager select the pnpm version`,
			);
		}
	}
});

test("package preview publishing requires an explicit repository opt-in", () => {
	const publishStart = preview.indexOf(
		"      - name: Publish package previews",
	);
	assert.notEqual(publishStart, -1, "missing named package preview step");
	const publish = preview.slice(publishStart);

	assert.match(publish, /if: vars\.PKG_PR_NEW_ENABLED == 'true'/);
	assert.match(publish, /pnpm exec pkg-pr-new publish/);
});

test("production writes have only the governed central and Account Phase One entrypoints", () => {
	const trigger = central.slice(
		central.indexOf("on:"),
		central.indexOf("permissions:"),
	);
	assert.match(trigger, /workflow_dispatch:/);
	assert.doesNotMatch(trigger, /\n  push:/);
	assert.doesNotMatch(trigger, /\n  workflow_call:/);

	const accountTrigger = account.slice(
		account.indexOf("on:"),
		account.indexOf("permissions:"),
	);
	assert.match(accountTrigger, /workflow_call:/);
	assert.match(accountTrigger, /workflow_dispatch:/);
	assert.doesNotMatch(accountTrigger, /\n  push:/);

	for (const [job, workflow] of [
		["deploy-account-portal", "deploy-account-portal.yml"],
		["deploy-admin-console", "deploy-admin-console.yml"],
	]) {
		const block = jobBlock(central, job);
		assert.match(block, /needs: deploy-worker/);
		assert.match(
			block,
			new RegExp(`uses: \\.\\/.github/workflows/${workflow}`),
		);
		assert.match(block, /secrets: inherit/);
	}
});

test("the central caller explicitly selects reusable Account mode without exposing a manual bypass", () => {
	const trigger = account.slice(
		account.indexOf("on:"),
		account.indexOf("permissions:"),
	);
	const workflowCallStart = trigger.indexOf("  workflow_call:");
	const workflowDispatchStart = trigger.indexOf("  workflow_dispatch:");
	assert.notEqual(workflowCallStart, -1);
	assert.notEqual(workflowDispatchStart, -1);
	const workflowCall = trigger.slice(workflowCallStart, workflowDispatchStart);
	const workflowDispatch = trigger.slice(workflowDispatchStart);
	assert.match(workflowCall, /deployment_mode:/);
	assert.match(workflowCall, /required: true/);
	assert.match(workflowCall, /type: string/);
	assert.doesNotMatch(workflowDispatch, /deployment_mode:/);

	const caller = jobBlock(
		central,
		"deploy-account-portal",
		"deploy-admin-console",
	);
	assert.match(caller, /with:\s+deployment_mode: central/);
	assert.match(caller, /secrets: inherit/);

	const deploy = jobBlock(account, "deploy");
	assert.match(deploy, /Validate reusable Account deployment mode/);
	assert.match(deploy, /if: inputs\.deployment_mode == ''/);
	assert.match(deploy, /if: inputs\.deployment_mode == 'central'/);
	assert.doesNotMatch(deploy, /if: github\.event_name/);
});

test("manual Account Phase One deploy is main-only, attested, and keeps SIWE disabled", () => {
	const deploy = jobBlock(account, "deploy");
	assert.match(account, /DEPLOY CINAAUTH ACCOUNT PORTAL PHASE ONE/);
	assert.match(deploy, /if: inputs\.deployment_mode == ''/);
	assert.match(deploy, /GITHUB_REF.*refs\/heads\/main/);
	assert.match(
		deploy,
		/CINAAUTH_PLANNED_WORKER_CONFIG: \.\.\/\.\.\/workers\/auth-api\/wrangler\.json/,
	);
	assert.match(deploy, /CINAAUTH_SIWE_ENABLED/);
	assert.match(deploy, /!== "false"/);
	assert.match(deploy, /REOWN_PROJECT_ID/);
	assert.match(deploy, /Configure wallet UI rollout from tracked Auth config/);
	assert.match(deploy, /NEXT_PUBLIC_SIWE_WALLET_UI_ENABLED/);
	assert.match(deploy, /Verify deployed Account wallet readiness parity/);
	assert.match(deploy, /cinaauth-siwe-v2/);
	assert.match(deploy, /reown-appkit-v1/);
	assert.match(deploy, /readiness\.reownProjectId !== expectedProjectId/);
	assert.match(
		deploy,
		/readiness\.walletUiEnabled !== expectedWalletUiEnabled/,
	);
	assert.match(deploy, /Verify public Auth availability for Phase One/);
	assert.match(deploy, /if: inputs\.deployment_mode == 'central'/);
	assert.doesNotMatch(deploy, /if: github\.event_name/);
	assert.match(deploy, /environment: production/);
});

test("every Account deployment verifies the deployed wallet marker against the tracked release", () => {
	const start = account.indexOf(
		"      - name: Verify deployed Account wallet readiness parity",
	);
	assert.notEqual(start, -1, "missing deployed Account wallet readiness check");
	const end = account.indexOf("      - name: Smoke test account portal", start);
	assert.notEqual(end, -1, "wallet readiness check must precede Account smoke");
	const parity = account.slice(start, end);

	assert.doesNotMatch(parity, /^\s+if:/m);
	assert.match(
		parity,
		/REOWN_PROJECT_ID: \$\{\{ secrets\.REOWN_PROJECT_ID \}\}/,
	);
	assert.match(parity, /NEXT_PUBLIC_SIWE_WALLET_UI_ENABLED/);
	assert.match(parity, /cache-control:.*no-store/i);
	assert.match(parity, /readiness\.schemaVersion !== 1/);
	assert.match(parity, /readiness\.ready !== expectedReady/);
	assert.match(parity, /readiness\.siweProtocol !== "cinaauth-siwe-v2"/);
	assert.match(parity, /readiness\.walletUi !== "reown-appkit-v1"/);
	assert.match(
		parity,
		/readiness\.walletUiEnabled !== expectedWalletUiEnabled/,
	);
	assert.match(parity, /readiness\.reownProjectId !== expectedProjectId/);
	assert.doesNotMatch(parity, /console\.log\([^)]*REOWN_PROJECT_ID/);
});

test("Account Portal deployment jobs build workspace packages before typecheck", () => {
	const deploymentJobs = [
		["manual and reusable Account deployment", jobBlock(account, "deploy")],
		[
			"central Account preflight",
			jobBlock(central, "preflight-account-portal", "deploy-delivery"),
		],
	];

	for (const [name, source] of deploymentJobs) {
		const install = source.indexOf("- name: Install dependencies");
		const build = source.indexOf("- name: Build workspace packages");
		const typecheck = source.indexOf("- name: Typecheck account portal");

		assert.ok(install >= 0, `${name} must install dependencies`);
		assert.ok(build > install, `${name} must build after install`);
		assert.ok(
			typecheck > build,
			`${name} must typecheck after the workspace build`,
		);
		assert.match(
			source.slice(build, typecheck),
			/run: pnpm --dir \.\.\/\.\. build/,
		);
	}
});

test("Admin deployment builds the real auth handler before typechecking and testing proxies", () => {
	const install = admin.indexOf("- name: Install dependencies");
	const build = admin.indexOf("- name: Build Admin test dependencies");
	const typecheck = admin.indexOf("- name: Typecheck admin console");
	const testAdmin = admin.indexOf("- name: Test admin console");
	assert.ok(build > install, "Admin must build dependencies after installing");
	assert.ok(
		typecheck > build,
		"Admin typecheck requires built CinaAuth declarations",
	);
	assert.ok(
		testAdmin > typecheck,
		"Admin proxy tests must run after dependency build and typecheck",
	);
	assert.match(
		admin.slice(build, typecheck),
		/run: pnpm --dir \.\.\/\.\. exec turbo build --filter=cinaauth\.\.\./,
	);
});

test("Account Portal smoke verifies the legacy custom domain across Cloudflare boundaries", () => {
	const deploy = jobBlock(account, "deploy");
	const smokeStart = deploy.indexOf("- name: Smoke test account portal");
	assert.ok(smokeStart >= 0, "missing Account Portal smoke step");
	const smoke = deploy.slice(smokeStart);

	assert.match(smoke, /workers\/domains\?hostname=demo-auth\.cinagroup\.com/);
	assert.match(smoke, /domains\.length !== 1/);
	assert.match(smoke, /domain\.service !== "cinaauth-demo"/);
	assert.match(smoke, /domain\.zone_name !== "cinagroup\.com"/);
	assert.match(smoke, /domain\.cert_id/);
	assert.match(
		smoke,
		/domain\.environment !== undefined && domain\.environment !== "production"/,
	);
	assert.match(
		smoke,
		/legacy_status="\$\(curl[\s\S]*--write-out '%\{http_code\}'/,
	);
	assert.match(smoke, /legacy_status" = "308"/);
	assert.match(
		smoke,
		/legacy_location" = "https:\/\/accounts\.cinaseek\.ai\/sign-in\?callbackURL=%2Fdashboard"/,
	);
	assert.match(smoke, /cf-mitigated:\[\[:space:\]\]\*challenge/);
	assert.match(smoke, /\^cf-ray:/);
	assert.match(smoke, /attention required/);
	assert.match(smoke, /sorry, you have been blocked/);
	assert.match(smoke, /cloudflare/);
	assert.match(smoke, /ray id/);
	assert.match(smoke, /Cloudflare mitigation response/);
	assert.match(smoke, /Unexpected legacy Account domain response/);
	assert.match(deploy, /middleware\.test\.ts/);
});

test("stateful Worker probes reuse the strict Account edge-mitigation contract", () => {
	assert.match(edgeMitigationClassifier, /status !== 403/);
	assert.match(edgeMitigationClassifier, /contentType !== "text\/html"/);
	assert.match(edgeMitigationClassifier, /headers\.get\("cf-mitigated"\)/);
	assert.match(edgeMitigationClassifier, /=== "challenge"/);
	assert.match(edgeMitigationClassifier, /headers\.get\("cf-ray"\)/);
	assert.match(edgeMitigationClassifier, /bodyRayId === headerRayId/);
	assert.match(edgeMitigationClassifier, /attention required/);
	assert.match(edgeMitigationClassifier, /you have been blocked/);
	assert.match(edgeMitigationClassifier, /cloudflare\\s\+ray\\s\+id/);

	for (const [name, remotePreflight] of [
		["Delivery", deliveryRemotePreflight],
		["Privacy Erasure", privacyRemotePreflight],
	]) {
		assert.match(
			remotePreflight,
			/import \{ classifyCloudflareEdgeMitigation \} from "\.\.\/\.\.\/\.\.\/scripts\/cloudflare-edge-mitigation\.mjs"/,
			`${name} must use the shared classifier`,
		);
		assert.match(
			remotePreflight,
			/!allowEdgeMitigation \|\| response\.status !== 403/,
			`${name} must keep non-403 responses on the normal validation path`,
		);
		assert.match(
			remotePreflight,
			/checkPublicEndpoints\(failures\.length === 0(?: && domainVerified)?\)/,
			`${name} must require successful Cloudflare API checks before mitigation handling`,
		);
		assert.match(remotePreflight, /edge-mitigated\/unverified/);
		assert.match(remotePreflight, /readiness was not verified/);
		assert.match(remotePreflight, /edgeMitigatedEndpoints\.length > 0/);
	}
	assert.match(deliveryRemotePreflight, /domainVerified/);
	assert.match(
		deliveryRemotePreflight,
		/checkPublicEndpoints\(failures\.length === 0 && domainVerified\)/,
	);
	assert.match(
		deliveryRemotePreflight,
		/Remote Delivery Worker has no active 100% deployment/,
	);
	assert.match(deliveryRemotePreflight, /DeliveryProviderConfig/);
	assert.match(deliveryRemotePreflight, /migration_tag !== "v1"/);
	assert.match(deliveryRemotePreflight, /Custom Domain .* is missing/);
	assert.match(
		deliveryRemotePreflight,
		/remoteDomain\.environment !== undefined &&[\s\S]*remoteDomain\.environment !== "production"/,
	);
	assert.match(
		privacyRemotePreflight,
		/remote\.environment !== undefined &&[\s\S]*remote\.environment !== "production"/,
	);
});

test("production attestation and live backup audit gate every Cloudflare write", () => {
	for (const input of [
		"restore_rehearsal_completed",
		"restore_rehearsal_reference",
		"backup_reference",
		"operator_attestation",
	]) {
		assert.match(central, new RegExp(`${input}:`));
	}
	assert.match(central, /type: boolean/);
	assert.match(central, /DEPLOY CINAAUTH PRODUCTION/);

	const gate = jobBlock(
		central,
		"authorize-production",
		"preflight-account-portal",
	);
	assert.match(gate, /environment: production/);
	assert.match(gate, /PLANETSCALE_SERVICE_TOKEN_ID/);
	assert.match(gate, /PLANETSCALE_SERVICE_TOKEN/);
	assert.match(gate, /GITHUB_REF.*refs\/heads\/main/);
	assert.match(gate, /tr -d '\[:space:\]'/);
	assert.match(
		gate,
		/node workers\/auth-api\/scripts\/check-planetscale-backups\.mjs > "\$report_file"/,
	);
	assert.doesNotMatch(
		gate,
		/pnpm .*--dir workers\/auth-api run check:planetscale-backups/,
	);
	assert.match(gate, /report\.activeBackups/);
	assert.match(gate, /inputs\.backup_reference/);
	assert.doesNotMatch(gate, /cloudflare\/wrangler-action|command: deploy/);

	for (const [job, nextJob] of [
		["deploy-delivery", "deploy-privacy-erasure"],
		["deploy-privacy-erasure", "deploy-worker"],
	]) {
		const block = jobBlock(central, job, nextJob);
		assert.match(
			block,
			/needs: \[authorize-production, preflight-account-portal\]/,
		);
		assert.match(block, /environment: production/);
	}
	assert.match(
		jobBlock(central, "deploy-worker", "deploy-account-portal"),
		/environment: production/,
	);
});

test("planned SIWE and the Accounts bundle are verified before Worker deployment", () => {
	const preflight = jobBlock(
		central,
		"preflight-account-portal",
		"deploy-delivery",
	);
	assert.match(preflight, /needs: authorize-production/);
	assert.match(preflight, /environment: production/);
	assert.match(
		preflight,
		/CINAAUTH_PLANNED_WORKER_CONFIG: \.\.\/\.\.\/workers\/auth-api\/wrangler\.json/,
	);
	assert.match(
		preflight,
		/REOWN_PROJECT_ID: \$\{\{ secrets\.REOWN_PROJECT_ID \}\}/,
	);
	assert.match(
		preflight,
		/NEXT_PUBLIC_REOWN_PROJECT_ID: \$\{\{ secrets\.REOWN_PROJECT_ID \}\}/,
	);
	assert.doesNotMatch(preflight, /vars\.REOWN_PROJECT_ID/);
	assert.match(
		account,
		/REOWN_PROJECT_ID: \$\{\{ secrets\.REOWN_PROJECT_ID \}\}/,
	);
	assert.match(
		account,
		/NEXT_PUBLIC_REOWN_PROJECT_ID: \$\{\{ secrets\.REOWN_PROJECT_ID \}\}/,
	);
	assert.doesNotMatch(account, /vars\.REOWN_PROJECT_ID/);
	assert.match(preflight, /pnpm run check:oauth-build/);
	assert.match(preflight, /CINAAUTH_EMAIL_AUTH_GATE: portal-compatible/);
	assert.match(
		preflight,
		/CINAAUTH_CAPABILITIES_URL: https:\/\/accounts\.cinaseek\.ai\/api\/auth\/capabilities/,
	);
	assert.match(account, /CINAAUTH_EMAIL_AUTH_GATE: runtime-configurable/);
	assert.match(
		account,
		/CINAAUTH_CAPABILITIES_URL: https:\/\/accounts\.cinaseek\.ai\/api\/auth\/capabilities/,
	);
	assert.match(preflight, /pnpm run build:cf/);
	assert.match(
		preflight,
		/Configure wallet UI rollout from tracked Auth config/,
	);
	assert.match(preflight, /NEXT_PUBLIC_SIWE_WALLET_UI_ENABLED/);
	assert.match(
		preflight,
		/CINAAUTH_ACCOUNT_BUILD_READINESS_URL: https:\/\/accounts\.cinaseek\.ai\/api\/build-readiness/,
	);
	for (const contract of [
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
	]) {
		assert.match(preflight, new RegExp(contract.replaceAll(".", "\\.")));
		assert.match(account, new RegExp(contract.replaceAll(".", "\\.")));
	}
	assert.doesNotMatch(
		preflight,
		/cloudflare\/wrangler-action|command: deploy|pnpm run deploy/,
	);
	assert.equal(
		(
			account.match(
				/run: pnpm run deploy:cf --deployment-target=production/g,
			) ?? []
		).length,
		1,
		"the reusable Account Portal workflow must deploy exactly once",
	);
	assert.ok(
		account.indexOf("CINAAUTH_EMAIL_AUTH_GATE: runtime-configurable") <
			account.indexOf("run: pnpm run deploy:cf --deployment-target=production"),
		"the live configurable authentication contract gate must run before the Account write",
	);
	assert.doesNotMatch(account, /cloudflare\/wrangler-action|command: deploy/);

	for (const [job, nextJob] of [
		["deploy-delivery", "deploy-privacy-erasure"],
		["deploy-privacy-erasure", "deploy-worker"],
	]) {
		assert.match(
			jobBlock(central, job, nextJob),
			/needs: \[authorize-production, preflight-account-portal\]/,
		);
	}
	assert.match(
		jobBlock(central, "deploy-worker", "deploy-account-portal"),
		/needs: \[deploy-delivery, deploy-privacy-erasure, preflight-account-portal\]/,
	);
});

test("Auth Worker builds workspace dependencies before configuration and checks", () => {
	const auth = jobBlock(central, "deploy-worker", "deploy-account-portal");
	const install = auth.indexOf("- name: Install dependencies");
	const build = auth.indexOf("- name: Build Auth workspace dependencies");
	const configureHyperdrive = auth.indexOf(
		"- name: Configure Hyperdrive binding",
	);
	const checkWorker = auth.indexOf("- name: Check Worker types and bindings");

	assert.ok(install >= 0, "Auth Worker must install dependencies");
	assert.ok(
		build > install,
		"Auth Worker must build dependencies after install",
	);
	assert.ok(
		configureHyperdrive > build,
		"Auth Worker must configure Hyperdrive after building dependencies",
	);
	assert.ok(
		checkWorker > configureHyperdrive,
		"Auth Worker must check types and bindings after Hyperdrive configuration",
	);
	assert.match(
		auth.slice(build, configureHyperdrive),
		/^\s+run: pnpm run build:dependencies\s*$/m,
	);
});

test("Auth Worker verifies the deployed Agent Auth policy", () => {
	const auth = jobBlock(central, "deploy-worker", "deploy-account-portal");
	const deploy = auth.indexOf("- name: Deploy Worker");
	const readiness = auth.indexOf("- name: Check Worker readiness");
	const verification = auth.indexOf(
		"- name: Verify deployed Agent Auth discovery and capability policy",
	);

	assert.ok(deploy >= 0, "Auth Worker must deploy");
	assert.ok(
		readiness > deploy,
		"Auth Worker must verify readiness after deploy",
	);
	assert.ok(
		verification > readiness,
		"Agent Auth policy verification must run after readiness",
	);
	assert.match(auth.slice(verification), /run: pnpm run check:agent-auth/);
});

test("E2E jobs use one consistent runner selection contract", () => {
	for (const [job, nextJob] of [
		["smoke", "integration"],
		["integration", "adapter-integration"],
		["adapter-integration", "e2e"],
	]) {
		const block = jobBlock(e2e, job, nextJob);
		assert.match(block, /head\.repo\.full_name == 'cinaauth\/cinaauth'/);
		assert.match(block, /github\.repository == 'cinaauth\/cinaauth'/);
		assert.doesNotMatch(block, /cinagroup\/cinaauth/);
	}
});

test("application workflows remain reusable production-environment units", () => {
	for (const source of [account, admin]) {
		const trigger = source.slice(
			source.indexOf("on:"),
			source.indexOf("permissions:"),
		);
		assert.match(trigger, /workflow_call:/);
		assert.doesNotMatch(trigger, /\n  push:/);
		assert.match(jobBlock(source, "deploy"), /environment: production/);
	}
	const adminTrigger = admin.slice(
		admin.indexOf("on:"),
		admin.indexOf("permissions:"),
	);
	assert.doesNotMatch(adminTrigger, /workflow_dispatch:/);
});

test("backend bootstrap preserves stateful secrets and never writes deferred V1 shared secrets", () => {
	for (const preserved of [
		"CINAAUTH_SECRET",
		"CINAAUTH_PRIVACY_EXPORT_KEY",
		"CINAAUTH_ERASURE_STORAGE_SECRET",
	]) {
		assert.doesNotMatch(
			central,
			new RegExp(`secrets\\.${preserved}|^\\s+${preserved}:`, "m"),
			`${preserved} must stay in Cloudflare and must not be sourced from GitHub or rewritten by the central deployment`,
		);
	}

	for (const forbidden of [
		"RESEND_API_KEY",
		"RESEND_EMAIL_FROM",
		"CLOUDFLARE_EMAIL_API_TOKEN",
		"CLOUDFLARE_EMAIL_FROM",
		"TWILIO_ACCOUNT_SID",
		"TWILIO_AUTH_TOKEN",
		"TWILIO_FROM_NUMBER",
		"CINAAUTH_ERASURE_TARGETS",
		"CINAAUTH_DELIVERY_WEBHOOK_SECRET",
		"CINAAUTH_ERASURE_WEBHOOK_SECRET",
		"CINAADMIN_OIDC_CLIENT_SECRET",
		"CINAADMIN_OIDC_BRIDGE_SECRET",
		"CINAADMIN_OIDC_TRANSACTION_SECRET",
	]) {
		assert.doesNotMatch(central, new RegExp(forbidden));
	}

	const delivery = jobBlock(
		central,
		"deploy-delivery",
		"deploy-privacy-erasure",
	);
	assert.match(delivery, /pnpm run build/);
	assert.match(delivery, /pnpm run check:cloudflare/);
	assert.doesNotMatch(delivery, /provision:secrets/);

	const privacy = jobBlock(central, "deploy-privacy-erasure", "deploy-worker");
	assert.doesNotMatch(privacy, /CINAAUTH_ERASURE_STORAGE_SECRET/);
	assert.doesNotMatch(privacy, /pnpm run provision:secrets/);
	assert.match(privacy, /check:cloudflare -- --allow-not-ready/);

	const auth = jobBlock(central, "deploy-worker", "deploy-account-portal");
	assert.match(
		auth,
		/Provision Auth Worker mutable and configured optional secrets/,
	);
	assert.match(auth, /run: pnpm run provision:secrets/);
	assert.doesNotMatch(
		auth,
		/node - <<|wrangler secret bulk|Object\.fromEntries/,
	);
	for (const name of [
		"CINAAUTH_MIGRATION_TOKEN",
		"CINAAUTH_DELIVERY_WEBHOOK_URL",
		"OAUTH_PAIRWISE_SECRET",
		"CINAAUTH_ENTITLEMENT_CONFIG",
	]) {
		assert.match(auth, new RegExp(name));
	}
	assert.doesNotMatch(auth, /CINAAUTH_SECRET|CINAAUTH_PRIVACY_EXPORT_KEY/);
	assert.doesNotMatch(
		auth,
		/^\s+CINAAUTH_ERASURE_WEBHOOK_URL:/m,
		"the provisioner owns the canonical erasure endpoint; CI must not supply an override",
	);
	assert.ok(
		auth.indexOf("run: pnpm run provision:secrets") <
			auth.indexOf("Build Worker dry run"),
		"Auth bulk provisioning must precede the deploy build",
	);

	for (const block of [delivery, privacy]) {
		assert.ok(
			block.indexOf("pnpm run build") < block.indexOf("command: deploy"),
			"dry-run build must precede deployment",
		);
		assert.ok(
			block.indexOf("command: deploy") < block.indexOf("check:cloudflare"),
			"remote binding checks must follow deployment",
		);
	}
});

test("production authorization verifies preserved Cloudflare secret names read-only", () => {
	const gate = jobBlock(
		central,
		"authorize-production",
		"preflight-account-portal",
	);
	assert.match(gate, /Verify preserved Cloudflare Worker secret inventory/);
	assert.match(gate, /scripts\/check-cloudflare-preserved-secrets\.mjs/);
	assert.match(gate, /CLOUDFLARE_API_TOKEN/);
	assert.match(gate, /CLOUDFLARE_ACCOUNT_ID/);
	assert.doesNotMatch(gate, /secret put|secret bulk|command: deploy/);
});

test("production script consumers select the explicit top-level deployment target", () => {
	const provisionCommands = [
		...central.matchAll(/^\s*run:\s+(pnpm run provision:secrets[^\r\n]*)/gm),
	].map((match) => match[1]);
	assert.equal(provisionCommands.length, 1);
	for (const command of provisionCommands) {
		assert.match(command, /--deployment-target=production(?:\s|$)/);
		assert.doesNotMatch(command, /-- --deployment-target/);
		assert.doesNotMatch(command, /--env(?:\s|=)|CLOUDFLARE_ENV/);
	}
	assert.match(
		localDeploy,
		/pnpm --dir apps\/account-portal run deploy:cf --deployment-target=production/,
	);
	assert.match(
		account,
		/run: pnpm run deploy:cf --deployment-target=production/,
	);
	assert.doesNotMatch(
		account,
		/run: pnpm run deploy:cf -- --deployment-target/,
	);
	for (const workflow of [account, central]) {
		assert.match(workflow, /run: pnpm run test:deploy-cf/);
	}
});

test("deployment target contracts run in CI and before production authorization", () => {
	const script = rootPackage.scripts?.["test:cloudflare-deployment-contracts"];
	assert.equal(typeof script, "string");
	const testFiles = [
		"scripts/cloudflare-deployment-target.test.mjs",
		"scripts/check-cloudflare-preserved-secrets.test.mjs",
		"scripts/cloudflare-edge-mitigation.test.mjs",
		".github/workflows/deployment-workflows.test.mjs",
		"workers/auth-api/scripts/provision-secrets.test.mjs",
		"workers/delivery/scripts/provision-secrets.test.mjs",
		"workers/privacy-erasure/scripts/provision-secrets.test.mjs",
		"apps/account-portal/deploy-cf.test.mjs",
	];
	for (const file of testFiles) {
		assert.match(script, new RegExp(file.replaceAll(".", "\\.")));
		assert.match(central, new RegExp(file.replaceAll(".", "\\.")));
	}
	assert.match(ci, /run: pnpm run test:cloudflare-deployment-contracts/);
});

test("the preserved-secret checker is a declared production tooling entry", () => {
	assert.match(knip, /"scripts\/check-cloudflare-preserved-secrets\.mjs!"/);
});

test("frontends rely on Auth readiness and configured bindings", () => {
	assert.doesNotMatch(account, /CINAAUTH_DEMO_SECRET|wrangler secret put/);
	assert.match(account, /Wait for governed Auth readiness/);

	assert.doesNotMatch(
		admin,
		/CINAADMIN_OIDC_(?:CLIENT|BRIDGE|TRANSACTION)_SECRET|provision:secrets/,
	);
	assert.match(admin, /Validate production binding contract/);
	assert.match(admin, /Wait for governed Auth readiness/);
});

test("OIDC acceptance validates its explicit production target", () => {
	assert.match(
		oidcClient,
		/CINAAUTH_OIDC_DEMO_TARGET_ORIGIN: https:\/\/oidc-demo\.cinaseek\.ai/,
	);
	assert.match(oidcClient, /pnpm run check:production/);
	assert.doesNotMatch(oidcClient, /env\.staging|deploy-siwe-staging/);
});

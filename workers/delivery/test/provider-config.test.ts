import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DeliveryWorkerEnv } from "../src/env";
import type {
	EmailProviderConfig,
	SmsProviderConfig,
} from "../src/provider-config";
import { DeliveryProviderConfig } from "../src/provider-config";

type SqlValue = Uint8Array | string | number | null;
type SqlRow = Record<string, SqlValue>;

const createSqlState = () => {
	const database = new DatabaseSync(":memory:");
	let initialization = Promise.resolve();
	const sql = {
		exec<T extends SqlRow>(query: string, ...bindings: SqlValue[]) {
			const statement = database.prepare(query);
			const rows = statement.columns().length
				? (statement.all(...bindings) as T[])
				: (statement.run(...bindings), [] as T[]);
			return {
				toArray: () => rows,
				one: () => {
					if (rows.length !== 1 || !rows[0]) {
						throw new Error(`Expected one SQLite row, received ${rows.length}`);
					}
					return rows[0];
				},
			};
		},
	};
	const storage = {
		sql,
		transactionSync<T>(callback: () => T) {
			database.exec("BEGIN IMMEDIATE");
			try {
				const result = callback();
				database.exec("COMMIT");
				return result;
			} catch (error) {
				database.exec("ROLLBACK");
				throw error;
			}
		},
	};
	const state = {
		storage,
		blockConcurrencyWhile<T>(callback: () => Promise<T>) {
			const current = callback();
			initialization = current.then(() => undefined);
			return current;
		},
	};
	return {
		database,
		state: state as unknown as DurableObjectState,
		waitForInitialization: () => initialization,
	};
};

const kek = `test-delivery-config-kek-${"k".repeat(48)}`;

const makeRepository = () => {
	const sqlState = createSqlState();
	const env = {
		CINAAUTH_DELIVERY_CONFIG_KEK_STORE: {
			get: vi.fn(async () => kek),
		},
	} as unknown as DeliveryWorkerEnv;
	return {
		database: sqlState.database,
		state: sqlState.state,
		waitForInitialization: sqlState.waitForInitialization,
		repository: new DeliveryProviderConfig(sqlState.state, env),
	};
};

const emailConfig: EmailProviderConfig = {
	provider: "resend",
	apiKey: `re_${"a".repeat(36)}`,
	from: "CinaSeek <no-reply@cinaseek.ai>",
};

const cloudflareEmailConfig: EmailProviderConfig = {
	provider: "cloudflare-email",
	apiToken: `cf-email-token-${"e".repeat(24)}`,
	accountId: `f${"0".repeat(31)}`,
	from: "CinaSeek <no-reply@cinaseek.ai>",
};

const smsConfig: SmsProviderConfig = {
	accountSid: `AC${"b".repeat(32)}`,
	authToken: "c".repeat(32),
	from: "+14155550123",
};

afterEach(() => {
	vi.restoreAllMocks();
});

describe("DeliveryProviderConfig SQLite repository", () => {
	it("stages, activates, and resolves a Cloudflare Email provider without leaking its token", async () => {
		const harness = makeRepository();
		await harness.waitForInitialization();

		const staged = await harness.repository.stage({
			provider: "email",
			config: cloudflareEmailConfig,
			expectedVersion: 0,
			idempotencyKey: "stage-email-cf01",
		});
		expect(staged).toMatchObject({
			ok: true,
			value: { operation: "stage", revision: 1, version: 1 },
		});

		const persisted = harness.database
			.prepare("SELECT * FROM delivery_provider_versions")
			.all();
		expect(JSON.stringify(persisted)).not.toContain(
			cloudflareEmailConfig.apiToken,
		);
		expect(JSON.stringify(persisted)).not.toContain(
			cloudflareEmailConfig.accountId,
		);

		const prepared = await harness.repository.prepareTest({
			provider: "email",
			target: "owner@example.test",
			expectedVersion: 1,
			idempotencyKey: "test-email-cf01",
		});
		expect(prepared).toMatchObject({
			ok: true,
			value: { kind: "ready", config: cloudflareEmailConfig },
		});
		if (!prepared.ok || prepared.value.kind !== "ready") {
			throw new Error("test preparation failed");
		}
		await harness.repository.completeTest({
			provider: "email",
			version: staged.ok ? (staged.value.version ?? 1) : 1,
			idempotencyKey: "test-email-cf01",
			operationToken: prepared.value.operationToken,
		});
		await harness.repository.activate({
			provider: "email",
			expectedVersion: 2,
			idempotencyKey: "activate-email-cf01",
		});
		expect(await harness.repository.getActive("email")).toMatchObject({
			configured: true,
			config: cloudflareEmailConfig,
		});
	});

	it("normalizes legacy Resend rows staged without the provider discriminator", async () => {
		const harness = makeRepository();
		await harness.waitForInitialization();
		const legacyEmail = {
			apiKey: `re_${"g".repeat(36)}`,
			from: "CinaSeek <no-reply@cinaseek.ai>",
		};
		const legacyShape = legacyEmail as unknown as EmailProviderConfig;

		const staged = await harness.repository.stage({
			provider: "email",
			config: legacyShape,
			expectedVersion: 0,
			idempotencyKey: "stage-email-lg01",
		});
		expect(staged).toMatchObject({ ok: true });
		const prepared = await harness.repository.prepareTest({
			provider: "email",
			target: "owner@example.test",
			expectedVersion: 1,
			idempotencyKey: "test-email-lg01",
		});
		expect(prepared).toMatchObject({
			ok: true,
			value: {
				kind: "ready",
				config: { provider: "resend", ...legacyEmail },
			},
		});
		if (!prepared.ok || prepared.value.kind !== "ready") {
			throw new Error("test preparation failed");
		}
		await harness.repository.completeTest({
			provider: "email",
			version: staged.ok ? (staged.value.version ?? 1) : 1,
			idempotencyKey: "test-email-lg01",
			operationToken: prepared.value.operationToken,
		});
		await harness.repository.activate({
			provider: "email",
			expectedVersion: 2,
			idempotencyKey: "activate-email-lg01",
		});
		expect(await harness.repository.getActive("email")).toMatchObject({
			configured: true,
			config: { provider: "resend", ...legacyEmail },
		});
	});

	it("encrypts write-only NEXT values and refuses activation before a successful test", async () => {
		const harness = makeRepository();
		await harness.waitForInitialization();

		const staged = await harness.repository.stage({
			provider: "email",
			config: emailConfig,
			expectedVersion: 0,
			idempotencyKey: "stage-email-0001",
		});
		expect(staged).toMatchObject({
			ok: true,
			value: {
				operation: "stage",
				revision: 1,
				version: 1,
				validated: false,
			},
		});
		expect(JSON.stringify(staged)).not.toContain(emailConfig.apiKey);
		expect(JSON.stringify(staged)).not.toContain(emailConfig.from);

		const persisted = harness.database
			.prepare("SELECT * FROM delivery_provider_versions")
			.all();
		expect(JSON.stringify(persisted)).not.toContain(emailConfig.apiKey);
		expect(JSON.stringify(persisted)).not.toContain(emailConfig.from);

		if (!staged.ok || staged.value.version === null) {
			throw new Error("stage failed");
		}
		await expect(
			harness.repository.activate({
				provider: "email",
				expectedVersion: 1,
				idempotencyKey: "activate-email-0001",
			}),
		).resolves.toMatchObject({
			ok: false,
			code: "next_not_tested",
			currentVersion: 1,
		});
	});

	it("uses optimistic revision and idempotency without duplicating a stage", async () => {
		const harness = makeRepository();
		await harness.waitForInitialization();
		const operation = {
			provider: "sms" as const,
			config: smsConfig,
			expectedVersion: 0,
			idempotencyKey: "stage-sms-0001",
		};

		const first = await harness.repository.stage(operation);
		const retried = await harness.repository.stage(operation);
		expect(retried).toEqual(first);
		expect((await harness.repository.status()).revision).toBe(1);

		await expect(
			harness.repository.stage({
				...operation,
				config: { ...smsConfig, from: "+14155550124" },
			}),
		).resolves.toMatchObject({
			ok: false,
			code: "idempotency_conflict",
			currentVersion: 1,
		});
		await expect(
			harness.repository.stage({
				...operation,
				idempotencyKey: "stage-sms-0002",
			}),
		).resolves.toMatchObject({
			ok: false,
			code: "revision_conflict",
			currentVersion: 1,
		});
	});

	it("marks only the current NEXT as tested, activates it, and rolls back atomically", async () => {
		const harness = makeRepository();
		await harness.waitForInitialization();
		const staged = await harness.repository.stage({
			provider: "email",
			config: emailConfig,
			expectedVersion: 0,
			idempotencyKey: "stage-email-1001",
		});
		if (!staged.ok || staged.value.version === null) {
			throw new Error("stage failed");
		}

		const prepared = await harness.repository.prepareTest({
			provider: "email",
			target: "owner@example.test",
			expectedVersion: 1,
			idempotencyKey: "test-email-1001",
		});
		expect(prepared).toMatchObject({
			ok: true,
			value: { kind: "ready", config: emailConfig },
		});
		if (!prepared.ok || prepared.value.kind !== "ready") {
			throw new Error("test preparation failed");
		}
		const tested = await harness.repository.completeTest({
			provider: "email",
			version: staged.value.version,
			idempotencyKey: "test-email-1001",
			operationToken: prepared.value.operationToken,
		});
		expect(tested).toMatchObject({ ok: true, value: { revision: 2 } });

		const activated = await harness.repository.activate({
			provider: "email",
			expectedVersion: 2,
			idempotencyKey: "activate-email-1001",
		});
		expect(activated).toMatchObject({
			ok: true,
			value: {
				operation: "activate",
				revision: 3,
				version: staged.value.version,
				validated: true,
			},
		});
		expect(await harness.repository.getActive("email")).toMatchObject({
			configured: true,
			version: staged.value.version,
			config: emailConfig,
		});

		const replacement = await harness.repository.stage({
			provider: "email",
			config: { ...emailConfig, apiKey: `re_${"d".repeat(36)}` },
			expectedVersion: 3,
			idempotencyKey: "stage-email-1002",
		});
		if (!replacement.ok || replacement.value.version === null) {
			throw new Error("replacement stage failed");
		}
		const preparedReplacement = await harness.repository.prepareTest({
			provider: "email",
			target: "owner@example.test",
			expectedVersion: 4,
			idempotencyKey: "test-email-1002",
		});
		if (!preparedReplacement.ok || preparedReplacement.value.kind !== "ready") {
			throw new Error("replacement test preparation failed");
		}
		await harness.repository.completeTest({
			provider: "email",
			version: replacement.value.version,
			idempotencyKey: "test-email-1002",
			operationToken: preparedReplacement.value.operationToken,
		});
		await harness.repository.activate({
			provider: "email",
			expectedVersion: 5,
			idempotencyKey: "activate-email-1002",
		});

		const rolledBack = await harness.repository.rollback({
			provider: "email",
			expectedVersion: 6,
			idempotencyKey: "rollback-email-1001",
		});
		expect(rolledBack).toMatchObject({
			ok: true,
			value: {
				operation: "rollback",
				revision: 7,
				version: staged.value.version,
				validated: true,
			},
		});
	});
});

import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ErasureConfigDurableObject } from "../src/configuration-do";
import type { PrivacyErasureEnv } from "../src/env";
import worker from "../src/index";
import { signBody } from "../src/protocol";

const managementSecret = `test-management-${"m".repeat(40)}`;
const storageSecret = `test-storage-${"s".repeat(40)}`;
const encryptionKey = `test-config-kek-${"k".repeat(48)}`;
const allowedHosts = "commerce.example.test,support.example.test";

const plainSha256 = async (value: string) => {
	const digest = new Uint8Array(
		await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
	);
	let binary = "";
	for (const byte of digest) binary += String.fromCharCode(byte);
	return btoa(binary)
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replace(/=+$/, "");
};

const createManagementHeaders = async (
	body: string,
	nonce: string,
	timestamp = Math.floor(Date.now() / 1000),
) => {
	const timestampValue = String(timestamp);
	return {
		"Content-Type": "application/json",
		"X-CinaAuth-Nonce": nonce,
		"X-CinaAuth-Timestamp": timestampValue,
		"X-CinaAuth-Signature": `v1=${await signBody(
			`${timestampValue}.${nonce}.${body}`,
			managementSecret,
		)}`,
	};
};

type SqlValue = ArrayBuffer | string | number | null;
type SqlRow = Record<string, SqlValue>;

const createSqlState = () => {
	const database = new Database(":memory:");
	let initialization = Promise.resolve();
	const sql = {
		exec<T extends SqlRow>(query: string, ...bindings: unknown[]) {
			const normalized = query.trim().toUpperCase();
			let rows: T[] = [];
			if (bindings.length === 0 && !normalized.startsWith("SELECT")) {
				database.exec(query);
			} else {
				const statement = database.prepare(query);
				if (statement.reader) rows = statement.all(...bindings) as T[];
				else statement.run(...bindings);
			}
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
	const state = {
		storage: { sql },
		blockConcurrencyWhile<T>(callback: () => Promise<T>) {
			const current = callback();
			initialization = current.then(() => undefined);
			return current;
		},
	};
	return {
		database,
		state: state as DurableObjectState,
		waitForInitialization: () => initialization,
	};
};

const createConfigHarness = (configKek = encryptionKey) => {
	const sql = createSqlState();
	const env = {
		CINAAUTH_ERASURE_CONFIG_KEK_STORE: {
			get: vi.fn(async () => configKek),
		},
		CINAAUTH_ERASURE_ALLOWED_HOSTS: allowedHosts,
	} as unknown as PrivacyErasureEnv;
	const object = new ErasureConfigDurableObject(sql.state, env);
	return {
		database: sql.database,
		state: sql.state,
		waitForInitialization: sql.waitForInitialization,
		env,
		object,
	};
};

const targets = [
	{
		id: "support-system",
		url: "https://support.example.test/privacy/erase?tenant=cinaseek",
		secret: `test-support-${"a".repeat(40)}`,
	},
	{
		id: "commerce-system",
		url: "https://commerce.example.test/privacy/erase",
		secret: `test-commerce-${"b".repeat(40)}`,
	},
];

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("encrypted privacy erasure configuration", () => {
	it("stores only encrypted target material and exposes redacted status", async () => {
		const harness = createConfigHarness();
		await harness.waitForInitialization();
		const staged = await harness.object.stage({
			expectedVersion: 0,
			idempotencyKey: "stage-000000000001",
			targets,
		});
		const replayed = await harness.object.stage({
			expectedVersion: 0,
			idempotencyKey: "stage-000000000001",
			targets,
		});

		expect(staged.revision).toBe(1);
		expect(replayed).toEqual(staged);
		expect(staged.next).toMatchObject({
			version: 1,
			targetIds: ["commerce-system", "support-system"],
			targetCount: 2,
			configured: true,
			validated: false,
		});
		expect(JSON.stringify(staged)).not.toContain("example.test");
		expect(JSON.stringify(staged)).not.toContain("test-support");

		const stored = JSON.stringify(
			harness.database.prepare("SELECT * FROM config_versions").all(),
		);
		expect(stored).not.toContain("example.test");
		expect(stored).not.toContain("test-support");
		expect(stored).not.toContain("tenant=cinaseek");

		const idempotency = harness.database
			.prepare(
				"SELECT request_hash FROM config_idempotency WHERE idempotency_key = ?",
			)
			.get("stage-000000000001") as { request_hash: string };
		const normalizedTargets = [...targets].sort((left, right) =>
			left.id.localeCompare(right.id),
		);
		const offlineDigest = await plainSha256(
			JSON.stringify({
				action: "stage",
				expectedVersion: 0,
				targets: normalizedTargets,
			}),
		);
		expect(idempotency.request_hash).not.toBe(offlineDigest);
		expect(JSON.stringify(idempotency)).not.toContain(encryptionKey);

		const alternateKey = createConfigHarness(
			`test-config-kek-${"z".repeat(48)}`,
		);
		await alternateKey.waitForInitialization();
		await alternateKey.object.stage({
			expectedVersion: 0,
			idempotencyKey: "stage-000000000001",
			targets,
		});
		const alternateDigest = alternateKey.database
			.prepare(
				"SELECT request_hash FROM config_idempotency WHERE idempotency_key = ?",
			)
			.pluck()
			.get("stage-000000000001") as string;
		expect(alternateDigest).not.toBe(idempotency.request_hash);

		await expect(
			harness.object.stage({
				expectedVersion: 0,
				idempotencyKey: "stage-000000000001",
				targets: [targets[0]!],
			}),
		).rejects.toMatchObject({
			code: "IDEMPOTENCY_KEY_CONFLICT",
			status: 409,
		});
	});

	it("purges legacy unkeyed idempotency digests during migration", async () => {
		const harness = createConfigHarness();
		await harness.waitForInitialization();
		harness.database
			.prepare("DELETE FROM _config_schema_migrations WHERE id = 2")
			.run();
		harness.database
			.prepare(
				`INSERT INTO config_idempotency (
					idempotency_key, action, request_hash, response_json, created_at
				 ) VALUES (?, ?, ?, ?, ?)`,
			)
			.run(
				"legacy-stage-0001",
				"stage",
				await plainSha256("legacy payload containing secret material"),
				JSON.stringify({ revision: 1 }),
				new Date().toISOString(),
			);

		new ErasureConfigDurableObject(harness.state, harness.env);
		await harness.waitForInitialization();
		expect(
			harness.database
				.prepare("SELECT COUNT(*) FROM config_idempotency")
				.pluck()
				.get(),
		).toBe(0);
		expect(
			harness.database
				.prepare("SELECT MAX(id) FROM _config_schema_migrations")
				.pluck()
				.get(),
		).toBe(2);
	});

	it("rejects empty allow-lists, private addresses, and optimistic conflicts", async () => {
		const emptyAllowList = createConfigHarness();
		emptyAllowList.env.CINAAUTH_ERASURE_ALLOWED_HOSTS = "";
		await emptyAllowList.waitForInitialization();
		await expect(
			emptyAllowList.object.stage({
				expectedVersion: 0,
				idempotencyKey: "stage-000000000002",
				targets,
			}),
		).rejects.toMatchObject({ code: "TARGET_HOST_NOT_ALLOWED", status: 400 });

		const privateAddress = createConfigHarness();
		await privateAddress.waitForInitialization();
		await expect(
			privateAddress.object.stage({
				expectedVersion: 0,
				idempotencyKey: "stage-000000000003",
				targets: [
					{
						id: "private-target",
						url: "https://127.0.0.1/privacy/erase",
						secret: "x".repeat(40),
					},
				],
			}),
		).rejects.toMatchObject({ code: "INVALID_TARGET", status: 400 });

		const harness = createConfigHarness();
		await harness.waitForInitialization();
		await harness.object.stage({
			expectedVersion: 0,
			idempotencyKey: "stage-000000000004",
			targets,
		});
		await expect(
			harness.object.stage({
				expectedVersion: 0,
				idempotencyKey: "stage-000000000005",
				targets,
			}),
		).rejects.toMatchObject({ code: "CONFIG_VERSION_CONFLICT", status: 409 });
	});

	it("requires a signed readiness handshake before activate and supports rollback", async () => {
		const harness = createConfigHarness();
		await harness.waitForInitialization();
		await harness.object.stage({
			expectedVersion: 0,
			idempotencyKey: "stage-000000000006",
			targets,
		});

		await expect(
			harness.object.activate({
				expectedVersion: 1,
				idempotencyKey: "activate-00000001",
			}),
		).rejects.toMatchObject({ code: "NEXT_CONFIG_NOT_VALIDATED", status: 409 });

		vi.stubGlobal(
			"fetch",
			vi.fn(async () =>
				Response.json({
					schemaVersion: 1,
					action: "erasure-target-ready",
					challengeId: "not-the-issued-challenge",
					targetId: "support-system",
					ready: true,
					respondedAt: new Date().toISOString(),
				}),
			),
		);
		await expect(
			harness.object.test({
				expectedVersion: 1,
				idempotencyKey: "test-failed-000001",
			}),
		).rejects.toMatchObject({ code: "TARGET_VALIDATION_FAILED", status: 503 });
		expect((await harness.object.status()).revision).toBe(1);

		vi.stubGlobal(
			"fetch",
			vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
				const request = JSON.parse(String(init?.body)) as {
					action: string;
					challengeId: string;
					targetId: string;
				};
				expect(request.action).toBe("verify-erasure-target");
				const body = JSON.stringify({
					schemaVersion: 1,
					action: "erasure-target-ready",
					challengeId: request.challengeId,
					targetId: request.targetId,
					ready: true,
					respondedAt: new Date().toISOString(),
				});
				const target = targets.find(({ id }) => id === request.targetId);
				return new Response(body, {
					headers: {
						"Content-Type": "application/json",
						"X-CinaAuth-Signature": `v1=${await signBody(
							body,
							target?.secret ?? "",
						)}`,
					},
				});
			}),
		);

		const tested = await harness.object.test({
			expectedVersion: 1,
			idempotencyKey: "test-000000000001",
		});
		expect(tested.next?.validated).toBe(true);
		const activated = await harness.object.activate({
			expectedVersion: 2,
			idempotencyKey: "activate-00000002",
		});
		expect(activated.operationalReady).toBe(true);
		expect(activated.active?.version).toBe(1);

		await harness.object.stage({
			expectedVersion: 3,
			idempotencyKey: "stage-000000000007",
			targets: [targets[0]!],
		});
		await harness.object.test({
			expectedVersion: 4,
			idempotencyKey: "test-000000000002",
		});
		const second = await harness.object.activate({
			expectedVersion: 5,
			idempotencyKey: "activate-00000003",
		});
		expect(second.active?.version).toBe(2);
		expect(second.previous?.version).toBe(1);

		const rolledBack = await harness.object.rollback({
			expectedVersion: 6,
			idempotencyKey: "rollback-00000001",
		});
		expect(rolledBack.active?.version).toBe(1);
		expect(rolledBack.previous?.version).toBe(2);
	});
});

describe("privacy configuration management HTTP contract", () => {
	it("requires exact-body HMAC and never returns target material", async () => {
		const harness = createConfigHarness();
		await harness.waitForInitialization();
		const configNamespace = {
			getByName: () => harness.object,
		} as unknown as DurableObjectNamespace<ErasureConfigDurableObject>;
		const env = {
			...harness.env,
			CINAAUTH_ERASURE_WEBHOOK_SECRET: managementSecret,
			CINAAUTH_ERASURE_STORAGE_SECRET: storageSecret,
			CINAAUTH_ERASURE_TARGETS: "[]",
			CINAAUTH_ERASURE_WEBHOOK_SECRET_STORE_V2: {
				get: vi.fn(async () => managementSecret),
			},
			ERASURE_CONFIG: configNamespace,
			VERSION_METADATA: {
				id: "test-worker-version",
				tag: "test",
				timestamp: "2026-08-10T00:00:00.000Z",
			},
		} as unknown as PrivacyErasureEnv;
		const body = JSON.stringify({ schemaVersion: 1, action: "status" });
		const staleTimestamp = Math.floor(Date.now() / 1000) - 86_400;
		const stale = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/status",
				{
					method: "POST",
					headers: await createManagementHeaders(
						body,
						"stale-status-0001",
						staleTimestamp,
					),
					body,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(stale.status).toBe(401);
		expect(await stale.json()).toMatchObject({ code: "STALE_SIGNATURE" });
		const unsigned = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/status",
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(unsigned.status).toBe(401);

		const statusHeaders = await createManagementHeaders(
			body,
			"status-request-0001",
		);
		const response = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/status",
				{
					method: "POST",
					headers: statusHeaders,
					body,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(response.status).toBe(200);
		expect(response.headers.get("cache-control")).toBe("no-store");
		const text = await response.text();
		const statusResult = JSON.parse(text) as Record<string, unknown>;
		expect(Object.keys(statusResult).sort()).toEqual(
			[
				"revision",
				"structuralReady",
				"operationalReady",
				"source",
				"active",
				"next",
				"previous",
			].sort(),
		);
		expect(text).not.toContain("example.test");
		expect(text).not.toContain("secret");

		const bodyTamper = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/status",
				{
					method: "POST",
					headers: statusHeaders,
					body: `${body} `,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(bodyTamper.status).toBe(401);
		expect(await bodyTamper.json()).toMatchObject({
			code: "INVALID_SIGNATURE",
		});

		const nonceTamperHeaders = new Headers(statusHeaders);
		nonceTamperHeaders.set("X-CinaAuth-Nonce", "status-request-0002");
		const nonceTamper = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/status",
				{
					method: "POST",
					headers: nonceTamperHeaders,
					body,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(nonceTamper.status).toBe(401);
		expect(await nonceTamper.json()).toMatchObject({
			code: "INVALID_SIGNATURE",
		});

		const stageBody = JSON.stringify({
			schemaVersion: 1,
			action: "stage",
			expectedVersion: 0,
			idempotencyKey: "http-stage-0000001",
			targets,
		});
		const stageHeaders = await createManagementHeaders(
			stageBody,
			"http-stage-0000001",
		);
		const stageResponse = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/stage",
				{
					method: "POST",
					headers: stageHeaders,
					body: stageBody,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(stageResponse.status).toBe(200);
		const stageText = await stageResponse.text();
		const stageResult = JSON.parse(stageText) as Record<string, unknown>;
		expect(Object.keys(stageResult).sort()).toEqual(
			["operation", "revision", "updatedAt", "validated", "version"].sort(),
		);
		expect(stageResult).toMatchObject({
			operation: "stage",
			revision: 1,
			version: 1,
			validated: false,
		});
		expect(stageText).not.toContain("example.test");
		expect(stageText).not.toContain("tenant=cinaseek");
		expect(stageText).not.toContain("test-support");

		const replayedStage = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/stage",
				{
					method: "POST",
					headers: stageHeaders,
					body: stageBody,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(replayedStage.status).toBe(200);
		expect(await replayedStage.json()).toEqual(stageResult);

		const mismatchedNonce = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/stage",
				{
					method: "POST",
					headers: await createManagementHeaders(
						stageBody,
						"different-nonce-0001",
					),
					body: stageBody,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(mismatchedNonce.status).toBe(400);
		expect(await mismatchedNonce.json()).toMatchObject({
			code: "INVALID_CONFIG_REQUEST",
		});

		const activateWithoutConfirmation = JSON.stringify({
			schemaVersion: 1,
			action: "activate",
			expectedVersion: 1,
			idempotencyKey: "http-activate-0001",
		});
		const rejectedActivate = await worker.fetch(
			new Request(
				"https://cinaauth-erasure.cinagroup.com/internal/config/erasure/activate",
				{
					method: "POST",
					headers: await createManagementHeaders(
						activateWithoutConfirmation,
						"http-activate-0001",
					),
					body: activateWithoutConfirmation,
				},
			),
			env,
			{} as ExecutionContext,
		);
		expect(rejectedActivate.status).toBe(400);
		expect(await rejectedActivate.json()).toMatchObject({
			code: "INVALID_CONFIG_REQUEST",
		});
	});
});

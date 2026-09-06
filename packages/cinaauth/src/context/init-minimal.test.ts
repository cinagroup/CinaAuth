import type { CinaAuthOptions } from "@cinaauth/core";
import { registerSchemaCheck } from "@cinaauth/core/db/internal";
import { memoryAdapter } from "@cinaauth/memory-adapter";
import { describe, expect, it } from "vitest";
import { initMinimal } from "./init-minimal";

describe("init-minimal (without Kysely)", () => {
	const db: Record<string, any[]> = {};

	it("should initialize without Kysely dependencies", async () => {
		const res = await initMinimal({
			baseURL: "http://localhost:3000",
			database: memoryAdapter(db),
		});

		expect(res).toBeDefined();
		expect(res.adapter.id).toBe("memory");
		expect(res.adapter.options?.type).toBeUndefined();
	});

	it("should throw error when attempting to run migrations", async () => {
		const res = await initMinimal({
			baseURL: "http://localhost:3000",
			database: memoryAdapter(db),
		});

		await expect(res.runMigrations()).rejects.toThrow(
			"Migrations are not supported in 'cinaauth/minimal'",
		);
	});

	it("should work with non-Kysely adapters like memory adapter", async () => {
		const customDb: Record<string, any[]> = {
			users: [],
			sessions: [],
		};

		const res = await initMinimal({
			baseURL: "http://localhost:3000",
			database: memoryAdapter(customDb),
		});

		expect(res.adapter.id).toBe("memory");
		expect(res.adapter.options?.type).toBeUndefined();
	});

	it("exposes the schema check an adapter registers", async () => {
		const check = () => undefined;
		const database = (options: CinaAuthOptions) => {
			const adapter = memoryAdapter({})(options);
			registerSchemaCheck(adapter, check);
			return adapter;
		};
		const res = await initMinimal({
			baseURL: "http://localhost:3000",
			database,
		});
		expect(res.checkSchema).toBe(check);
	});
});

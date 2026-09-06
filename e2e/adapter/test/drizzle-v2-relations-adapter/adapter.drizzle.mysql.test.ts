import { execSync } from "node:child_process";
import { drizzleAdapter } from "@cinaauth/drizzle-adapter/relations-v2";
import { testAdapter } from "@cinaauth/test-utils/adapter";
import { drizzle } from "drizzle-orm/mysql2";
import { createPool } from "mysql2/promise";
import { assert } from "vitest";
import {
	authFlowTestSuite,
	caseInsensitiveTestSuite,
	joinsTestSuite,
	normalTestSuite,
	numberIdTestSuite,
	transactionsTestSuite,
	uuidTestSuite,
} from "../adapter-factory";
import { generateDrizzleSchema, resetGenerationCount } from "./generate-schema";

const dbName = "cinaauth";
const mysqlDB = createPool({
	uri: `mysql://user:password@127.0.0.1:3306/${dbName}`,
	timezone: "Z",
});

const { execute } = await testAdapter({
	adapter: async (options) => {
		const { schema } = await generateDrizzleSchema(mysqlDB, options, "mysql");
		const { authRelations: relations, ...schema1 } = schema;
		const drizzleI2 = drizzle<typeof relations>({
			client: mysqlDB,
			relations,
		});
		return drizzleAdapter(drizzleI2, {
			debugLogs: { isRunningAdapterTests: true },
			schema: { ...schema1, relations },
			provider: "mysql",
		});
	},
	async runMigrations(CinaAuthOptions) {
		await mysqlDB.query(`DROP DATABASE IF EXISTS ${dbName}`);
		await mysqlDB.query(`CREATE DATABASE IF NOT EXISTS ${dbName}`);
		await mysqlDB.query(`USE ${dbName}`);

		const { fileName } = await generateDrizzleSchema(
			mysqlDB,
			CinaAuthOptions,
			"mysql",
		);

		const command = `pnpm exec drizzle-kit push --dialect=mysql --schema=${fileName}.ts --url=mysql://user:password@localhost:3306/${dbName}`;
		console.log(`Running: ${command}`);
		console.log(`Options:`, CinaAuthOptions);
		try {
			// wait for the above console.log to be printed
			await new Promise((resolve) => setTimeout(resolve, 10));
			execSync(command, {
				cwd: import.meta.dirname,
				stdio: "inherit",
			});
		} catch (error) {
			console.error("Failed to push drizzle schema (mysql):", error);
			throw error;
		}

		// ensure migrations were run successfully
		const [tables_result] = (await mysqlDB.query("SHOW TABLES")) as unknown as [
			{ Tables_in_cinaauth: string }[],
		];
		const tables = tables_result.map((table) => table.Tables_in_cinaauth);
		assert(tables.length > 0, "No tables found");
	},
	prefixTests: "mysql",
	tests: [
		normalTestSuite(),
		transactionsTestSuite(),
		authFlowTestSuite(),
		numberIdTestSuite(),
		joinsTestSuite(),
		uuidTestSuite(),
		caseInsensitiveTestSuite({
			disableTests: {
				"findOne - eq with mode sensitive (default) should not match different case": true,
			},
		}),
	],
	async onFinish() {
		await mysqlDB.end();
		resetGenerationCount();
	},
});

execute();

import type { CinaAuthOptions, CinaAuthPlugin } from "@cinaauth/core";
import { kyselyAdapter } from "@cinaauth/kysely-adapter";
import { createTestSuite, testAdapter } from "@cinaauth/test-utils/adapter";
import { getMigrations } from "cinaauth/db/migration";
import { Kysely, MysqlDialect } from "kysely";
import { createPool } from "mysql2/promise";
import { assert, expect } from "vitest";
import {
	authFlowTestSuite,
	caseInsensitiveTestSuite,
	joinsTestSuite,
	normalTestSuite,
	numberIdTestSuite,
	transactionsTestSuite,
	uuidTestSuite,
} from "../adapter-factory";
import { compoundIndexTestSuite } from "../adapter-factory/compound-index-test-suite";

const mysqlDB = createPool({
	uri: "mysql://user:password@localhost:3307/cinaauth",
	timezone: "Z",
});

const kyselyDB = new Kysely({
	dialect: new MysqlDialect(mysqlDB),
});

const mysqlDisabledIndexTestSuite = createTestSuite(
	"mysql migration index introspection",
	{},
	() => ({
		/**
		 * @see https://dev.mysql.com/doc/refman/8.4/en/alter-table.html
		 */
		"rejects a disabled MyISAM index": async () => {
			const tableName = "mysql_disabled_index_subject";
			const indexName = "mysql_disabled_subject_idx";
			const options = {
				database: mysqlDB,
				plugins: [
					{
						id: "mysql-disabled-index",
						schema: {
							mysqlDisabledIndexSubject: {
								modelName: tableName,
								fields: {
									subject: { type: "string" },
								},
								indexes: [{ fields: ["subject"], name: indexName }],
							},
						},
					} satisfies CinaAuthPlugin,
				],
			} satisfies CinaAuthOptions;

			await mysqlDB.query(`
				CREATE TABLE \`${tableName}\` (
					\`id\` varchar(191) NOT NULL,
					\`subject\` varchar(191) NOT NULL,
					PRIMARY KEY (\`id\`),
					INDEX \`${indexName}\` (\`subject\`)
				) ENGINE=MyISAM
			`);
			try {
				await expect(getMigrations(options)).resolves.toBeDefined();
				await mysqlDB.query(`ALTER TABLE \`${tableName}\` DISABLE KEYS`);
				await expect(getMigrations(options)).rejects.toThrow(
					`Database index "${indexName}" on table "${tableName}" does not match the configured fields and uniqueness.`,
				);
			} finally {
				await mysqlDB.query(`DROP TABLE \`${tableName}\``);
			}
		},
	}),
);

const { execute } = await testAdapter({
	adapter: () =>
		kyselyAdapter(kyselyDB, {
			type: "mysql",
			debugLogs: { isRunningAdapterTests: true },
		}),
	async runMigrations(CinaAuthOptions) {
		await mysqlDB.query("DROP DATABASE IF EXISTS cinaauth");
		await mysqlDB.query("CREATE DATABASE cinaauth");
		await mysqlDB.query("USE cinaauth");
		const opts = Object.assign(CinaAuthOptions, { database: mysqlDB });
		const { runMigrations } = await getMigrations(opts);
		await runMigrations();

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
		transactionsTestSuite({ disableTests: { ALL: true } }),
		authFlowTestSuite(),
		numberIdTestSuite(),
		joinsTestSuite(),
		uuidTestSuite(),
		mysqlDisabledIndexTestSuite(),
		caseInsensitiveTestSuite({
			disableTests: {
				"findOne - eq with mode sensitive (default) should not match different case": true,
			},
		}),
		compoundIndexTestSuite({
			async rerunMigrations(options) {
				const migrations = await getMigrations({
					...options,
					database: mysqlDB,
				});
				const pendingMigration = await migrations.compileMigrations();
				await migrations.runMigrations();
				return pendingMigration;
			},
			mismatchError:
				'Database index "compound_identity_uidx" on table "compound_index_subject" does not match the configured fields and uniqueness.',
			async verifyMismatchedIndexRejected(options) {
				await mysqlDB.query(
					"ALTER TABLE `compound_index_subject` DROP INDEX `compound_identity_uidx`",
				);
				await mysqlDB.query(
					"CREATE INDEX `compound_identity_uidx` ON `compound_index_subject` (`provider_subject`)",
				);
				try {
					await getMigrations({ ...options, database: mysqlDB });
				} finally {
					await mysqlDB.query(
						"ALTER TABLE `compound_index_subject` DROP INDEX `compound_identity_uidx`",
					);
					await mysqlDB.query(
						"CREATE UNIQUE INDEX `compound_identity_uidx` ON `compound_index_subject` (`issuer_url`, `provider_subject`)",
					);
				}
			},
		}),
	],
	async onFinish() {
		await mysqlDB.end();
	},
});
execute();

import type { CinaAuthOptions } from "@cinaauth/core";
import { createTestSuite } from "@cinaauth/test-utils/adapter";
import { getNormalTestSuiteTests } from "../adapter-factory";

export const DEFAULT_SCHEMA_REFERENCE = "internal";

const DEFAULT_CINAAUTH_OPTIONS: CinaAuthOptions = {
	user: {
		modelName: `${DEFAULT_SCHEMA_REFERENCE}.users`,
	},
	session: {
		modelName: `${DEFAULT_SCHEMA_REFERENCE}.sessions`,
	},
	account: {
		modelName: `${DEFAULT_SCHEMA_REFERENCE}.accounts`,
	},
};

/**
 * This tests using schema references for the models.
 * For example, users can modify table names to use something like `public.user` instead of just a plain `user`.
 */
export const schemaRefTestSuite = createTestSuite(
	"schema-reference",
	{
		defaultCinaAuthOptions: DEFAULT_CINAAUTH_OPTIONS,
		alwaysMigrate: true,
		prefixTests: "schema-reference",
	},
	(helpers) => {
		const {
			"findOne - should find a model with modified model name": _,
			...tests
		} = getNormalTestSuiteTests(helpers);
		return tests;
	},
);

/**
 * Same as the normal standard notation test suite, but with joins enabled.
 */
export const schemaRefJoinTestSuite = createTestSuite(
	"schema-reference-join",
	{
		defaultCinaAuthOptions: {
			...DEFAULT_CINAAUTH_OPTIONS,
			advanced: {
				database: {
					joins: true,
				},
			},
		},
		alwaysMigrate: true,
		prefixTests: "schema-reference-join",
	},
	(helpers) => {
		const {
			"findOne - should find a model with modified model name": _,
			...tests
		} = getNormalTestSuiteTests(helpers);
		return tests;
	},
);

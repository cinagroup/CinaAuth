import type { CinaAuthOptions } from "@cinaauth/core";
import type { DBAdapter } from "@cinaauth/core/db/adapter";

export interface SchemaGeneratorResult {
	code?: string;
	fileName: string;
	overwrite?: boolean;
	append?: boolean;
	/**
	 * Schema changes the generated code contains but no database can apply
	 * without corrupting the rows it already holds.
	 */
	unsafeChanges?: string[];
	/**
	 * Columns the database requires that CinaAuth never writes. No generated
	 * migration removes them; each entry names the change that does.
	 */
	schemaProblems?: string[];
}

export interface SchemaGenerator {
	<Options extends CinaAuthOptions>(opts: {
		file?: string;
		adapter: DBAdapter;
		options: Options;
	}): Promise<SchemaGeneratorResult>;
}

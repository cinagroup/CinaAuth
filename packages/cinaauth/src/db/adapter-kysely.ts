import type { CinaAuthOptions } from "@cinaauth/core";
import type { DBAdapter } from "@cinaauth/core/db/adapter";
import { CinaAuthError } from "@cinaauth/core/error";
import { getBaseAdapter } from "./adapter-base";

export async function getAdapter(
	options: CinaAuthOptions,
): Promise<DBAdapter<CinaAuthOptions>> {
	return getBaseAdapter(options, async (opts) => {
		const { createKyselyAdapter, kyselyAdapter } = await import(
			"../adapters/kysely-adapter"
		);
		const { kysely, databaseType, transaction } =
			await createKyselyAdapter(opts);
		if (!kysely) {
			throw new CinaAuthError("Failed to initialize database adapter");
		}
		return kyselyAdapter(kysely, {
			type: databaseType || "sqlite",
			debugLogs:
				opts.database && "debugLogs" in opts.database
					? opts.database.debugLogs
					: false,
			transaction,
		})(opts);
	});
}

import { DatabaseSync } from "node:sqlite";
import { CinaAuth } from "cinaauth";
import { getMigrations } from "cinaauth/db/migration";

const database = new DatabaseSync(":memory:");

export const auth = CinaAuth({
	database,
	emailAndPassword: {
		enabled: true,
	},
	trustedOrigins: ["http://localhost:*"],
	logger: {
		level: "debug",
	},
});

const { runMigrations } = await getMigrations(auth.options);

await runMigrations();

// Deno: `deno serve` (Deno 1.43+) auto-mounts the default export's `fetch`
// handler. No explicit Deno.serve call needed.
// https://docs.deno.com/runtime/reference/cli/serve
export default auth;

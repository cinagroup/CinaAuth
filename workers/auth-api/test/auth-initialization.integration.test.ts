import { readFileSync } from "node:fs";
import { CinaAuth } from "cinaauth";
import { getMigrations } from "cinaauth/db/migration";
import { getTestInstance } from "cinaauth/test";
import { describe, expect, it } from "vitest";
import type { CloudflareBindings } from "../src/env";
import { createAuthPlugins } from "../src/plugins";
import { makeOriginEnv } from "./origin-test-env";

const productionConfig = JSON.parse(
	readFileSync(new URL("../wrangler.json", import.meta.url), "utf8"),
) as { vars: Partial<CloudflareBindings> };
const env = makeOriginEnv({
	...productionConfig.vars,
	CINAAUTH_SECRET:
		"production-initialization-test-secret-at-least-32-characters",
	STRIPE_SECRET_KEY: "sk_test_initialization",
	STRIPE_WEBHOOK_SECRET: "whsec_initialization",
});

/** @see https://www.better-auth.com/docs/guides/1-7-upgrade-guide */
describe("production Auth initialization", () => {
	it("serves issuer discovery with the complete production plugin composition", async () => {
		const { auth } = await getTestInstance(
			{
				baseURL: env.CINAAUTH_URL,
				secret: env.CINAAUTH_SECRET,
				plugins: createAuthPlugins(env, { advancedOrganization: true }),
				session: {
					freshAge: 15 * 60,
					cookieCache: { enabled: true, maxAge: 300 },
				},
			},
			{ disableTestUser: true },
		);
		const response = await auth.handler(
			new Request(`${env.CINAAUTH_URL}/.well-known/openid-configuration`),
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			issuer: env.CINAAUTH_URL,
			jwks_uri: `${env.CINAAUTH_URL}/api/auth/jwks`,
		});
	});

	it("upgrades existing team tables before serving authentication requests", async () => {
		const plugins = createAuthPlugins(env, { advancedOrganization: true });
		const legacyPlugins = plugins.map((plugin) => {
			if (plugin.id !== "organization" || !plugin.schema) return plugin;
			const { memberCount: _memberCount, ...teamFields } =
				plugin.schema.team!.fields;
			const { membershipKey: _membershipKey, ...memberFields } =
				plugin.schema.teamMember!.fields;
			return {
				...plugin,
				schema: {
					...plugin.schema,
					team: { ...plugin.schema.team!, fields: teamFields },
					teamMember: { ...plugin.schema.teamMember!, fields: memberFields },
				},
			};
		});
		const { auth: legacyAuth } = await getTestInstance(
			{
				baseURL: env.CINAAUTH_URL,
				secret: env.CINAAUTH_SECRET,
				plugins: legacyPlugins,
				logger: { disabled: true },
			},
			{ disableTestUser: true },
		);
		const options = { ...legacyAuth.options, plugins };
		const auth = CinaAuth(options);
		const request = () =>
			new Request(`${env.CINAAUTH_URL}/.well-known/openid-configuration`);
		await expect(auth.handler(request())).rejects.toThrow(
			/team\.memberCount[\s\S]*teamMember\.membershipKey/,
		);
		const migrations = await getMigrations(options);
		expect(migrations.toBeAdded.map(({ table }) => table).sort()).toEqual([
			"team",
			"teamMember",
		]);
		await migrations.runMigrations();
		const response = await auth.handler(request());
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ issuer: env.CINAAUTH_URL });
	});
});

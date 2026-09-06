import type { CinaAuthOptions, CinaAuthPlugin } from "@cinaauth/core";
import { createTestSuite } from "@cinaauth/test-utils/adapter";
import { expect } from "vitest";

const compoundIndexName = "compound_identity_uidx";
const compoundIndexTableName = "compound_index_subject";

const compoundIndexCinaAuthOptions = {
	plugins: [
		{
			id: "compound-index-workflow",
			schema: {
				compoundIndexSubject: {
					modelName: compoundIndexTableName,
					fields: {
						issuer: {
							type: "string",
							fieldName: "issuer_url",
						},
						providerSubject: {
							type: "string",
							fieldName: "provider_subject",
						},
						displayName: {
							type: "string",
							fieldName: "display_name",
						},
					},
					indexes: [
						{
							fields: ["issuer", "providerSubject"],
							name: compoundIndexName,
							unique: true,
						},
					],
				},
			},
		} satisfies CinaAuthPlugin,
	],
} satisfies CinaAuthOptions;

interface CompoundIndexTestSuiteOptions {
	rerunMigrations?: ((options: CinaAuthOptions) => Promise<string>) | undefined;
	mismatchError?: RegExp | string | undefined;
	verifyIndexState?: (() => Promise<void>) | undefined;
	verifyMismatchedIndexRejected?:
		| ((options: CinaAuthOptions) => Promise<void>)
		| undefined;
}

interface CompoundIndexSubject {
	displayName: string;
	id: string;
	issuer: string;
	providerSubject: string;
}

export function compoundIndexTestSuite(
	options: CompoundIndexTestSuiteOptions = {},
) {
	return createTestSuite("compound-index", {}, ({ adapter }) => ({
		"enforces the configured tuple through the real database": {
			migrateCinaAuth: compoundIndexCinaAuthOptions,
			async test() {
				const createSubject = (
					issuer: string,
					providerSubject: string,
					displayName: string,
				) =>
					adapter.create<CompoundIndexSubject>({
						model: "compoundIndexSubject",
						data: { issuer, providerSubject, displayName },
					});

				await expect(
					Promise.all([
						createSubject("https://idp.example", "employee-1", "Ada"),
						createSubject("https://idp.example", "employee-2", "Lin"),
						createSubject("https://partner.example", "employee-1", "Kai"),
					]),
				).resolves.toHaveLength(3);

				await expect(
					createSubject("https://idp.example", "employee-1", "Duplicate"),
				).rejects.toThrow();

				if (options.rerunMigrations) {
					const pendingMigration = await options.rerunMigrations(
						compoundIndexCinaAuthOptions,
					);
					expect(pendingMigration.trim()).toBe(";");
				}

				await options.verifyIndexState?.();

				if (options.verifyMismatchedIndexRejected) {
					await expect(
						options.verifyMismatchedIndexRejected(compoundIndexCinaAuthOptions),
					).rejects.toThrow(options.mismatchError);
				}
			},
		},
	}))();
}

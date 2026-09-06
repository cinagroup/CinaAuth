import { describe, expect, it } from "vitest";
import {
	classifyChangeType,
	isMaintenanceBranch,
	mapTypeToBump,
	resolveDomain,
	resolvePackage,
} from "../src/change-classifier.ts";

describe("change classification", () => {
	it("recognizes versioned maintenance branches", () => {
		expect(isMaintenanceBranch("v1.6.x")).toBe(true);
		expect(isMaintenanceBranch("v1.6.30")).toBe(false);
		expect(isMaintenanceBranch("v1.4.x-staging")).toBe(false);
		expect(isMaintenanceBranch("release/1.6")).toBe(false);
	});

	it.each([
		["sso", "enterprise"],
		["expo", "platform"],
		["session", "core"],
		["prisma-adapter", "database"],
	])("maps the %s scope to the %s domain", (scope, domain) => {
		expect(resolveDomain(scope, [])).toBe(domain);
	});

	it.each([
		["packages/expo/src/index.ts", "platform"],
		["packages/sso/src/index.ts", "enterprise"],
		["packages/cinaauth/src/db/index.ts", "database"],
		["docs/content/docs/index.mdx", "docs"],
	])("maps %s to the %s domain", (path, domain) => {
		expect(resolveDomain(undefined, [path])).toBe(domain);
	});

	it.each([
		["expo", "@cinaauth/expo"],
		["sso", "@cinaauth/sso"],
		["cli", "auth"],
		["session", "cinaauth"],
	])("maps the %s scope to the %s package", (scope, packageName) => {
		expect(resolvePackage(scope, [])).toBe(packageName);
	});

	it("prefers a specific package over the core catch-all", () => {
		expect(
			resolvePackage(undefined, [
				"packages/cinaauth/src/index.ts",
				"packages/expo/src/index.ts",
			]),
		).toBe("@cinaauth/expo");
	});

	it("classifies semver and release-note change types", () => {
		expect(mapTypeToBump("feat", false)).toBe("minor");
		expect(mapTypeToBump("fix", false)).toBe("patch");
		expect(mapTypeToBump("docs", false)).toBe("skip");
		expect(mapTypeToBump("fix", true)).toBe("minor");

		expect(classifyChangeType("feat", false)).toBe("feat");
		expect(classifyChangeType("fix", false)).toBe("fix");
		expect(classifyChangeType("fix", true)).toBe("breaking");
	});
});

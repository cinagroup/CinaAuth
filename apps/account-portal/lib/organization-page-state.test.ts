// @vitest-environment happy-dom
import { act, createElement, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ organization: vi.fn(), session: vi.fn() }));
vi.mock("next/headers", () => ({ headers: async () => new Headers() }));
vi.mock("@/lib/auth", () => ({
	auth: {
		api: {
			getSession: mocks.session,
			listOrganizations: async () => [],
			getFullOrganization: mocks.organization,
			listOrganizationTeams: async () => [],
			listOrganizationRoles: async () => [],
			getEntitlements: async () => null,
		},
	},
}));
vi.mock("@/app/dashboard/organization/organization-console", () => ({
	OrganizationConsole: () => {
		const [secret, setSecret] = useState("");
		return createElement(
			"button",
			{ onClick: () => setSecret("one-time-credential") },
			secret || "Create credential",
		);
	},
}));

import OrganizationConsolePage from "@/app/dashboard/organization/page";

const container = document.createElement("div");
let root: ReturnType<typeof createRoot>;
const organization = (id: string) => ({
	id,
	name: id,
	slug: id,
	createdAt: new Date(),
	members: [],
	invitations: [],
});
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	mocks.session.mockResolvedValue({
		user: { id: "user-1", name: "User", email: "user@example.com" },
		session: { createdAt: new Date() },
	});
	mocks.organization.mockResolvedValue(organization("organization-1"));
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	vi.unstubAllGlobals();
});

/** @see https://react.dev/learn/preserving-and-resetting-state */
it("preserves drafts on refresh but clears tenant credentials on organization and account changes", async () => {
	await act(async () => root.render(await OrganizationConsolePage()));
	await act(async () => container.querySelector("button")?.click());
	expect(container.textContent).toBe("one-time-credential");
	await act(async () => root.render(await OrganizationConsolePage()));
	expect(container.textContent).toBe("one-time-credential");
	mocks.organization.mockResolvedValue(organization("organization-2"));
	await act(async () => root.render(await OrganizationConsolePage()));
	expect(container.textContent).toBe("Create credential");
	await act(async () => container.querySelector("button")?.click());
	mocks.session.mockResolvedValue({
		user: { id: "user-2", name: "Another user", email: "another@example.com" },
		session: { createdAt: new Date() },
	});
	await act(async () => root.render(await OrganizationConsolePage()));
	expect(container.textContent).toBe("Create credential");
	await act(async () => container.querySelector("button")?.click());
	mocks.organization.mockResolvedValue(null);
	await act(async () => root.render(await OrganizationConsolePage()));
	expect(container.textContent).toBe("Create credential");
});

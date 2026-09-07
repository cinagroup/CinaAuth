import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	$fetch: vi.fn(),
}));

vi.mock("@/lib/auth-client", () => ({
	authClient: { $fetch: mocks.$fetch },
}));

import {
	addOrganizationTeamMember,
	createOrganizationRole,
	createOrganizationTeam,
	deleteOrganizationRole,
	deleteOrganizationTeam,
	listOrganizationTeamMembers,
	removeOrganizationTeamMember,
	updateOrganizationRole,
	updateOrganizationTeam,
} from "./advanced-organization-mutations";

describe("advanced organization mutations", () => {
	beforeEach(() => {
		mocks.$fetch.mockReset();
		mocks.$fetch.mockResolvedValue({ data: { success: true }, error: null });
	});

	it("uses organization-scoped team lifecycle endpoints", async () => {
		await createOrganizationTeam({
			organizationId: "organization-1",
			name: "Platform",
		});
		await updateOrganizationTeam({
			organizationId: "organization-1",
			teamId: "team-1",
			name: "Core Platform",
		});
		await deleteOrganizationTeam({
			organizationId: "organization-1",
			teamId: "team-1",
		});

		expect(mocks.$fetch).toHaveBeenNthCalledWith(
			1,
			"/organization/create-team",
			{
				method: "POST",
				body: { organizationId: "organization-1", name: "Platform" },
			},
		);
		expect(mocks.$fetch).toHaveBeenNthCalledWith(
			2,
			"/organization/update-team",
			{
				method: "POST",
				body: {
					teamId: "team-1",
					data: { name: "Core Platform", organizationId: "organization-1" },
				},
			},
		);
		expect(mocks.$fetch).toHaveBeenNthCalledWith(
			3,
			"/organization/remove-team",
			{
				method: "POST",
				body: { organizationId: "organization-1", teamId: "team-1" },
			},
		);
	});

	it("adds and removes a stable user id from a team", async () => {
		await addOrganizationTeamMember({
			organizationId: "organization-1",
			teamId: "team-1",
			userId: "user-1",
		});
		await removeOrganizationTeamMember({
			organizationId: "organization-1",
			teamId: "team-1",
			userId: "user-1",
		});

		expect(mocks.$fetch).toHaveBeenNthCalledWith(
			1,
			"/organization/add-team-member",
			{
				method: "POST",
				body: {
					organizationId: "organization-1",
					teamId: "team-1",
					userId: "user-1",
				},
			},
		);
		expect(mocks.$fetch).toHaveBeenNthCalledWith(
			2,
			"/organization/remove-team-member",
			{
				method: "POST",
				body: {
					organizationId: "organization-1",
					teamId: "team-1",
					userId: "user-1",
				},
			},
		);
	});

	it("loads membership for one explicit team", async () => {
		mocks.$fetch.mockResolvedValue({
			data: [{ id: "membership-1", teamId: "team-1", userId: "user-1" }],
			error: null,
		});

		await expect(listOrganizationTeamMembers("team-1")).resolves.toEqual([
			{ id: "membership-1", teamId: "team-1", userId: "user-1" },
		]);
		expect(mocks.$fetch).toHaveBeenCalledWith(
			"/organization/list-team-members",
			{
				method: "GET",
				query: { teamId: "team-1" },
			},
		);
	});

	it("uses role names only for custom-role lifecycle mutations", async () => {
		await createOrganizationRole({
			organizationId: "organization-1",
			role: "support_agent",
			permission: { member: ["update"], ac: ["read"] },
		});
		await updateOrganizationRole({
			organizationId: "organization-1",
			roleName: "support_agent",
			nextRoleName: "support_lead",
			permission: { member: ["update"], ac: ["read"] },
		});
		await deleteOrganizationRole({
			organizationId: "organization-1",
			roleName: "support_lead",
		});

		expect(mocks.$fetch).toHaveBeenNthCalledWith(
			1,
			"/organization/create-role",
			{
				method: "POST",
				body: {
					organizationId: "organization-1",
					role: "support_agent",
					permission: { member: ["update"], ac: ["read"] },
				},
			},
		);
		expect(mocks.$fetch).toHaveBeenNthCalledWith(
			2,
			"/organization/update-role",
			{
				method: "POST",
				body: {
					organizationId: "organization-1",
					roleName: "support_agent",
					data: {
						roleName: "support_lead",
						permission: { member: ["update"], ac: ["read"] },
					},
				},
			},
		);
		expect(mocks.$fetch).toHaveBeenNthCalledWith(
			3,
			"/organization/delete-role",
			{
				method: "POST",
				body: {
					organizationId: "organization-1",
					roleName: "support_lead",
				},
			},
		);
	});

	it("updates permissions without resubmitting an unchanged role name", async () => {
		await updateOrganizationRole({
			organizationId: "organization-1",
			roleName: "support_agent",
			nextRoleName: "support_agent",
			permission: { ac: ["read"] },
		});

		expect(mocks.$fetch).toHaveBeenCalledWith("/organization/update-role", {
			method: "POST",
			body: {
				organizationId: "organization-1",
				roleName: "support_agent",
				data: { permission: { ac: ["read"] } },
			},
		});
	});

	it("surfaces the authoritative server error", async () => {
		mocks.$fetch.mockResolvedValue({
			data: null,
			error: { message: "Recent authentication required" },
		});

		await expect(
			createOrganizationTeam({
				organizationId: "organization-1",
				name: "Platform",
			}),
		).rejects.toThrow("Recent authentication required");
	});
});

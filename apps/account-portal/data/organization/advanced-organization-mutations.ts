import type { OrganizationPermissionMap } from "@/lib/advanced-organization-console";
import type { OrganizationTeamMember } from "@/lib/auth";
import { authClient } from "@/lib/auth-client";

type TeamMutationIdentity = {
	organizationId: string;
	teamId: string;
};

const getErrorMessage = (error: unknown, fallback: string) => {
	if (
		typeof error === "object" &&
		error !== null &&
		"message" in error &&
		typeof error.message === "string" &&
		error.message
	) {
		return error.message;
	}
	return fallback;
};

const mutate = async (
	path: string,
	body: Record<string, unknown>,
	fallback: string,
) => {
	const { error } = await authClient.$fetch(path, {
		method: "POST",
		body,
	});
	if (error) throw new Error(getErrorMessage(error, fallback));
};

export const listOrganizationTeamMembers = async (teamId: string) => {
	const { data, error } = await authClient.$fetch(
		"/organization/list-team-members",
		{
			method: "GET",
			query: { teamId },
		},
	);
	if (error) {
		throw new Error(getErrorMessage(error, "Unable to load team members"));
	}
	if (!Array.isArray(data)) {
		throw new Error("CinaAuth returned an invalid team member list");
	}
	return data as OrganizationTeamMember[];
};

export const createOrganizationTeam = (params: {
	organizationId: string;
	name: string;
}) =>
	mutate(
		"/organization/create-team",
		{ organizationId: params.organizationId, name: params.name.trim() },
		"Unable to create the team",
	);

export const updateOrganizationTeam = (params: {
	organizationId: string;
	teamId: string;
	name: string;
}) =>
	mutate(
		"/organization/update-team",
		{
			teamId: params.teamId,
			data: { name: params.name.trim(), organizationId: params.organizationId },
		},
		"Unable to update the team",
	);

export const deleteOrganizationTeam = (params: TeamMutationIdentity) =>
	mutate("/organization/remove-team", params, "Unable to delete the team");

export const addOrganizationTeamMember = (
	params: TeamMutationIdentity & { userId: string },
) =>
	mutate(
		"/organization/add-team-member",
		params,
		"Unable to add the team member",
	);

export const removeOrganizationTeamMember = (
	params: TeamMutationIdentity & { userId: string },
) =>
	mutate(
		"/organization/remove-team-member",
		params,
		"Unable to remove the team member",
	);

export const createOrganizationRole = (params: {
	organizationId: string;
	role: string;
	permission: OrganizationPermissionMap;
}) =>
	mutate(
		"/organization/create-role",
		{
			organizationId: params.organizationId,
			role: params.role.trim(),
			permission: params.permission,
		},
		"Unable to create the role",
	);

export const updateOrganizationRole = (params: {
	organizationId: string;
	roleName: string;
	nextRoleName: string;
	permission: OrganizationPermissionMap;
}) =>
	mutate(
		"/organization/update-role",
		{
			organizationId: params.organizationId,
			roleName: params.roleName,
			data: {
				...(params.nextRoleName.trim() !== params.roleName
					? { roleName: params.nextRoleName.trim() }
					: {}),
				permission: params.permission,
			},
		},
		"Unable to update the role",
	);

export const deleteOrganizationRole = (params: {
	organizationId: string;
	roleName: string;
}) => mutate("/organization/delete-role", params, "Unable to delete the role");

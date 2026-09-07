import { cinaauthFetch } from "./client";
import type { StandardResponse } from "./types";

type OrganizationTeam = { id: string; organizationId: string; name: string };
type TeamMember = { id: string; teamId: string; userId: string };

/** Keep team reads scoped to the organization selected in the Admin URL. */
export const listOrganizationTeams = (organizationId: string, cookie: string) =>
	cinaauthFetch<OrganizationTeam[]>(
		`/organization/list-teams?${new URLSearchParams({ organizationId })}`,
		{ cookie },
	);

/** Resolve membership IDs only after checking the team's organization. */
export async function listOrganizationTeamMembers(
	organizationId: string,
	teamId: string,
	cookie: string,
): Promise<StandardResponse<TeamMember[]>> {
	const teams = await listOrganizationTeams(organizationId, cookie);
	if (!teams.ok) return { ok: false, error: teams.error };
	if (
		!teams.data?.some(
			(team) => team.id === teamId && team.organizationId === organizationId,
		)
	) {
		return organizationResourceNotFound();
	}
	return cinaauthFetch<TeamMember[]>(
		`/organization/list-team-members?${new URLSearchParams({ teamId })}`,
		{ cookie },
	);
}

/** Do not reveal resources outside the selected organization. */
export function organizationResourceNotFound(): StandardResponse<never> {
	return {
		ok: false,
		error: {
			code: "NOT_FOUND",
			message: "Organization resource not found",
			status: 404,
		},
	};
}

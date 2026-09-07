import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { requireAdmin, requireAdminControlPermission } from "@/lib/auth-guard";
import { cinaauthFetch } from "@/lib/cinaauth/client";
import {
	listOrganizationTeamMembers,
	organizationResourceNotFound,
} from "@/lib/cinaauth/organization";
import { adminUpstreamResponseStatus } from "@/lib/cinaauth/upstream-response";
import { requireRecentAdminAuthentication } from "@/lib/recent-auth-guard";

/** DELETE .../teams/[teamId]/members/[memberId] — remove a team member. */
export async function DELETE(
	request: NextRequest,
	{
		params,
	}: { params: Promise<{ id: string; teamId: string; memberId: string }> },
) {
	const session = await requireAdmin(request).catch((error: Response) => error);
	if (session instanceof Response) return session;
	try {
		requireAdminControlPermission(session, "organization.team.manage");
	} catch (error) {
		return error as Response;
	}
	const { id, teamId, memberId } = await params;
	try {
		await requireRecentAdminAuthentication(request, session);
	} catch (error) {
		return error as Response;
	}
	const cookie = request.headers.get("cookie") ?? "";
	const members = await listOrganizationTeamMembers(id, teamId, cookie);
	if (!members.ok)
		return NextResponse.json(members, {
			status: adminUpstreamResponseStatus(members, { allowNotFound: true }),
		});
	const member = members.data?.find(
		(entry) => entry.id === memberId && entry.teamId === teamId,
	);
	if (!member)
		return NextResponse.json(organizationResourceNotFound(), { status: 404 });
	const res = await cinaauthFetch("/organization/remove-team-member", {
		method: "POST",
		body: { teamId, userId: member.userId, organizationId: id },
		cookie,
	});
	return NextResponse.json(res, { status: adminUpstreamResponseStatus(res) });
}

import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { requireAdmin, requireAdminControlPermission } from "@/lib/auth-guard";
import { cinaauthFetch } from "@/lib/cinaauth/client";
import { organizationResourceNotFound } from "@/lib/cinaauth/organization";
import { adminUpstreamResponseStatus } from "@/lib/cinaauth/upstream-response";
import { requireRecentAdminAuthentication } from "@/lib/recent-auth-guard";

/**
 * DELETE /api/admin/organizations/[id]/invitations/[inviteId] — cancel a
 * pending org invitation. Forwards to /organization/cancel-invitation.
 */
export async function DELETE(
	request: NextRequest,
	{ params }: { params: Promise<{ id: string; inviteId: string }> },
) {
	const session = await requireAdmin(request).catch((error: Response) => error);
	if (session instanceof Response) return session;
	try {
		requireAdminControlPermission(session, "organization.member.invite");
	} catch (error) {
		return error as Response;
	}
	const { id, inviteId } = await params;
	try {
		await requireRecentAdminAuthentication(request, session);
	} catch (error) {
		return error as Response;
	}
	const cookie = request.headers.get("cookie") ?? "";
	const invitations = await cinaauthFetch<
		{ id: string; organizationId: string }[]
	>(
		`/organization/list-invitations?${new URLSearchParams({ organizationId: id })}`,
		{ cookie },
	);
	if (!invitations.ok)
		return NextResponse.json(invitations, {
			status: adminUpstreamResponseStatus(invitations),
		});
	if (
		!invitations.data?.some(
			(invitation) =>
				invitation.id === inviteId && invitation.organizationId === id,
		)
	) {
		return NextResponse.json(organizationResourceNotFound(), { status: 404 });
	}
	const res = await cinaauthFetch("/organization/cancel-invitation", {
		method: "POST",
		body: { invitationId: inviteId },
		cookie,
	});
	return NextResponse.json(res, { status: adminUpstreamResponseStatus(res) });
}

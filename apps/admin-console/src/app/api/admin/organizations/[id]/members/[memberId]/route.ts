import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { requireAdmin, requireAdminControlPermission } from "@/lib/auth-guard";
import { cinaauthFetch } from "@/lib/cinaauth/client";
import { adminUpstreamResponseStatus } from "@/lib/cinaauth/upstream-response";
import { requireRecentAdminAuthentication } from "@/lib/recent-auth-guard";

/**
 * DELETE /api/admin/organizations/[id]/members/[memberId] — remove a member
 * from an organization. Forwards to cinaauth's /organization/remove-member.
 * Requires super_admin.
 */
export async function DELETE(
	request: NextRequest,
	{ params }: { params: Promise<{ id: string; memberId: string }> },
) {
	const session = await requireAdmin(request).catch((error: Response) => error);
	if (session instanceof Response) return session;
	try {
		requireAdminControlPermission(session, "organization.member.remove");
	} catch (error) {
		return error as Response;
	}
	const { id, memberId } = await params;
	// Consume request body to prevent request smuggling.
	await request.json().catch(() => ({}));
	try {
		await requireRecentAdminAuthentication(request, session);
	} catch (error) {
		return error as Response;
	}
	const cookie = request.headers.get("cookie") ?? "";
	const res = await cinaauthFetch(`/organization/remove-member`, {
		method: "POST",
		body: { organizationId: id, memberIdOrEmail: memberId },
		cookie,
	});
	return NextResponse.json(res, { status: adminUpstreamResponseStatus(res) });
}

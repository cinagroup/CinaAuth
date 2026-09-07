import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { requireAdmin, requireAdminControlPermission } from "@/lib/auth-guard";
import { cinaauthFetch } from "@/lib/cinaauth/client";
import { adminUpstreamResponseStatus } from "@/lib/cinaauth/upstream-response";

/**
 * GET /api/admin/organizations/[id] — fetch a single organization with its
 * members and invitations. Forwards to cinaauth's /organization/get-full-organization.
 */
export async function GET(
	request: NextRequest,
	{ params }: { params: Promise<{ id: string }> },
) {
	const session = await requireAdmin(request).catch((error: Response) => error);
	if (session instanceof Response) return session;
	try {
		requireAdminControlPermission(session, "organization.read");
	} catch (error) {
		return error as Response;
	}
	const { id } = await params;
	const cookie = request.headers.get("cookie") ?? "";
	const res = await cinaauthFetch(
		`/organization/get-full-organization?${new URLSearchParams({ organizationId: id })}`,
		{
			method: "GET",
			cookie,
		},
	);
	if (!res.ok) {
		return NextResponse.json(res, {
			status: adminUpstreamResponseStatus(res, { allowNotFound: true }),
		});
	}
	return NextResponse.json({ ok: true, data: res.data });
}

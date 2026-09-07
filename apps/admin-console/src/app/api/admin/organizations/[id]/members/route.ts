import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { requireAdmin, requireAdminControlPermission } from "@/lib/auth-guard";
import { cinaauthFetch } from "@/lib/cinaauth/client";
import { adminUpstreamResponseStatus } from "@/lib/cinaauth/upstream-response";

/**
 * GET /api/admin/organizations/[id]/members — list organization members.
 * Forwards to cinaauth's /organization/list-members.
 */
export async function GET(
	request: NextRequest,
	{ params }: { params: Promise<{ id: string }> },
) {
	const session = await requireAdmin(request).catch((error: Response) => error);
	if (session instanceof Response) return session;
	try {
		requireAdminControlPermission(session, "organization.member.read");
	} catch (error) {
		return error as Response;
	}
	const { id } = await params;
	const cookie = request.headers.get("cookie") ?? "";
	const query = request.nextUrl.searchParams;
	const limit = Number(query.get("limit") ?? 20);
	const offset = Number(query.get("offset") ?? 0);
	if (
		!Number.isSafeInteger(limit) ||
		limit < 1 ||
		limit > 100 ||
		!Number.isSafeInteger(offset) ||
		offset < 0
	) {
		return NextResponse.json(
			{
				ok: false,
				error: { code: "INVALID_PAGINATION", message: "Invalid member page" },
			},
			{ status: 400 },
		);
	}
	const res = await cinaauthFetch(
		`/organization/list-members?${new URLSearchParams({ organizationId: id, limit: String(limit), offset: String(offset), sortBy: "id", sortDirection: "asc" })}`,
		{
			method: "GET",
			cookie,
		},
	);
	if (!res.ok) {
		return NextResponse.json(res, { status: adminUpstreamResponseStatus(res) });
	}
	return NextResponse.json({ ok: true, data: res.data });
}

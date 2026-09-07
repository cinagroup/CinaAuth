import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { requireAdmin, requireAdminControlPermission } from "@/lib/auth-guard";
import { cinaauthFetch } from "@/lib/cinaauth/client";
import { listOrganizationTeams } from "@/lib/cinaauth/organization";
import { adminUpstreamResponseStatus } from "@/lib/cinaauth/upstream-response";
import { requireRecentAdminAuthentication } from "@/lib/recent-auth-guard";

/** GET /api/admin/organizations/[id]/teams — list teams in an org. */
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
	const res = await listOrganizationTeams(id, cookie);
	return NextResponse.json(
		res.ok ? { ok: true, data: { teams: res.data } } : res,
		{ status: adminUpstreamResponseStatus(res) },
	);
}

/** POST /api/admin/organizations/[id]/teams — create a team. */
export async function POST(
	request: NextRequest,
	{ params }: { params: Promise<{ id: string }> },
) {
	const session = await requireAdmin(request).catch((error: Response) => error);
	if (session instanceof Response) return session;
	try {
		requireAdminControlPermission(session, "organization.team.manage");
	} catch (error) {
		return error as Response;
	}
	const { id } = await params;
	const body = (await request.json().catch(() => ({}))) as Record<
		string,
		unknown
	>;
	try {
		await requireRecentAdminAuthentication(request, session);
	} catch (error) {
		return error as Response;
	}
	const cookie = request.headers.get("cookie") ?? "";
	// Pin organizationId after the spread so the path param always wins.
	const res = await cinaauthFetch("/organization/create-team", {
		method: "POST",
		body: { ...body, organizationId: id },
		cookie,
	});
	return NextResponse.json(res, { status: adminUpstreamResponseStatus(res) });
}

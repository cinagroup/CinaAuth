// @vitest-environment node
import { organization } from "cinaauth/plugins/organization";
import { getTestInstance } from "cinaauth/test";
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as cancelInvitation from "@/app/api/admin/organizations/[id]/invitations/[inviteId]/route";
import * as removeMember from "@/app/api/admin/organizations/[id]/members/[memberId]/route";
import * as members from "@/app/api/admin/organizations/[id]/members/route";
import * as detail from "@/app/api/admin/organizations/[id]/route";
import * as removeTeamMember from "@/app/api/admin/organizations/[id]/teams/[teamId]/members/[memberId]/route";
import * as teamMembers from "@/app/api/admin/organizations/[id]/teams/[teamId]/members/route";
import * as team from "@/app/api/admin/organizations/[id]/teams/[teamId]/route";
import * as teams from "@/app/api/admin/organizations/[id]/teams/route";
import * as update from "@/app/api/admin/organizations/[id]/update/route";
import { cinaauthFetch } from "@/lib/cinaauth/client";
import { cinaauthConfig } from "@/lib/cinaauth/config";

const mocks = vi.hoisted(() => ({ fetch: vi.fn(), session: vi.fn() }));
vi.mock("@/lib/cinaauth/fetcher", () => ({ fetchAuthRequest: mocks.fetch }));
vi.mock("@/lib/cinaauth/session", async (importOriginal) => ({
	...(await importOriginal<typeof import("@/lib/cinaauth/session")>()),
	resolveAdminSession: mocks.session,
}));
vi.mock("@/lib/recent-auth-guard", () => ({
	requireRecentAdminAuthentication: vi.fn().mockResolvedValue(undefined),
}));

const createFixture = async () => {
	const { auth, signInWithTestUser } = await getTestInstance({
		baseURL: cinaauthConfig.baseUrl,
		trustedOrigins: [cinaauthConfig.requestOrigin],
		advanced: { useSecureCookies: false },
		plugins: [
			organization({ teams: { enabled: true, allowRemovingAllTeams: true } }),
		],
	});
	const { headers, user } = await signInWithTestUser();
	const first = await auth.api.createOrganization({
		headers,
		body: { name: "First", slug: "first" },
	});
	const second = await auth.api.createOrganization({
		headers,
		body: { name: "Second", slug: "second" },
	});
	if (!first || !second)
		throw new Error("Organization fixtures were not created");
	const context = await auth.$context;
	const target = await context.internalAdapter.createUser(
		{ name: "Member", email: "member@example.com", emailVerified: true },
		{ method: "admin" },
	);
	const member = await auth.api.addMember({
		headers,
		body: { organizationId: first.id, userId: target.id, role: "member" },
	});
	const firstTeam = await auth.api.createTeam({
		headers,
		body: { organizationId: first.id, name: "First team" },
	});
	await auth.api.addTeamMember({
		headers,
		body: { organizationId: first.id, teamId: firstTeam.id, userId: user.id },
	});
	const secondTeam = await auth.api.createTeam({
		headers,
		body: { organizationId: second.id, name: "Second team" },
	});
	await auth.api.addTeamMember({
		headers,
		body: { organizationId: second.id, teamId: secondTeam.id, userId: user.id },
	});
	// The selected Admin route must win over the unrelated active organization.
	await auth.api.setActiveOrganization({
		headers,
		body: { organizationId: second.id },
	});
	mocks.session.mockResolvedValue({
		userId: user.id,
		role: "super_admin",
		impersonatedBy: null,
	});
	mocks.fetch.mockImplementation((request: Request) => auth.handler(request));
	const request = (method = "GET", body?: unknown) =>
		new NextRequest(
			`${cinaauthConfig.requestOrigin}/api/admin/organizations/${first.id}`,
			{
				method,
				headers: {
					cookie: headers.get("cookie") ?? "",
					...(body === undefined ? {} : { "content-type": "application/json" }),
				},
				body: body === undefined ? undefined : JSON.stringify(body),
			},
		);
	return {
		auth,
		headers,
		first,
		second,
		firstTeam,
		secondTeam,
		target,
		member,
		request,
	};
};

let fixture: Awaited<ReturnType<typeof createFixture>>;
beforeEach(async () => {
	vi.clearAllMocks();
	fixture = await createFixture();
});

/** @see https://github.com/cinagroup/cinaauth/tree/main/packages/cinaauth/src/plugins/organization/routes */
describe("Admin organization proxies against the current authentication handler", () => {
	it("authenticates the transport fixture against the real organization handler", async () => {
		const response = await cinaauthFetch(
			`/organization/get-full-organization?${new URLSearchParams({ organizationId: fixture.first.id })}`,
			{ cookie: fixture.headers.get("cookie") ?? "" },
		);
		expect(response).toMatchObject({
			ok: true,
			data: { id: fixture.first.id },
		});
	});
	it("reads the organization selected in the path", async () => {
		const response = await detail.GET(fixture.request(), {
			params: Promise.resolve({ id: fixture.first.id }),
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true,
			data: { id: fixture.first.id, name: "First" },
		});
	});
	it("reads organization members with the current GET query contract", async () => {
		const response = await members.GET(fixture.request(), {
			params: Promise.resolve({ id: fixture.first.id }),
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			data: {
				members: expect.arrayContaining([
					expect.objectContaining({ id: fixture.member.id }),
				]),
			},
		});
	});
	it("paginates members without allowing query parameters to replace the path organization", async () => {
		const request = new NextRequest(
			`${cinaauthConfig.requestOrigin}/api/admin/organizations/${fixture.first.id}/members?limit=1&offset=1&organizationId=${fixture.second.id}`,
			{ headers: fixture.request().headers },
		);
		const response = await members.GET(request, {
			params: Promise.resolve({ id: fixture.first.id }),
		});
		expect(response.status).toBe(200);
		const result = (await response.json()) as {
			data: { total: number; members: { organizationId: string }[] };
		};
		expect(result.data.total).toBe(2);
		expect(result.data.members).toHaveLength(1);
		expect(result.data.members[0].organizationId).toBe(fixture.first.id);
	});
	it("retains upstream authentication requirements even when the Admin session resolves", async () => {
		const response = await detail.GET(
			new NextRequest(cinaauthConfig.requestOrigin),
			{ params: Promise.resolve({ id: fixture.first.id }) },
		);
		expect(response.status).toBe(401);
	});
	it("does not mutate a team through another organization's path", async () => {
		const response = await team.DELETE(fixture.request("DELETE"), {
			params: Promise.resolve({
				id: fixture.first.id,
				teamId: fixture.secondTeam.id,
			}),
		});
		expect(response.ok).toBe(false);
		expect(
			await fixture.auth.api.listOrganizationTeams({
				headers: fixture.headers,
				query: { organizationId: fixture.second.id },
			}),
		).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: fixture.secondTeam.id }),
			]),
		);
	});
	it("returns the team collection shape consumed by the Admin page", async () => {
		const response = await teams.GET(fixture.request(), {
			params: Promise.resolve({ id: fixture.first.id }),
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			data: {
				teams: expect.arrayContaining([
					expect.objectContaining({ id: fixture.firstTeam.id }),
				]),
			},
		});
	});
	it("returns the team member collection shape consumed by the Admin page", async () => {
		const response = await teamMembers.GET(fixture.request(), {
			params: Promise.resolve({
				id: fixture.first.id,
				teamId: fixture.firstTeam.id,
			}),
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			data: {
				members: expect.arrayContaining([
					expect.objectContaining({ teamId: fixture.firstTeam.id }),
				]),
			},
		});
	});
	it("updates organization data without accepting a different body organization", async () => {
		const response = await update.POST(
			fixture.request("POST", {
				name: "Renamed",
				organizationId: fixture.second.id,
			}),
			{ params: Promise.resolve({ id: fixture.first.id }) },
		);
		expect(response.status).toBe(200);
		expect(
			await fixture.auth.api.getFullOrganization({
				headers: fixture.headers,
				query: { organizationId: fixture.first.id },
			}),
		).toMatchObject({ name: "Renamed" });
		expect(
			await fixture.auth.api.getFullOrganization({
				headers: fixture.headers,
				query: { organizationId: fixture.second.id },
			}),
		).toMatchObject({ name: "Second" });
	});
	it("removes the organization member represented by the route", async () => {
		const response = await removeMember.DELETE(fixture.request("DELETE"), {
			params: Promise.resolve({
				id: fixture.first.id,
				memberId: fixture.member.id,
			}),
		});
		expect(response.status).toBe(200);
		const remaining = await fixture.auth.api.listMembers({
			headers: fixture.headers,
			query: { organizationId: fixture.first.id },
		});
		expect(
			remaining.members.some((entry) => entry.id === fixture.member.id),
		).toBe(false);
	});
	it("cancels an invitation using its canonical identifier", async () => {
		const invitation = await fixture.auth.api.createInvitation({
			headers: fixture.headers,
			body: {
				organizationId: fixture.first.id,
				email: "invitee@example.com",
				role: "member",
			},
		});
		const response = await cancelInvitation.DELETE(fixture.request("DELETE"), {
			params: Promise.resolve({
				id: fixture.first.id,
				inviteId: invitation.id,
			}),
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			data: { status: "canceled" },
		});
	});
	it("updates a team in the path organization while another organization is active", async () => {
		const response = await team.POST(
			fixture.request("POST", {
				name: "Renamed team",
				organizationId: fixture.second.id,
			}),
			{
				params: Promise.resolve({
					id: fixture.first.id,
					teamId: fixture.firstTeam.id,
				}),
			},
		);
		expect(response.status).toBe(200);
		expect(
			await fixture.auth.api.listOrganizationTeams({
				headers: fixture.headers,
				query: { organizationId: fixture.first.id },
			}),
		).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "Renamed team" }),
			]),
		);
	});
	it("adds and removes a team membership without confusing membership IDs and user IDs", async () => {
		const params = { id: fixture.first.id, teamId: fixture.firstTeam.id };
		const added = await teamMembers.POST(
			fixture.request("POST", {
				userId: fixture.target.id,
				organizationId: fixture.second.id,
			}),
			{ params: Promise.resolve(params) },
		);
		expect(added.status).toBe(200);
		const entries = await fixture.auth.api.listTeamMembers({
			headers: fixture.headers,
			query: { teamId: fixture.firstTeam.id },
		});
		const membership = entries.find(
			(entry) => entry.userId === fixture.target.id,
		)!;
		expect(membership).toBeDefined();
		const removed = await removeTeamMember.DELETE(fixture.request("DELETE"), {
			params: Promise.resolve({ ...params, memberId: membership.id }),
		});
		expect(removed.status).toBe(200);
		expect(
			await fixture.auth.api.listTeamMembers({
				headers: fixture.headers,
				query: { teamId: fixture.firstTeam.id },
			}),
		).not.toEqual(
			expect.arrayContaining([
				expect.objectContaining({ userId: fixture.target.id }),
			]),
		);
	});
	it("deletes a team from the path organization while another is active", async () => {
		const response = await team.DELETE(fixture.request("DELETE"), {
			params: Promise.resolve({
				id: fixture.first.id,
				teamId: fixture.firstTeam.id,
			}),
		});
		expect(response.status).toBe(200);
		expect(
			await fixture.auth.api.listOrganizationTeams({
				headers: fixture.headers,
				query: { organizationId: fixture.first.id },
			}),
		).not.toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: fixture.firstTeam.id }),
			]),
		);
	});
	it("rejects a team read under the wrong organization path even when the actor belongs to both", async () => {
		const response = await teamMembers.GET(fixture.request(), {
			params: Promise.resolve({
				id: fixture.first.id,
				teamId: fixture.secondTeam.id,
			}),
		});
		expect(response.status).toBe(404);
	});
	it("does not cancel an invitation belonging to another organization", async () => {
		const invitation = await fixture.auth.api.createInvitation({
			headers: fixture.headers,
			body: {
				organizationId: fixture.second.id,
				email: "invitee@example.com",
				role: "member",
			},
		});
		const response = await cancelInvitation.DELETE(fixture.request("DELETE"), {
			params: Promise.resolve({
				id: fixture.first.id,
				inviteId: invitation.id,
			}),
		});
		expect(response.status).toBe(404);
		const organization = await fixture.auth.api.getFullOrganization({
			headers: fixture.headers,
			query: { organizationId: fixture.second.id },
		});
		expect(organization?.invitations).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: invitation.id, status: "pending" }),
			]),
		);
	});
});

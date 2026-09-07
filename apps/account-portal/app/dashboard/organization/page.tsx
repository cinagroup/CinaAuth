import type { EntitlementSnapshot } from "@cinaauth/auth-web-contract";
import type { Metadata } from "next";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import type { OrganizationAuditPage } from "@/data/organization/organization-audit";
import type {
	OrganizationDynamicRoleSummary,
	OrganizationTeamSummary,
} from "@/lib/advanced-organization-console";
import type { SCIMProviderConnection, SSOProviderSummary } from "@/lib/auth";
import { auth } from "@/lib/auth";
import { dashboardMessages } from "@/lib/dashboard-i18n";
import type {
	OrganizationDetail,
	OrganizationSummary,
} from "@/lib/organization-console";
import { parseOrganizationRoles } from "@/lib/organization-console";
import { getRequestLocale } from "@/lib/request-locale";
import { OrganizationConsole } from "./organization-console";

export async function generateMetadata(): Promise<Metadata> {
	const messages = dashboardMessages[await getRequestLocale()];
	return {
		title: messages.organizationTitle,
		description: messages.organizationMetadataDescription,
	};
}

const toIsoString = (value: Date | string) => new Date(value).toISOString();

export default async function OrganizationConsolePage() {
	const requestHeaders = await headers();
	const session = await auth.api.getSession({ headers: requestHeaders });
	if (!session) {
		redirect("/sign-in?callbackURL=/dashboard/organization");
	}

	const [organizationsResult, organizationResult] = await Promise.all([
		auth.api
			.listOrganizations({ headers: requestHeaders })
			.then((data) => ({ data, unavailable: false }))
			.catch(() => ({ data: [], unavailable: true })),
		auth.api
			.getFullOrganization({ headers: requestHeaders })
			.then((data) => ({ data, unavailable: false }))
			.catch(() => ({ data: null, unavailable: true })),
	]);

	const organizations: OrganizationSummary[] = organizationsResult.data.map(
		(item) => ({
			id: item.id,
			name: item.name,
			slug: item.slug || item.id,
			logo: item.logo ?? null,
		}),
	);
	const organization: OrganizationDetail | null = organizationResult.data
		? {
				id: organizationResult.data.id,
				name: organizationResult.data.name,
				slug: organizationResult.data.slug,
				logo: organizationResult.data.logo ?? null,
				createdAt: toIsoString(organizationResult.data.createdAt),
				members: organizationResult.data.members.map((member) => ({
					id: member.id,
					userId: member.userId,
					organizationId: member.organizationId,
					role: member.role,
					createdAt: toIsoString(member.createdAt),
					user: {
						id: member.user.id,
						name: member.user.name,
						email: member.user.email,
						image: member.user.image ?? null,
					},
				})),
				invitations: organizationResult.data.invitations.map((invitation) => ({
					id: invitation.id,
					organizationId: invitation.organizationId,
					email: invitation.email,
					role: invitation.role,
					status: invitation.status,
					expiresAt: toIsoString(invitation.expiresAt),
					createdAt: toIsoString(invitation.createdAt),
				})),
			}
		: null;
	const currentMember = organization?.members.find(
		(member) => member.userId === session.user.id,
	);
	const canViewOrganizationAudit = parseOrganizationRoles(
		currentMember?.role ?? "",
	).some((role) => role === "owner" || role === "admin");
	const [teamsResult, rolesResult, entitlementsResult] = organization
		? await Promise.all([
				auth.api
					.listOrganizationTeams(organization.id, {
						headers: requestHeaders,
					})
					.then((data) => ({ data, unavailable: false }))
					.catch(() => ({ data: [], unavailable: true })),
				auth.api
					.listOrganizationRoles(organization.id, {
						headers: requestHeaders,
					})
					.then((data) => ({ data, unavailable: false }))
					.catch(() => ({ data: [], unavailable: true })),
				auth.api
					.getEntitlements(organization.id, { headers: requestHeaders })
					.then((data) => ({ data, unavailable: false }))
					.catch(() => ({
						data: null as EntitlementSnapshot | null,
						unavailable: true,
					})),
			])
		: [
				{ data: [], unavailable: false },
				{ data: [], unavailable: false },
				{ data: null as EntitlementSnapshot | null, unavailable: false },
			];
	const teams: OrganizationTeamSummary[] = teamsResult.data.map((team) => ({
		id: team.id,
		name: team.name,
		organizationId: team.organizationId,
		createdAt: toIsoString(team.createdAt),
		updatedAt: team.updatedAt ? toIsoString(team.updatedAt) : null,
	}));
	const dynamicRoles: OrganizationDynamicRoleSummary[] = rolesResult.data.map(
		(role) => ({
			id: role.id,
			organizationId: role.organizationId,
			role: role.role,
			permission: role.permission,
			createdAt: toIsoString(role.createdAt),
			updatedAt: role.updatedAt ? toIsoString(role.updatedAt) : null,
		}),
	);
	const [auditResult, ssoResult, scimResult] =
		organization && canViewOrganizationAudit
			? await Promise.all([
					auth.api
						.listOrganizationAudit(organization.id, {
							headers: requestHeaders,
							query: { limit: 25 },
						})
						.then((data) => ({ data, unavailable: false }))
						.catch(() => ({
							data: { rows: [], total: 0, limit: 25, offset: 0 },
							unavailable: true,
						})),
					auth.api
						.listSSOProviders({ headers: requestHeaders })
						.then((data) => ({
							data: data.providers.filter(
								(provider) => provider.organizationId === organization.id,
							),
							unavailable: false,
						}))
						.catch(() => ({ data: [], unavailable: true })),
					auth.api
						.listSCIMProviderConnections({ headers: requestHeaders })
						.then((data) => ({
							data: data.providers.filter(
								(provider) => provider.organizationId === organization.id,
							),
							unavailable: false,
						}))
						.catch(() => ({ data: [], unavailable: true })),
				])
			: [
					{
						data: { rows: [], total: 0, limit: 25, offset: 0 },
						unavailable: false,
					},
					{ data: [] as SSOProviderSummary[], unavailable: false },
					{ data: [] as SCIMProviderConnection[], unavailable: false },
				];
	const auditPage: OrganizationAuditPage = {
		...auditResult.data,
		rows: auditResult.data.rows.map((event) => ({
			id: event.id,
			timestamp: toIsoString(event.timestamp),
			category: event.category,
			action: event.action,
			result: event.result,
			actorId: event.actorId,
			actorRole: event.actorRole,
			actorSite: event.actorSite,
			targetType: event.targetType,
			targetId: event.targetId,
			metadata: event.metadata,
		})),
	};

	return (
		<OrganizationConsole
			key={JSON.stringify([session.user.id, organization?.id ?? null])}
			currentUser={{
				id: session.user.id,
				name: session.user.name,
				email: session.user.email,
				image: session.user.image ?? null,
			}}
			currentSessionCreatedAt={toIsoString(session.session.createdAt)}
			initialOrganizations={organizations}
			initialOrganization={organization}
			initialTeams={teams}
			initialDynamicRoles={dynamicRoles}
			initialEntitlements={entitlementsResult.data}
			entitlementsUnavailable={entitlementsResult.unavailable}
			advancedOrganizationDataUnavailable={{
				teams: teamsResult.unavailable,
				roles: rolesResult.unavailable,
			}}
			initialAuditPage={auditPage}
			auditUnavailable={auditResult.unavailable}
			initialSSOProviders={ssoResult.data}
			initialSCIMProviders={scimResult.data}
			enterpriseDataUnavailable={{
				sso: ssoResult.unavailable,
				scim: scimResult.unavailable,
			}}
			dataUnavailable={{
				organizations: organizationsResult.unavailable,
				organization: organizationResult.unavailable,
			}}
		/>
	);
}

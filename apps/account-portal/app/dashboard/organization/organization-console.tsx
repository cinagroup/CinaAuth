"use client";

import type {
	EntitlementFeature,
	EntitlementLimit,
	EntitlementSnapshot,
} from "@cinaauth/auth-web-contract";
import {
	AlertTriangle,
	CalendarDays,
	Copy,
	Loader2,
	LogOut,
	MailPlus,
	Plus,
	ShieldCheck,
	Trash2,
	Users,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { DashboardPageHeader } from "@/components/dashboard/dashboard-page-header";
import { useDashboardI18n } from "@/components/dashboard/use-dashboard-i18n";
import { CreateOrganizationForm } from "@/components/forms/create-organization-form";
import { InviteMemberForm } from "@/components/forms/invite-member-form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
	AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
	DialogTrigger,
} from "@/components/ui/dialog";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import { useInvitationCancelMutation } from "@/data/organization/invitation-cancel-mutation";
import { useMemberRemoveMutation } from "@/data/organization/member-remove-mutation";
import { useOrganizationActiveMutation } from "@/data/organization/organization-active-mutation";
import type { OrganizationAuditPage } from "@/data/organization/organization-audit";
import { useOrganizationLeaveMutation } from "@/data/organization/organization-leave-mutation";
import type {
	OrganizationDynamicRoleSummary,
	OrganizationTeamSummary,
} from "@/lib/advanced-organization-console";
import { hasOrganizationPermission } from "@/lib/advanced-organization-console";
import type { SCIMProviderConnection, SSOProviderSummary } from "@/lib/auth";
import { authClient } from "@/lib/auth-client";
import { startAccountStepUp } from "@/lib/client-api";
import { formatDashboardMessage } from "@/lib/dashboard-i18n";
import type {
	OrganizationDetail,
	OrganizationMember,
	OrganizationSummary,
} from "@/lib/organization-console";
import {
	canLeaveOrganization,
	canManageOrganizationMember,
	formatOrganizationDate,
	getOrganizationInvitationUrl,
	getOrganizationPermissions,
	getOrganizationRoleLabel,
	parseOrganizationRoles,
} from "@/lib/organization-console";
import { isSessionRecent } from "@/lib/security-center";
import {
	AdvancedMemberRoleEditor,
	AdvancedOrganizationCard,
} from "./advanced-organization-card";
import { EnterpriseConnectionsCard } from "./enterprise-connections-card";
import { OrganizationAuditCard } from "./organization-audit-card";

type OrganizationConsoleProps = {
	currentUser: {
		id: string;
		name: string;
		email: string;
		image: string | null;
	};
	currentSessionCreatedAt: string;
	initialOrganizations: OrganizationSummary[];
	initialOrganization: OrganizationDetail | null;
	initialTeams: OrganizationTeamSummary[];
	initialDynamicRoles: OrganizationDynamicRoleSummary[];
	initialEntitlements: EntitlementSnapshot | null;
	entitlementsUnavailable: boolean;
	advancedOrganizationDataUnavailable: {
		teams: boolean;
		roles: boolean;
	};
	initialAuditPage: OrganizationAuditPage;
	auditUnavailable: boolean;
	initialSSOProviders: SSOProviderSummary[];
	initialSCIMProviders: SCIMProviderConnection[];
	enterpriseDataUnavailable: {
		sso: boolean;
		scim: boolean;
	};
	dataUnavailable: {
		organizations: boolean;
		organization: boolean;
	};
};

export function OrganizationConsole({
	currentUser,
	currentSessionCreatedAt,
	initialOrganizations,
	initialOrganization,
	initialTeams,
	initialDynamicRoles,
	initialEntitlements,
	entitlementsUnavailable,
	advancedOrganizationDataUnavailable,
	initialAuditPage,
	auditUnavailable,
	initialSSOProviders,
	initialSCIMProviders,
	enterpriseDataUnavailable,
	dataUnavailable,
}: OrganizationConsoleProps) {
	const { locale, messages } = useDashboardI18n();
	const router = useRouter();
	const [createDialogOpen, setCreateDialogOpen] = useState(false);
	const [inviteDialogOpen, setInviteDialogOpen] = useState(false);
	const [reauthenticating, setReauthenticating] = useState(false);
	const setActiveMutation = useOrganizationActiveMutation();
	const removeMemberMutation = useMemberRemoveMutation();
	const cancelInvitationMutation = useInvitationCancelMutation();
	const leaveOrganizationMutation = useOrganizationLeaveMutation();

	const recentAuthentication = isSessionRecent(currentSessionCreatedAt);
	const entitlementFeatureLabels = {
		sso: messages.enterpriseSso,
		scim: messages.scimProvisioning,
		organizationAudit: messages.organizationAudit,
		teams: messages.teams,
		dynamicRoles: messages.dynamicRoles,
		oauthClients: messages.oauthClients,
		apiKeys: messages.apiKeys,
	} satisfies Record<EntitlementFeature, string>;
	const entitlementLimitLabels = {
		organizationMembers: messages.organizationMembers,
		teams: messages.teams,
		teamMembers: messages.membersPerTeam,
		dynamicRoles: messages.dynamicRoles,
		oauthClients: messages.oauthClients,
		apiKeys: messages.apiKeys,
		auditRetentionDays: messages.auditRetentionDays,
	} satisfies Record<EntitlementLimit, string>;
	const currentMember = initialOrganization?.members.find(
		(member) => member.userId === currentUser.id,
	);
	const permissions = getOrganizationPermissions(currentMember?.role ?? "");
	const actorRole = currentMember?.role ?? "";
	const hasEffectivePermission = (
		resource: "member" | "invitation" | "team" | "ac",
		action: string,
	) =>
		hasOrganizationPermission({
			role: actorRole,
			dynamicRoles: initialDynamicRoles,
			resource,
			action,
		});
	const canUpdateMembers =
		permissions.canManageMembers || hasEffectivePermission("member", "update");
	const canDeleteMembers =
		permissions.canManageMembers || hasEffectivePermission("member", "delete");
	const canInviteMembers =
		permissions.canManageInvitations ||
		hasEffectivePermission("invitation", "create");
	const canCancelInvitations =
		permissions.canManageInvitations ||
		hasEffectivePermission("invitation", "cancel");
	const teamPermissions = {
		create: hasEffectivePermission("team", "create"),
		update: hasEffectivePermission("team", "update"),
		delete: hasEffectivePermission("team", "delete"),
	};
	const rolePermissions = {
		create: hasEffectivePermission("ac", "create"),
		update: hasEffectivePermission("ac", "update"),
		delete: hasEffectivePermission("ac", "delete"),
	};
	const pendingInvitations =
		initialOrganization?.invitations.filter(
			(invitation) => invitation.status === "pending",
		) ?? [];
	const ownerCount =
		initialOrganization?.members.filter((member) =>
			parseOrganizationRoles(member.role).includes("owner"),
		).length ?? 0;
	const canLeaveActiveOrganization = currentMember
		? canLeaveOrganization(currentMember.role, ownerCount)
		: false;
	const onlyOwnerCannotLeave = Boolean(
		currentMember &&
			parseOrganizationRoles(currentMember.role).includes("owner") &&
			ownerCount <= 1,
	);
	const authoritativeOrganizationData =
		!dataUnavailable.organizations && !dataUnavailable.organization;

	const switchOrganization = (organizationId: string) => {
		const nextId = organizationId === "personal" ? null : organizationId;
		if (nextId === (initialOrganization?.id ?? null)) return;
		setActiveMutation.mutate(
			{ organizationId: nextId },
			{ onSuccess: () => router.refresh() },
		);
	};

	const reauthenticate = async () => {
		setReauthenticating(true);
		try {
			await startAccountStepUp(authClient);
		} catch {
			setReauthenticating(false);
			toast.error(messages.unableFreshSignIn);
		}
	};

	const removeMember = (member: OrganizationMember) => {
		removeMemberMutation.mutate(
			{ memberIdOrEmail: member.id, organizationId: member.organizationId },
			{ onSuccess: () => router.refresh() },
		);
	};

	const cancelInvitation = (invitationId: string) => {
		cancelInvitationMutation.mutate(
			{ invitationId },
			{ onSuccess: () => router.refresh() },
		);
	};

	const leaveActiveOrganization = () => {
		if (!initialOrganization) return;
		leaveOrganizationMutation.mutate(
			{ organizationId: initialOrganization.id },
			{ onSuccess: () => router.refresh() },
		);
	};

	const copyInvitationLink = async (invitationId: string) => {
		const invitationURL = getOrganizationInvitationUrl(
			window.location.origin,
			invitationId,
		);
		if (!invitationURL) {
			toast.error(messages.unableBuildInvitationLink);
			return;
		}
		try {
			await navigator.clipboard.writeText(invitationURL);
			toast.success(messages.invitationLinkCopied);
		} catch {
			toast.error(messages.copyInvitationFailed);
		}
	};

	return (
		<div className="mx-auto w-full max-w-6xl">
			<DashboardPageHeader
				titleKey="organizationTitle"
				descriptionKey="organizationDescription"
			>
				<div className="flex w-full gap-2 sm:w-auto">
					<Select
						value={initialOrganization?.id ?? "personal"}
						onValueChange={switchOrganization}
						disabled={
							dataUnavailable.organizations || setActiveMutation.isPending
						}
					>
						<SelectTrigger
							className="min-w-48"
							aria-label={messages.activeOrganization}
						>
							<SelectValue placeholder={messages.selectOrganization} />
						</SelectTrigger>
						<SelectContent>
							<SelectItem value="personal">
								{messages.personalWorkspace}
							</SelectItem>
							{initialOrganizations.map((organization) => (
								<SelectItem key={organization.id} value={organization.id}>
									{organization.name}
								</SelectItem>
							))}
						</SelectContent>
					</Select>
					<Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
						<DialogTrigger asChild>
							<Button
								disabled={
									!recentAuthentication || dataUnavailable.organizations
								}
							>
								<Plus className="mr-2 h-4 w-4" /> {messages.new}
							</Button>
						</DialogTrigger>
						<DialogContent>
							<DialogHeader>
								<DialogTitle>{messages.createOrganization}</DialogTitle>
								<DialogDescription>
									{messages.createOrganizationDescription}
								</DialogDescription>
							</DialogHeader>
							<CreateOrganizationForm
								onSuccess={() => {
									setCreateDialogOpen(false);
									router.refresh();
								}}
							/>
						</DialogContent>
					</Dialog>
				</div>
			</DashboardPageHeader>

			{(!recentAuthentication || !authoritativeOrganizationData) && (
				<Alert className="mb-6">
					<AlertTriangle className="h-4 w-4" />
					<AlertTitle>
						{recentAuthentication
							? messages.organizationDataUnavailable
							: messages.recentAuthenticationRequired}
					</AlertTitle>
					<AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
						<span>
							{recentAuthentication
								? messages.organizationDataUnavailableDescription
								: messages.recentAuthenticationOrganizationDescription}
						</span>
						{!recentAuthentication && (
							<Button
								size="sm"
								variant="outline"
								onClick={reauthenticate}
								disabled={reauthenticating}
							>
								{reauthenticating && (
									<Loader2 className="mr-2 h-4 w-4 animate-spin" />
								)}
								{messages.signInAgain}
							</Button>
						)}
					</AlertDescription>
				</Alert>
			)}

			{initialOrganization ? (
				<div className="space-y-6">
					<div className="grid gap-4 md:grid-cols-3">
						<Card>
							<CardHeader className="pb-2">
								<CardDescription>{messages.activeWorkspace}</CardDescription>
								<CardTitle className="flex items-center gap-2 text-lg">
									<Avatar className="h-8 w-8">
										<AvatarImage src={initialOrganization.logo || undefined} />
										<AvatarFallback>
											{initialOrganization.name.charAt(0)}
										</AvatarFallback>
									</Avatar>
									{initialOrganization.name}
								</CardTitle>
							</CardHeader>
							<CardContent className="text-sm text-muted-foreground">
								/{initialOrganization.slug}
							</CardContent>
						</Card>
						<Card>
							<CardHeader className="pb-2">
								<CardDescription>{messages.members}</CardDescription>
								<CardTitle className="flex items-center gap-2 text-2xl">
									<Users className="h-5 w-5 text-muted-foreground" />
									{initialOrganization.members.length}
								</CardTitle>
							</CardHeader>
						</Card>
						<Card>
							<CardHeader className="pb-2">
								<CardDescription>{messages.pendingInvitations}</CardDescription>
								<CardTitle className="flex items-center gap-2 text-2xl">
									<MailPlus className="h-5 w-5 text-muted-foreground" />
									{pendingInvitations.length}
								</CardTitle>
							</CardHeader>
						</Card>
					</div>

					<Card>
						<CardHeader className="flex flex-row items-start justify-between gap-4">
							<div>
								<CardTitle>{messages.planAndEntitlements}</CardTitle>
								<CardDescription>
									{messages.planAndEntitlementsDescription}
								</CardDescription>
							</div>
							{initialEntitlements ? (
								<Badge variant="secondary">{initialEntitlements.plan.id}</Badge>
							) : null}
						</CardHeader>
						<CardContent className="space-y-5">
							{entitlementsUnavailable || !initialEntitlements ? (
								<Alert>
									<AlertTriangle className="h-4 w-4" />
									<AlertTitle>{messages.planPolicyUnavailable}</AlertTitle>
									<AlertDescription>
										{messages.planPolicyUnavailableDescription}
									</AlertDescription>
								</Alert>
							) : (
								<>
									<div>
										<p className="mb-2 text-sm font-medium">
											{messages.features}
										</p>
										<div className="flex flex-wrap gap-2">
											{Object.entries(initialEntitlements.features).map(
												([feature, enabled]) => (
													<Badge
														key={feature}
														variant={enabled ? "secondary" : "outline"}
													>
														{
															entitlementFeatureLabels[
																feature as EntitlementFeature
															]
														}{" "}
														{enabled
															? messages.featureEnabled
															: messages.featureUnavailable}
													</Badge>
												),
											)}
										</div>
									</div>
									<div>
										<p className="mb-2 text-sm font-medium">
											{messages.limits}
										</p>
										<div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
											{Object.entries(initialEntitlements.limits).map(
												([limit, value]) => (
													<div
														key={limit}
														className="flex items-center justify-between rounded-md border px-3 py-2 text-sm"
													>
														<span className="text-muted-foreground">
															{
																entitlementLimitLabels[
																	limit as EntitlementLimit
																]
															}
														</span>
														<span className="font-medium">
															{value === null ? messages.unlimited : value}
														</span>
													</div>
												),
											)}
										</div>
									</div>
								</>
							)}
						</CardContent>
					</Card>

					<Card>
						<CardHeader className="flex flex-row items-center justify-between gap-4">
							<div>
								<CardTitle>{messages.members}</CardTitle>
								<CardDescription>
									{messages.membersPolicyDescription}
								</CardDescription>
							</div>
							<Badge variant="secondary">
								{getOrganizationRoleLabel(
									currentMember?.role ?? "member",
									locale,
								)}
							</Badge>
						</CardHeader>
						<CardContent className="space-y-3">
							{initialOrganization.members.map((member) => {
								const isCurrentUser = member.userId === currentUser.id;
								const staticCanManageTarget = canManageOrganizationMember(
									currentMember?.role ?? "",
									member.role,
								);
								const targetIsOwner = parseOrganizationRoles(
									member.role,
								).includes("owner");
								const canUpdateTarget =
									staticCanManageTarget || (canUpdateMembers && !targetIsOwner);
								const canDeleteTarget =
									staticCanManageTarget || (canDeleteMembers && !targetIsOwner);
								const updateMutationDisabled =
									!recentAuthentication ||
									!authoritativeOrganizationData ||
									!canUpdateTarget;
								const deleteMutationDisabled =
									!recentAuthentication ||
									!authoritativeOrganizationData ||
									!canDeleteTarget;

								return (
									<div
										key={member.id}
										className="flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-center sm:justify-between"
									>
										<div className="flex min-w-0 items-center gap-3">
											<Avatar>
												<AvatarImage src={member.user.image || undefined} />
												<AvatarFallback>
													{member.user.name.charAt(0)}
												</AvatarFallback>
											</Avatar>
											<div className="min-w-0">
												<p className="truncate text-sm font-medium">
													{member.user.name}{" "}
													{isCurrentUser && `(${messages.you})`}
												</p>
												<p className="truncate text-xs text-muted-foreground">
													{member.user.email}
												</p>
											</div>
										</div>
										<div className="flex items-center gap-2">
											<Badge variant="outline">
												{getOrganizationRoleLabel(member.role, locale)}
											</Badge>
											<AdvancedMemberRoleEditor
												member={member}
												actorRole={currentMember?.role ?? ""}
												dynamicRoles={initialDynamicRoles}
												ownerCount={ownerCount}
												actorCanManage={canUpdateMembers}
												disabled={
													updateMutationDisabled ||
													advancedOrganizationDataUnavailable.roles
												}
											/>
											{!isCurrentUser && canDeleteTarget && (
												<AlertDialog>
													<AlertDialogTrigger asChild>
														<Button
															variant="destructive"
															size="icon"
															disabled={
																deleteMutationDisabled ||
																removeMemberMutation.isPending
															}
															aria-label={formatDashboardMessage(
																messages.removeNamedItem,
																{ name: member.user.name },
															)}
														>
															<Trash2 className="h-4 w-4" />
														</Button>
													</AlertDialogTrigger>
													<AlertDialogContent>
														<AlertDialogHeader>
															<AlertDialogTitle>
																{formatDashboardMessage(
																	messages.removeMemberTitle,
																	{
																		name: member.user.name,
																	},
																)}
															</AlertDialogTitle>
															<AlertDialogDescription>
																{messages.removeMemberDescription}
															</AlertDialogDescription>
														</AlertDialogHeader>
														<AlertDialogFooter>
															<AlertDialogCancel>
																{messages.cancel}
															</AlertDialogCancel>
															<AlertDialogAction
																onClick={() => removeMember(member)}
															>
																{messages.removeMember}
															</AlertDialogAction>
														</AlertDialogFooter>
													</AlertDialogContent>
												</AlertDialog>
											)}
										</div>
									</div>
								);
							})}
						</CardContent>
					</Card>

					<AdvancedOrganizationCard
						organizationId={initialOrganization.id}
						members={initialOrganization.members}
						initialTeams={initialTeams}
						initialDynamicRoles={initialDynamicRoles}
						teamPermissions={teamPermissions}
						rolePermissions={rolePermissions}
						recentAuthentication={recentAuthentication}
						authoritativeOrganizationData={authoritativeOrganizationData}
						dataUnavailable={advancedOrganizationDataUnavailable}
					/>

					<Card>
						<CardHeader className="flex flex-row items-center justify-between gap-4">
							<div>
								<CardTitle>{messages.invitations}</CardTitle>
								<CardDescription>
									{messages.invitationsDescription}
								</CardDescription>
							</div>
							<Dialog
								open={inviteDialogOpen}
								onOpenChange={setInviteDialogOpen}
							>
								<DialogTrigger asChild>
									<Button
										disabled={
											!canInviteMembers ||
											!recentAuthentication ||
											!authoritativeOrganizationData
										}
									>
										<MailPlus className="mr-2 h-4 w-4" /> {messages.invite}
									</Button>
								</DialogTrigger>
								<DialogContent>
									<DialogHeader>
										<DialogTitle>{messages.inviteMember}</DialogTitle>
										<DialogDescription>
											{messages.inviteMemberDescription}
										</DialogDescription>
									</DialogHeader>
									<InviteMemberForm
										onSuccess={() => {
											setInviteDialogOpen(false);
											router.refresh();
										}}
									/>
								</DialogContent>
							</Dialog>
						</CardHeader>
						<CardContent>
							{pendingInvitations.length > 0 ? (
								<div className="space-y-3">
									{pendingInvitations.map((invitation) => (
										<div
											key={invitation.id}
											className="flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-center sm:justify-between"
										>
											<div>
												<p className="text-sm font-medium">
													{invitation.email}
												</p>
												<div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
													<Badge variant="outline">
														{getOrganizationRoleLabel(invitation.role, locale)}
													</Badge>
													<span className="flex items-center gap-1">
														<CalendarDays className="h-3 w-3" />
														{formatDashboardMessage(messages.expiresOn, {
															date: formatOrganizationDate(
																invitation.expiresAt,
																locale,
															),
														})}
													</span>
												</div>
											</div>
											<div className="flex gap-2">
												<Button
													variant="outline"
													size="sm"
													onClick={() => copyInvitationLink(invitation.id)}
												>
													<Copy className="mr-2 h-4 w-4" /> {messages.copyLink}
												</Button>
												<Button
													variant="destructive"
													size="sm"
													onClick={() => cancelInvitation(invitation.id)}
													disabled={
														!canCancelInvitations ||
														!recentAuthentication ||
														!authoritativeOrganizationData ||
														cancelInvitationMutation.isPending
													}
												>
													{messages.revoke}
												</Button>
											</div>
										</div>
									))}
								</div>
							) : (
								<p className="text-sm text-muted-foreground">
									{messages.noActiveInvitationsPeriod}
								</p>
							)}
						</CardContent>
					</Card>

					{permissions.canManageMembers ? (
						<EnterpriseConnectionsCard
							organizationId={initialOrganization.id}
							recentAuthentication={recentAuthentication}
							authoritativeOrganizationData={authoritativeOrganizationData}
							initialSSOProviders={initialSSOProviders}
							initialSCIMProviders={initialSCIMProviders}
							dataUnavailable={enterpriseDataUnavailable}
						/>
					) : null}

					{permissions.canManageMembers ? (
						<OrganizationAuditCard
							key={initialOrganization.id}
							organizationId={initialOrganization.id}
							organizationName={initialOrganization.name}
							currentUserId={currentUser.id}
							initialPage={initialAuditPage}
							initiallyUnavailable={auditUnavailable}
						/>
					) : null}

					<Card className="border-destructive/40">
						<CardHeader>
							<CardTitle>{messages.leaveOrganization}</CardTitle>
							<CardDescription>
								{messages.leaveOrganizationDescription}
							</CardDescription>
						</CardHeader>
						<CardContent className="space-y-4">
							{onlyOwnerCannotLeave ? (
								<Alert variant="destructive">
									<AlertTriangle className="h-4 w-4" />
									<AlertTitle>
										{messages.transferOwnershipBeforeLeaving}
									</AlertTitle>
									<AlertDescription>
										{messages.transferOwnershipDescription}
									</AlertDescription>
								</Alert>
							) : (
								<p className="text-sm text-muted-foreground">
									{messages.leaveOrganizationImpact}
								</p>
							)}
							<AlertDialog>
								<AlertDialogTrigger asChild>
									<Button
										variant="destructive"
										disabled={
											!recentAuthentication ||
											!authoritativeOrganizationData ||
											!canLeaveActiveOrganization ||
											leaveOrganizationMutation.isPending
										}
									>
										{leaveOrganizationMutation.isPending ? (
											<Loader2 className="mr-2 h-4 w-4 animate-spin" />
										) : (
											<LogOut className="mr-2 h-4 w-4" />
										)}
										{formatDashboardMessage(messages.leaveNamedOrganization, {
											name: initialOrganization.name,
										})}
									</Button>
								</AlertDialogTrigger>
								<AlertDialogContent>
									<AlertDialogHeader>
										<AlertDialogTitle>
											{formatDashboardMessage(messages.leaveOrganizationTitle, {
												name: initialOrganization.name,
											})}
										</AlertDialogTitle>
										<AlertDialogDescription>
											{messages.leaveOrganizationDialogDescription}
										</AlertDialogDescription>
									</AlertDialogHeader>
									<AlertDialogFooter>
										<AlertDialogCancel>
											{messages.keepMembership}
										</AlertDialogCancel>
										<AlertDialogAction
											onClick={leaveActiveOrganization}
											className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
										>
											{messages.leaveOrganization}
										</AlertDialogAction>
									</AlertDialogFooter>
								</AlertDialogContent>
							</AlertDialog>
						</CardContent>
					</Card>
				</div>
			) : (
				<Card>
					<CardHeader>
						<CardTitle className="flex items-center gap-2">
							<ShieldCheck className="h-5 w-5" /> {messages.personalWorkspace}
						</CardTitle>
						<CardDescription>
							{messages.personalWorkspaceDescription}
						</CardDescription>
					</CardHeader>
					<CardContent className="flex items-center gap-3">
						<Avatar>
							<AvatarImage src={currentUser.image || undefined} />
							<AvatarFallback>{currentUser.name.charAt(0)}</AvatarFallback>
						</Avatar>
						<div>
							<p className="text-sm font-medium">{currentUser.name}</p>
							<p className="text-xs text-muted-foreground">
								{currentUser.email}
							</p>
						</div>
					</CardContent>
				</Card>
			)}
		</div>
	);
}

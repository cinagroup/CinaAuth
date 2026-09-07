"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	FolderKanban,
	Loader2,
	Pencil,
	Plus,
	ShieldCheck,
	Trash2,
	UserPlus,
	Users,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { useDashboardI18n } from "@/components/dashboard/use-dashboard-i18n";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
	DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import {
	addOrganizationTeamMember,
	createOrganizationRole,
	createOrganizationTeam,
	deleteOrganizationRole,
	deleteOrganizationTeam,
	listOrganizationTeamMembers,
	removeOrganizationTeamMember,
	updateOrganizationRole,
	updateOrganizationTeam,
} from "@/data/organization/advanced-organization-mutations";
import { useMemberRoleUpdateMutation } from "@/data/organization/member-role-update-mutation";
import type {
	DynamicRoleDraft,
	OrganizationDynamicRoleSummary,
	OrganizationTeamSummary,
} from "@/lib/advanced-organization-console";
import {
	createEmptyDynamicRoleDraft,
	getDynamicRoleDraftError,
	getMemberRoleSelectionError,
	getTeamNameError,
	ORGANIZATION_PERMISSION_RESOURCES,
	ORGANIZATION_PERMISSION_STATEMENT,
	toggleRolePermission,
	toRolePermissionPayload,
} from "@/lib/advanced-organization-console";
import type { DashboardMessages } from "@/lib/dashboard-i18n";
import { formatDashboardMessage } from "@/lib/dashboard-i18n";
import type { OrganizationMember } from "@/lib/organization-console";
import {
	getOrganizationRoleLabel,
	parseOrganizationRoles,
} from "@/lib/organization-console";

type AdvancedOrganizationCardProps = {
	organizationId: string;
	members: OrganizationMember[];
	initialTeams: OrganizationTeamSummary[];
	initialDynamicRoles: OrganizationDynamicRoleSummary[];
	teamPermissions: {
		create: boolean;
		update: boolean;
		delete: boolean;
	};
	rolePermissions: {
		create: boolean;
		update: boolean;
		delete: boolean;
	};
	recentAuthentication: boolean;
	authoritativeOrganizationData: boolean;
	dataUnavailable: {
		teams: boolean;
		roles: boolean;
	};
};

const mutationError = (error: unknown, fallback: string) =>
	error instanceof Error && error.message ? error.message : fallback;

const localizeAdvancedError = (error: string, messages: DashboardMessages) => {
	const errorMessages: Record<string, string> = {
		"Enter a team name.": messages.teamNameRequired,
		"Team names must be 64 characters or less.": messages.teamNameTooLong,
		"Team names cannot contain control characters.":
			messages.teamNameControlCharacters,
		"Enter a role name.": messages.roleNameRequired,
		"Owner, admin, and member are reserved roles.": messages.reservedRoleName,
		"Role names must start with a letter and use lowercase letters, numbers, hyphens, or underscores.":
			messages.invalidRoleName,
		"That role name already exists.": messages.duplicateRoleName,
		"Select at least one permission.": messages.permissionRequired,
		"Select at least one role.": messages.roleSelectionRequired,
		"One or more selected roles are no longer available.":
			messages.staleRoleSelection,
		"You cannot change organization roles.": messages.roleChangeForbidden,
		"Only an owner can change another owner role.":
			messages.ownerRoleChangeForbidden,
		"Only an owner can assign the owner role.":
			messages.ownerRoleAssignmentForbidden,
		"Transfer ownership before removing the final owner role.":
			messages.finalOwnerRole,
	};
	return errorMessages[error] ?? error;
};

const RoleEditorDialog = ({
	organizationId,
	roles,
	role,
	disabled,
	onSaved,
}: {
	organizationId: string;
	roles: OrganizationDynamicRoleSummary[];
	role?: OrganizationDynamicRoleSummary;
	disabled: boolean;
	onSaved: () => void;
}) => {
	const { messages } = useDashboardI18n();
	const permissionResourceLabels = {
		organization: messages.permissionResourceOrganization,
		member: messages.permissionResourceMember,
		invitation: messages.permissionResourceInvitation,
		team: messages.permissionResourceTeam,
		ac: messages.permissionResourceAccessControl,
	} as const;
	const permissionActionLabels: Record<string, string> = {
		create: messages.permissionActionCreate,
		read: messages.permissionActionRead,
		update: messages.permissionActionUpdate,
		delete: messages.permissionActionDelete,
		cancel: messages.permissionActionCancel,
	};
	const [open, setOpen] = useState(false);
	const [draft, setDraft] = useState<DynamicRoleDraft>(() =>
		role
			? {
					role: role.role,
					permission: toRolePermissionPayload(role.permission),
				}
			: createEmptyDynamicRoleDraft(),
	);
	const mutation = useMutation({
		mutationFn: async () => {
			const error = getDynamicRoleDraftError({
				draft,
				roles,
				editingRole: role?.role,
			});
			if (error) throw new Error(localizeAdvancedError(error, messages));
			const permission = toRolePermissionPayload(draft.permission);
			if (role) {
				await updateOrganizationRole({
					organizationId,
					roleName: role.role,
					nextRoleName: role.role,
					permission,
				});
				return;
			}
			await createOrganizationRole({
				organizationId,
				role: draft.role,
				permission,
			});
		},
		onSuccess: () => {
			toast.success(role ? messages.roleUpdated : messages.roleCreated);
			setOpen(false);
			onSaved();
		},
		onError: (error) =>
			toast.error(mutationError(error, messages.unableSaveRole)),
	});

	const onOpenChange = (nextOpen: boolean) => {
		setOpen(nextOpen);
		if (nextOpen) {
			setDraft(
				role
					? {
							role: role.role,
							permission: toRolePermissionPayload(role.permission),
						}
					: createEmptyDynamicRoleDraft(),
			);
		}
	};

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogTrigger asChild>
				<Button
					variant={role ? "outline" : "default"}
					size={role ? "icon" : "sm"}
					disabled={disabled}
					aria-label={
						role
							? formatDashboardMessage(messages.editNamedItem, {
									name: role.role,
								})
							: undefined
					}
				>
					{role ? (
						<Pencil className="h-4 w-4" />
					) : (
						<>
							<Plus className="mr-2 h-4 w-4" /> {messages.newRole}
						</>
					)}
				</Button>
			</DialogTrigger>
			<DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
				<DialogHeader>
					<DialogTitle>
						{role ? messages.editRole : messages.createRole}
					</DialogTitle>
					<DialogDescription>
						{messages.rolePermissionsDescription}
					</DialogDescription>
				</DialogHeader>
				<div className="space-y-5">
					<div className="space-y-2">
						<Label htmlFor={`role-name-${role?.id ?? "new"}`}>
							{messages.roleName}
						</Label>
						<Input
							id={`role-name-${role?.id ?? "new"}`}
							value={draft.role}
							onChange={(event) =>
								setDraft((current) => ({
									...current,
									role: event.target.value,
								}))
							}
							placeholder={messages.roleNamePlaceholder}
							disabled={mutation.isPending || Boolean(role)}
						/>
						<p className="text-xs text-muted-foreground">
							{messages.roleNameDescription}
						</p>
					</div>
					<div className="grid gap-3 sm:grid-cols-2">
						{ORGANIZATION_PERMISSION_RESOURCES.map((resource) => (
							<div key={resource} className="rounded-lg border p-3">
								<p className="mb-3 text-sm font-medium capitalize">
									{permissionResourceLabels[resource]}
								</p>
								<div className="space-y-2">
									{ORGANIZATION_PERMISSION_STATEMENT[resource].map((action) => {
										const id = `${role?.id ?? "new"}-${resource}-${action}`;
										return (
											<div key={action} className="flex items-center gap-2">
												<Checkbox
													id={id}
													checked={Boolean(
														draft.permission[resource]?.includes(action),
													)}
													onCheckedChange={(checked) =>
														setDraft((current) =>
															toggleRolePermission(
																current,
																resource,
																action,
																checked === true,
															),
														)
													}
													disabled={mutation.isPending}
												/>
												<Label htmlFor={id} className="font-normal capitalize">
													{permissionActionLabels[action] ?? action}
												</Label>
											</div>
										);
									})}
								</div>
							</div>
						))}
					</div>
				</div>
				<DialogFooter>
					<Button
						onClick={() => mutation.mutate()}
						disabled={mutation.isPending}
					>
						{mutation.isPending && (
							<Loader2 className="mr-2 h-4 w-4 animate-spin" />
						)}
						{role ? messages.saveRole : messages.createRole}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
};

const TeamEditorDialog = ({
	organizationId,
	team,
	disabled,
	onSaved,
}: {
	organizationId: string;
	team?: OrganizationTeamSummary;
	disabled: boolean;
	onSaved: () => void;
}) => {
	const { messages } = useDashboardI18n();
	const [open, setOpen] = useState(false);
	const [name, setName] = useState(team?.name ?? "");
	const mutation = useMutation({
		mutationFn: async () => {
			const error = getTeamNameError(name);
			if (error) throw new Error(localizeAdvancedError(error, messages));
			if (team) {
				await updateOrganizationTeam({ organizationId, teamId: team.id, name });
				return;
			}
			await createOrganizationTeam({ organizationId, name });
		},
		onSuccess: () => {
			toast.success(team ? messages.teamRenamed : messages.teamCreated);
			setOpen(false);
			onSaved();
		},
		onError: (error) =>
			toast.error(mutationError(error, messages.unableSaveTeam)),
	});

	return (
		<Dialog
			open={open}
			onOpenChange={(nextOpen) => {
				setOpen(nextOpen);
				if (nextOpen) setName(team?.name ?? "");
			}}
		>
			<DialogTrigger asChild>
				<Button
					variant={team ? "outline" : "default"}
					size={team ? "icon" : "sm"}
					disabled={disabled}
					aria-label={
						team
							? formatDashboardMessage(messages.renameNamedItem, {
									name: team.name,
								})
							: undefined
					}
				>
					{team ? (
						<Pencil className="h-4 w-4" />
					) : (
						<>
							<Plus className="mr-2 h-4 w-4" /> {messages.newTeam}
						</>
					)}
				</Button>
			</DialogTrigger>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>
						{team ? messages.renameTeam : messages.createTeam}
					</DialogTitle>
					<DialogDescription>{messages.teamDescription}</DialogDescription>
				</DialogHeader>
				<div className="space-y-2">
					<Label htmlFor={`team-name-${team?.id ?? "new"}`}>
						{messages.teamName}
					</Label>
					<Input
						id={`team-name-${team?.id ?? "new"}`}
						value={name}
						onChange={(event) => setName(event.target.value)}
						disabled={mutation.isPending}
						placeholder={messages.teamNamePlaceholder}
					/>
				</div>
				<DialogFooter>
					<Button
						onClick={() => mutation.mutate()}
						disabled={mutation.isPending}
					>
						{mutation.isPending && (
							<Loader2 className="mr-2 h-4 w-4 animate-spin" />
						)}
						{team ? messages.saveName : messages.createTeam}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
};

const TeamMembershipDialog = ({
	organizationId,
	team,
	members,
	disabled,
}: {
	organizationId: string;
	team: OrganizationTeamSummary;
	members: OrganizationMember[];
	disabled: boolean;
}) => {
	const { messages } = useDashboardI18n();
	const queryClient = useQueryClient();
	const [open, setOpen] = useState(false);
	const [selectedUserId, setSelectedUserId] = useState("");
	const queryKey = ["organization", organizationId, "team", team.id, "members"];
	const membershipQuery = useQuery({
		queryKey,
		queryFn: () => listOrganizationTeamMembers(team.id),
		enabled: open,
	});
	const membershipMutation = useMutation({
		mutationFn: ({
			action,
			userId,
		}: {
			action: "add" | "remove";
			userId: string;
		}) =>
			action === "add"
				? addOrganizationTeamMember({ organizationId, teamId: team.id, userId })
				: removeOrganizationTeamMember({
						organizationId,
						teamId: team.id,
						userId,
					}),
		onSuccess: async () => {
			setSelectedUserId("");
			await queryClient.invalidateQueries({ queryKey });
			toast.success(messages.teamMembershipUpdated);
		},
		onError: (error) =>
			toast.error(mutationError(error, messages.unableUpdateTeamMembership)),
	});
	const membershipUserIds = new Set(
		(membershipQuery.data ?? []).map((membership) => membership.userId),
	);
	const eligibleMembers = members.filter(
		(member) => !membershipUserIds.has(member.userId),
	);

	return (
		<Dialog open={open} onOpenChange={setOpen}>
			<DialogTrigger asChild>
				<Button variant="outline" size="sm">
					<Users className="mr-2 h-4 w-4" /> {messages.members}
				</Button>
			</DialogTrigger>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>
						{formatDashboardMessage(messages.teamMembersTitle, {
							name: team.name,
						})}
					</DialogTitle>
					<DialogDescription>
						{messages.teamMembersDescription}
					</DialogDescription>
				</DialogHeader>
				{membershipQuery.isPending ? (
					<div className="flex items-center gap-2 text-sm text-muted-foreground">
						<Loader2 className="h-4 w-4 animate-spin" />
						{messages.loadingMembers}
					</div>
				) : membershipQuery.isError ? (
					<Alert variant="destructive">
						<AlertTitle>{messages.teamMembershipUnavailable}</AlertTitle>
						<AlertDescription>
							{messages.teamMembershipUnavailableDescription}
						</AlertDescription>
					</Alert>
				) : (
					<div className="space-y-4">
						<div className="space-y-2">
							{(membershipQuery.data ?? []).length > 0 ? (
								(membershipQuery.data ?? []).map((membership) => {
									const member = members.find(
										(candidate) => candidate.userId === membership.userId,
									);
									return (
										<div
											key={membership.id}
											className="flex items-center justify-between rounded-lg border p-3"
										>
											<div>
												<p className="text-sm font-medium">
													{member?.user.name ?? messages.unknownMember}
												</p>
												<p className="text-xs text-muted-foreground">
													{member?.user.email ?? membership.userId}
												</p>
											</div>
											<Button
												variant="ghost"
												size="sm"
												disabled={disabled || membershipMutation.isPending}
												onClick={() =>
													membershipMutation.mutate({
														action: "remove",
														userId: membership.userId,
													})
												}
											>
												{messages.remove}
											</Button>
										</div>
									);
								})
							) : (
								<p className="text-sm text-muted-foreground">
									{messages.noTeamMembers}
								</p>
							)}
						</div>
						{eligibleMembers.length > 0 && (
							<div className="flex gap-2">
								<Select
									value={selectedUserId}
									onValueChange={setSelectedUserId}
									disabled={disabled || membershipMutation.isPending}
								>
									<SelectTrigger
										aria-label={formatDashboardMessage(
											messages.addMemberToTeam,
											{
												name: team.name,
											},
										)}
									>
										<SelectValue
											placeholder={messages.selectOrganizationMember}
										/>
									</SelectTrigger>
									<SelectContent>
										{eligibleMembers.map((member) => (
											<SelectItem key={member.id} value={member.userId}>
												{member.user.name} · {member.user.email}
											</SelectItem>
										))}
									</SelectContent>
								</Select>
								<Button
									disabled={
										disabled || !selectedUserId || membershipMutation.isPending
									}
									onClick={() =>
										membershipMutation.mutate({
											action: "add",
											userId: selectedUserId,
										})
									}
								>
									<UserPlus className="h-4 w-4" />
								</Button>
							</div>
						)}
					</div>
				)}
			</DialogContent>
		</Dialog>
	);
};

export const AdvancedMemberRoleEditor = ({
	member,
	actorRole,
	dynamicRoles,
	ownerCount,
	actorCanManage,
	disabled,
}: {
	member: OrganizationMember;
	actorRole: string;
	dynamicRoles: OrganizationDynamicRoleSummary[];
	ownerCount: number;
	actorCanManage: boolean;
	disabled: boolean;
}) => {
	const { locale, messages } = useDashboardI18n();
	const router = useRouter();
	const [open, setOpen] = useState(false);
	const [selectedRoles, setSelectedRoles] = useState<string[]>(() =>
		parseOrganizationRoles(member.role),
	);
	const updateMutation = useMemberRoleUpdateMutation();
	const availableRoles = [
		"owner",
		"admin",
		"member",
		...dynamicRoles.map((role) => role.role),
	];
	const staleRoles = selectedRoles.filter(
		(role) => !availableRoles.includes(role),
	);
	const actorIsOwner = parseOrganizationRoles(actorRole).includes("owner");
	const targetIsFinalOwner =
		parseOrganizationRoles(member.role).includes("owner") && ownerCount <= 1;

	const submit = () => {
		const error = getMemberRoleSelectionError({
			actorRole,
			targetRole: member.role,
			selectedRoles,
			availableRoles,
			ownerCount,
			actorCanManage,
		});
		if (error) {
			toast.error(localizeAdvancedError(error, messages));
			return;
		}
		updateMutation.mutate(
			{
				memberId: member.id,
				role: selectedRoles,
				organizationId: member.organizationId,
			},
			{
				onSuccess: () => {
					setOpen(false);
					router.refresh();
				},
			},
		);
	};

	return (
		<Dialog
			open={open}
			onOpenChange={(nextOpen) => {
				setOpen(nextOpen);
				if (nextOpen) setSelectedRoles(parseOrganizationRoles(member.role));
			}}
		>
			<DialogTrigger asChild>
				<Button variant="outline" size="sm" disabled={disabled}>
					{messages.manageRoles}
				</Button>
			</DialogTrigger>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>
						{formatDashboardMessage(messages.rolesForMember, {
							name: member.user.name,
						})}
					</DialogTitle>
					<DialogDescription>
						{messages.multipleRolesDescription}
					</DialogDescription>
				</DialogHeader>
				<div className="space-y-3">
					{availableRoles.map((role) => {
						const checked = selectedRoles.includes(role);
						const ownerLocked =
							role === "owner" &&
							(!actorIsOwner || (targetIsFinalOwner && checked));
						const id = `${member.id}-role-${role}`;
						return (
							<div
								key={role}
								className="flex items-center gap-2 rounded-lg border p-3"
							>
								<Checkbox
									id={id}
									checked={checked}
									disabled={ownerLocked || updateMutation.isPending}
									onCheckedChange={(nextChecked) =>
										setSelectedRoles((current) =>
											nextChecked === true
												? [...new Set([...current, role])]
												: current.filter((candidate) => candidate !== role),
										)
									}
								/>
								<Label htmlFor={id} className="font-normal">
									{getOrganizationRoleLabel(role, locale)}
								</Label>
							</div>
						);
					})}
					{staleRoles.length > 0 && (
						<Alert variant="destructive">
							<AlertTitle>{messages.unavailableRoleDefinitions}</AlertTitle>
							<AlertDescription>
								{formatDashboardMessage(messages.staleRolesDescription, {
									roles: staleRoles.join(", "),
								})}
							</AlertDescription>
						</Alert>
					)}
				</div>
				<DialogFooter>
					<Button onClick={submit} disabled={updateMutation.isPending}>
						{updateMutation.isPending && (
							<Loader2 className="mr-2 h-4 w-4 animate-spin" />
						)}
						{messages.saveRoles}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
};

export const AdvancedOrganizationCard = ({
	organizationId,
	members,
	initialTeams,
	initialDynamicRoles,
	teamPermissions,
	rolePermissions,
	recentAuthentication,
	authoritativeOrganizationData,
	dataUnavailable,
}: AdvancedOrganizationCardProps) => {
	const { locale, messages } = useDashboardI18n();
	const permissionResourceLabels = {
		organization: messages.permissionResourceOrganization,
		member: messages.permissionResourceMember,
		invitation: messages.permissionResourceInvitation,
		team: messages.permissionResourceTeam,
		ac: messages.permissionResourceAccessControl,
	} as const;
	const permissionActionLabels: Record<string, string> = {
		create: messages.permissionActionCreate,
		read: messages.permissionActionRead,
		update: messages.permissionActionUpdate,
		delete: messages.permissionActionDelete,
		cancel: messages.permissionActionCancel,
	};
	const router = useRouter();
	const mutationContextUnavailable =
		!recentAuthentication || !authoritativeOrganizationData;
	const deleteTeamMutation = useMutation({
		mutationFn: (teamId: string) =>
			deleteOrganizationTeam({ organizationId, teamId }),
		onSuccess: () => {
			toast.success(messages.teamDeleted);
			router.refresh();
		},
		onError: (error) =>
			toast.error(mutationError(error, messages.unableDeleteTeam)),
	});
	const deleteRoleMutation = useMutation({
		mutationFn: (roleName: string) =>
			deleteOrganizationRole({ organizationId, roleName }),
		onSuccess: () => {
			toast.success(messages.roleDeleted);
			router.refresh();
		},
		onError: (error) =>
			toast.error(mutationError(error, messages.unableDeleteRole)),
	});

	return (
		<div className="grid gap-6 lg:grid-cols-2">
			<Card>
				<CardHeader className="flex flex-row items-center justify-between gap-4">
					<div>
						<CardTitle className="flex items-center gap-2">
							<FolderKanban className="h-5 w-5" /> {messages.teams}
						</CardTitle>
						<CardDescription>{messages.teamsDescription}</CardDescription>
					</div>
					<TeamEditorDialog
						organizationId={organizationId}
						disabled={
							!teamPermissions.create ||
							mutationContextUnavailable ||
							dataUnavailable.teams
						}
						onSaved={() => router.refresh()}
					/>
				</CardHeader>
				<CardContent className="space-y-3">
					{dataUnavailable.teams ? (
						<Alert variant="destructive">
							<AlertTitle>{messages.teamsUnavailable}</AlertTitle>
							<AlertDescription>
								{messages.teamsUnavailableDescription}
							</AlertDescription>
						</Alert>
					) : initialTeams.length > 0 ? (
						initialTeams.map((team) => (
							<div
								key={team.id}
								className="flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-center sm:justify-between"
							>
								<div>
									<p className="text-sm font-medium">{team.name}</p>
									<p className="text-xs text-muted-foreground">
										{formatDashboardMessage(messages.teamId, {
											id: team.id.slice(-8),
										})}
									</p>
								</div>
								<div className="flex items-center gap-2">
									<TeamMembershipDialog
										organizationId={organizationId}
										team={team}
										members={members}
										disabled={
											!teamPermissions.update || mutationContextUnavailable
										}
									/>
									{(teamPermissions.update || teamPermissions.delete) && (
										<>
											{teamPermissions.update && (
												<TeamEditorDialog
													organizationId={organizationId}
													team={team}
													disabled={mutationContextUnavailable}
													onSaved={() => router.refresh()}
												/>
											)}
											{teamPermissions.delete && (
												<AlertDialog>
													<AlertDialogTrigger asChild>
														<Button
															variant="destructive"
															size="icon"
															disabled={
																mutationContextUnavailable ||
																deleteTeamMutation.isPending
															}
															aria-label={formatDashboardMessage(
																messages.deleteNamedItem,
																{ name: team.name },
															)}
														>
															<Trash2 className="h-4 w-4" />
														</Button>
													</AlertDialogTrigger>
													<AlertDialogContent>
														<AlertDialogHeader>
															<AlertDialogTitle>
																{formatDashboardMessage(
																	messages.deleteNamedItemTitle,
																	{
																		name: team.name,
																	},
																)}
															</AlertDialogTitle>
															<AlertDialogDescription>
																{messages.deleteTeamDescription}
															</AlertDialogDescription>
														</AlertDialogHeader>
														<AlertDialogFooter>
															<AlertDialogCancel>
																{messages.cancel}
															</AlertDialogCancel>
															<AlertDialogAction
																onClick={() =>
																	deleteTeamMutation.mutate(team.id)
																}
															>
																{messages.deleteTeam}
															</AlertDialogAction>
														</AlertDialogFooter>
													</AlertDialogContent>
												</AlertDialog>
											)}
										</>
									)}
								</div>
							</div>
						))
					) : (
						<p className="text-sm text-muted-foreground">{messages.noTeams}</p>
					)}
				</CardContent>
			</Card>

			<Card>
				<CardHeader className="flex flex-row items-center justify-between gap-4">
					<div>
						<CardTitle className="flex items-center gap-2">
							<ShieldCheck className="h-5 w-5" /> {messages.customRoles}
						</CardTitle>
						<CardDescription>{messages.customRolesDescription}</CardDescription>
					</div>
					<RoleEditorDialog
						organizationId={organizationId}
						roles={initialDynamicRoles}
						disabled={
							!rolePermissions.create ||
							mutationContextUnavailable ||
							dataUnavailable.roles
						}
						onSaved={() => router.refresh()}
					/>
				</CardHeader>
				<CardContent className="space-y-3">
					{dataUnavailable.roles ? (
						<Alert variant="destructive">
							<AlertTitle>{messages.roleDefinitionsUnavailable}</AlertTitle>
							<AlertDescription>
								{messages.roleDefinitionsUnavailableDescription}
							</AlertDescription>
						</Alert>
					) : initialDynamicRoles.length > 0 ? (
						initialDynamicRoles.map((role) => (
							<div key={role.id} className="rounded-lg border p-4">
								<div className="flex items-start justify-between gap-3">
									<div>
										<p className="text-sm font-medium">
											{getOrganizationRoleLabel(role.role, locale)}
										</p>
										<p className="text-xs text-muted-foreground">{role.role}</p>
									</div>
									{(rolePermissions.update || rolePermissions.delete) && (
										<div className="flex gap-2">
											{rolePermissions.update && (
												<RoleEditorDialog
													organizationId={organizationId}
													roles={initialDynamicRoles}
													role={role}
													disabled={mutationContextUnavailable}
													onSaved={() => router.refresh()}
												/>
											)}
											{rolePermissions.delete && (
												<AlertDialog>
													<AlertDialogTrigger asChild>
														<Button
															variant="destructive"
															size="icon"
															disabled={
																mutationContextUnavailable ||
																deleteRoleMutation.isPending
															}
															aria-label={formatDashboardMessage(
																messages.deleteNamedItem,
																{ name: role.role },
															)}
														>
															<Trash2 className="h-4 w-4" />
														</Button>
													</AlertDialogTrigger>
													<AlertDialogContent>
														<AlertDialogHeader>
															<AlertDialogTitle>
																{formatDashboardMessage(
																	messages.deleteNamedItemTitle,
																	{
																		name: role.role,
																	},
																)}
															</AlertDialogTitle>
															<AlertDialogDescription>
																{messages.deleteRoleDescription}
															</AlertDialogDescription>
														</AlertDialogHeader>
														<AlertDialogFooter>
															<AlertDialogCancel>
																{messages.cancel}
															</AlertDialogCancel>
															<AlertDialogAction
																onClick={() =>
																	deleteRoleMutation.mutate(role.role)
																}
															>
																{messages.deleteRole}
															</AlertDialogAction>
														</AlertDialogFooter>
													</AlertDialogContent>
												</AlertDialog>
											)}
										</div>
									)}
								</div>
								<div className="mt-3 flex flex-wrap gap-1.5">
									{ORGANIZATION_PERMISSION_RESOURCES.flatMap((resource) =>
										(role.permission[resource] ?? []).map((action) => (
											<Badge key={`${resource}:${action}`} variant="secondary">
												{permissionResourceLabels[resource]}:
												{permissionActionLabels[action] ?? action}
											</Badge>
										)),
									)}
								</div>
							</div>
						))
					) : (
						<p className="text-sm text-muted-foreground">
							{messages.noCustomRoles}
						</p>
					)}
				</CardContent>
			</Card>
		</div>
	);
};

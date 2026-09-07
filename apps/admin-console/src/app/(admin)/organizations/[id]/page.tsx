"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { AlertCircle, RefreshCw } from "lucide-react";
import { useParams, useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { PageHeader } from "@/components/layout/page-header";
import { RoleGuard } from "@/components/role-guard";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pagination } from "@/components/ui/pagination";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import { fetchAdminJson, fetchAdminResponse } from "@/lib/client-api";
import { useI18n } from "@/lib/i18n/i18n-context";
import { InviteDialog } from "./invite-dialog";

interface MemberDTO {
	id: string;
	userId: string;
	role: string;
	createdAt: string;
	user?: { name?: string; email?: string; image?: string | null };
}

interface OrganizationDTO {
	name?: string;
	slug?: string;
	invitations?: Record<string, unknown>[];
}

interface ApiResponse<T> {
	ok?: boolean;
	data?: T;
}

const MEMBER_PAGE_SIZE = 20;

export default function OrganizationDetailPage() {
	const params = useParams<{ id: string }>();
	return <OrganizationDetail key={params.id} orgId={params.id} />;
}

function OrganizationDetail({ orgId }: { orgId: string }) {
	const { t } = useI18n();
	const qc = useQueryClient();
	const router = useRouter();
	const [editOpen, setEditOpen] = useState(false);
	const [editName, setEditName] = useState("");
	const [editSlug, setEditSlug] = useState("");
	const [memberOffset, setMemberOffset] = useState(0);

	const {
		data: org,
		isFetching: orgLoading,
		isError: orgError,
		refetch: refetchOrg,
	} = useQuery({
		queryKey: ["organization", orgId],
		queryFn: async () => {
			const d = await fetchAdminJson<ApiResponse<OrganizationDTO>>(
				`/api/admin/organizations/${orgId}`,
			);
			return d.data ?? null;
		},
	});

	const {
		data: membersData,
		isFetching: membersLoading,
		isError: membersError,
		refetch: refetchMembers,
	} = useQuery({
		queryKey: ["organization-members", orgId, memberOffset],
		queryFn: async () => {
			const d = await fetchAdminJson<
				ApiResponse<{ members: MemberDTO[]; total: number }>
			>(
				`/api/admin/organizations/${orgId}/members?${new URLSearchParams({ limit: String(MEMBER_PAGE_SIZE), offset: String(memberOffset) })}`,
			);
			return d.data ?? { members: [], total: 0 };
		},
	});

	const members = useMemo(() => membersData?.members ?? [], [membersData]);
	const membersTotal = membersData?.total ?? 0;

	const removeMember = async (memberId: string) => {
		const r = await fetchAdminResponse(
			`/api/admin/organizations/${orgId}/members/${memberId}`,
			{
				method: "DELETE",
			},
		);
		if (!r.ok) {
			toast.error(t("toast.deleteFailed"));
			return false;
		}
		await qc.invalidateQueries({ queryKey: ["organization-members", orgId] });
		if (members.length === 1 && memberOffset > 0)
			setMemberOffset(Math.max(0, memberOffset - MEMBER_PAGE_SIZE));
		return true;
	};

	const changeRole = useMutation({
		mutationFn: async ({
			memberId,
			role,
		}: {
			memberId: string;
			role: string;
		}) => {
			const r = await fetchAdminResponse(
				`/api/admin/organizations/${orgId}/members/${memberId}/role`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ role }),
				},
			);
			if (r.ok) {
				toast.success(t("toast.roleChanged"));
				await qc.invalidateQueries({
					queryKey: ["organization-members", orgId],
				});
			} else {
				toast.error(t("toast.actionFailed"));
			}
		},
		onError: () => toast.error(t("toast.actionFailed")),
	});

	const saveOrg = useMutation({
		mutationFn: async () => {
			const r = await fetchAdminResponse(
				`/api/admin/organizations/${orgId}/update`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ name: editName, slug: editSlug }),
				},
			);
			if (r.ok) {
				toast.success(t("toast.orgUpdated"));
				setEditOpen(false);
				await qc.invalidateQueries({ queryKey: ["organization", orgId] });
			} else {
				// Keep the dialog open so the admin can correct and retry.
				toast.error(t("toast.saveFailed"));
			}
		},
		onError: () => toast.error(t("toast.saveFailed")),
	});

	const deleteOrg = async () => {
		const r = await fetchAdminResponse(
			`/api/admin/organizations/${orgId}/delete`,
			{
				method: "POST",
			},
		);
		if (r.ok) {
			toast.success(t("toast.orgDeleted"));
			// router.push is a soft navigation, so the cached ['organizations']
			// list survives; invalidate it or the deleted org lingers in the
			// list for up to the 30s staleTime.
			await qc.invalidateQueries({ queryKey: ["organizations"] });
			router.push("/organizations");
			return true;
		} else {
			toast.error(t("toast.deleteFailed"));
			return false;
		}
	};

	const memberColumns: ColumnDef<MemberDTO>[] = [
		{
			accessorKey: "user.email",
			header: t("users.col.email"),
			cell: ({ row }) => (
				<span className="font-medium text-ink">
					{row.original.user?.email ?? row.original.userId}
				</span>
			),
		},
		{
			accessorKey: "user.name",
			header: t("users.col.name"),
			cell: ({ row }) => row.original.user?.name ?? "—",
		},
		{
			accessorKey: "role",
			header: t("users.col.role"),
			cell: ({ row }) => {
				const role = row.original.role;
				if (role === "owner") {
					return <Badge variant="success">{role}</Badge>;
				}
				return (
					<RoleGuard allow={["super_admin"]} fallback={<Badge>{role}</Badge>}>
						<Select
							value={role}
							disabled={changeRole.isPending}
							onValueChange={(role) =>
								changeRole.mutate({ memberId: row.original.id, role })
							}
						>
							<SelectTrigger
								aria-label={t("organizations.memberRoleFor", {
									user: row.original.user?.email ?? row.original.userId,
								})}
								className="h-7 w-[110px] text-[13px]"
							>
								<SelectValue />
							</SelectTrigger>
							<SelectContent>
								<SelectItem value="admin">admin</SelectItem>
								<SelectItem value="member">member</SelectItem>
							</SelectContent>
						</Select>
					</RoleGuard>
				);
			},
		},
		{
			id: "actions",
			header: "",
			cell: ({ row }) => (
				<RoleGuard allow={["super_admin"]}>
					{row.original.role !== "owner" && (
						<ConfirmDialog
							trigger={
								<Button variant="ghost" size="sm" className="text-error">
									{t("common.remove")}
								</Button>
							}
							title={t("organizations.removeMember")}
							onConfirm={() => removeMember(row.original.id)}
						/>
					)}
				</RoleGuard>
			),
		},
	];

	const table = useReactTable({
		data: members,
		columns: memberColumns,
		getCoreRowModel: getCoreRowModel(),
	});

	if (orgError) {
		return (
			<div className="max-w-2xl">
				<PageHeader
					title={t("error.generic.title")}
					backHref="/organizations"
					backLabel={t("nav.organizations")}
				/>
				<EmptyState>
					<AlertCircle size={20} className="text-error" aria-hidden />
					<span>{t("error.generic.message")}</span>
					<Button
						variant="secondary"
						size="sm"
						onClick={() => void refetchOrg()}
					>
						<RefreshCw size={15} />
						{t("error.retry")}
					</Button>
				</EmptyState>
			</div>
		);
	}

	return (
		<div>
			<PageHeader
				title={org?.name ?? (orgLoading ? "…" : t("organizations.title"))}
				backHref="/organizations"
				backLabel={t("nav.organizations")}
			>
				<RoleGuard allow={["super_admin"]}>
					<InviteDialog orgId={orgId} />
					<Button
						variant="secondary"
						size="sm"
						onClick={() => {
							setEditName(org?.name ?? "");
							setEditSlug(org?.slug ?? "");
							setEditOpen(true);
						}}
						disabled={!org}
					>
						{t("organizations.editOrg")}
					</Button>
					<ConfirmDialog
						trigger={
							<Button variant="danger" size="sm">
								{t("organizations.deleteOrg")}
							</Button>
						}
						title={t("organizations.deleteOrg")}
						description={t("organizations.deleteConfirm")}
						danger
						confirmText={t("common.delete")}
						confirmationText={org?.slug ?? orgId}
						confirmationLabel={t("common.typeToConfirm", {
							value: org?.slug ?? orgId,
						})}
						onConfirm={deleteOrg}
					/>
				</RoleGuard>
			</PageHeader>
			<div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-[14px] leading-5 text-body">
				<span>
					{t("organizations.slug")}: {org?.slug ?? "—"}
				</span>
				<span>
					{t("organizations.membersLabel")}:{" "}
					{membersError || !membersData ? "—" : membersTotal}
				</span>
			</div>
			<DataTable
				table={table}
				emptyLabel={t("organizations.noMembers")}
				isLoading={membersLoading && !membersData}
				isError={membersError}
				onRetry={() => void refetchMembers()}
			/>
			{membersTotal > 0 && (
				<fieldset disabled={membersLoading}>
					<Pagination
						offset={memberOffset}
						pageSize={MEMBER_PAGE_SIZE}
						total={membersTotal}
						onPrev={() =>
							setMemberOffset(Math.max(0, memberOffset - MEMBER_PAGE_SIZE))
						}
						onNext={() => setMemberOffset(memberOffset + MEMBER_PAGE_SIZE)}
					/>
				</fieldset>
			)}

			{/* Pending invitations */}
			{org?.invitations && org.invitations.length > 0 && (
				<div className="mt-6">
					<h3 className="mb-3 font-mono text-[12px] uppercase text-mute">
						{t("organizations.invitations")} ({org.invitations.length})
					</h3>
					<div className="space-y-2">
						{org.invitations.map((inv: Record<string, unknown>) => (
							<div
								key={String(inv.id)}
								className="flex flex-col gap-2 rounded-[var(--radius-sm)] border border-hairline bg-canvas px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
							>
								<div className="flex min-w-0 flex-wrap items-center gap-3 text-[14px]">
									<span className="font-medium text-ink">
										{String(inv.email ?? "—")}
									</span>
									<Badge variant="muted">{String(inv.role ?? "member")}</Badge>
									<span className="text-mute">
										{String(inv.status ?? "pending")}
									</span>
								</div>
								<RoleGuard allow={["super_admin"]}>
									<ConfirmDialog
										trigger={
											<Button variant="ghost" size="sm" className="text-error">
												{t("organizations.cancelInvite")}
											</Button>
										}
										title={t("organizations.cancelInvite")}
										onConfirm={async () => {
											const r = await fetchAdminResponse(
												`/api/admin/organizations/${orgId}/invitations/${inv.id}`,
												{
													method: "DELETE",
												},
											);
											// Don't claim the invite was cancelled unless it was.
											if (r.ok) {
												toast.success(t("organizations.inviteCanceled"));
												await qc.invalidateQueries({
													queryKey: ["organization", orgId],
												});
												return true;
											} else {
												toast.error(t("toast.actionFailed"));
												return false;
											}
										}}
									/>
								</RoleGuard>
							</div>
						))}
					</div>
				</div>
			)}

			{/* Edit organization dialog */}
			<Dialog
				open={editOpen}
				onOpenChange={(open) => {
					if (!saveOrg.isPending) setEditOpen(open);
				}}
			>
				<DialogContent>
					<DialogHeader>
						<DialogTitle>{t("organizations.editOrg")}</DialogTitle>
					</DialogHeader>
					<div className="space-y-4">
						<div className="space-y-1.5">
							<Label htmlFor="org-name">{t("organizations.orgName")}</Label>
							<Input
								id="org-name"
								value={editName}
								onChange={(e) => setEditName(e.target.value)}
								disabled={saveOrg.isPending}
							/>
						</div>
						<div className="space-y-1.5">
							<Label htmlFor="org-slug">{t("organizations.slug")}</Label>
							<Input
								id="org-slug"
								value={editSlug}
								onChange={(e) => setEditSlug(e.target.value)}
								disabled={saveOrg.isPending}
							/>
						</div>
					</div>
					<DialogFooter>
						<Button
							variant="secondary"
							size="sm"
							onClick={() => setEditOpen(false)}
							disabled={saveOrg.isPending}
						>
							{t("common.cancel")}
						</Button>
						<Button
							variant="primary"
							size="sm"
							onClick={() => saveOrg.mutate()}
							disabled={
								saveOrg.isPending || !editName.trim() || !editSlug.trim()
							}
						>
							{t("organizations.save")}
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>

			{/* Teams section */}
			<TeamsSection orgId={orgId} />
		</div>
	);
}

/** Teams management section within an organization. */
function TeamsSection({ orgId }: { orgId: string }) {
	const { t } = useI18n();
	const qc = useQueryClient();
	const [newTeamName, setNewTeamName] = useState("");

	const {
		data: teamsData,
		isError,
		isPending: teamsLoading,
		refetch,
	} = useQuery({
		queryKey: ["org-teams", orgId],
		queryFn: async () => {
			const d = await fetchAdminJson<
				ApiResponse<{
					teams?: Array<{ id: string; name: string }>;
				}>
			>(`/api/admin/organizations/${orgId}/teams`);
			return d.data?.teams ?? [];
		},
	});
	const teams: Array<{ id: string; name: string }> = teamsData ?? [];

	const createTeam = useMutation({
		mutationFn: async () => {
			if (!newTeamName.trim()) return;
			const r = await fetchAdminResponse(
				`/api/admin/organizations/${orgId}/teams`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ name: newTeamName.trim() }),
				},
			);
			if (r.ok) {
				toast.success(t("toast.teamCreated"));
				setNewTeamName("");
				await qc.invalidateQueries({ queryKey: ["org-teams", orgId] });
			} else {
				toast.error(t("toast.createFailed"));
			}
		},
		onError: () => toast.error(t("toast.createFailed")),
	});

	const deleteTeam = async (teamId: string) => {
		const r = await fetchAdminResponse(
			`/api/admin/organizations/${orgId}/teams/${teamId}`,
			{ method: "DELETE" },
		);
		if (r.ok) {
			toast.success(t("toast.teamDeleted"));
			await qc.invalidateQueries({ queryKey: ["org-teams", orgId] });
			return true;
		} else {
			toast.error(t("toast.deleteFailed"));
			return false;
		}
	};

	return (
		<div className="mt-8">
			<div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
				<h3 className="font-mono text-[12px] uppercase text-mute">
					{t("organizations.teams")} ({teams.length})
				</h3>
				<RoleGuard allow={["super_admin"]}>
					<div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
						<Input
							value={newTeamName}
							onChange={(e) => setNewTeamName(e.target.value)}
							aria-label={t("organizations.teamName")}
							disabled={createTeam.isPending}
							placeholder={t("organizations.teamName")}
							className="h-8 sm:w-[180px]"
						/>
						<Button
							variant="primary"
							size="sm"
							onClick={() => createTeam.mutate()}
							disabled={createTeam.isPending || !newTeamName.trim()}
						>
							{t("organizations.createTeam")}
						</Button>
					</div>
				</RoleGuard>
			</div>
			{isError ? (
				<EmptyState>
					<AlertCircle size={20} className="text-error" aria-hidden />
					<span>{t("error.generic.message")}</span>
					<Button variant="secondary" size="sm" onClick={() => void refetch()}>
						<RefreshCw size={15} />
						{t("error.retry")}
					</Button>
				</EmptyState>
			) : teamsLoading ? (
				<p role="status" className="text-[14px] text-mute">
					{t("common.loading")}
				</p>
			) : teams.length === 0 ? (
				<p className="text-[14px] text-mute">{t("organizations.noTeams")}</p>
			) : (
				<div className="space-y-3">
					{teams.map((team) => (
						<TeamCard
							key={team.id}
							orgId={orgId}
							team={team}
							onDelete={() => deleteTeam(team.id)}
						/>
					))}
				</div>
			)}
		</div>
	);
}

function TeamCard({
	orgId,
	team,
	onDelete,
}: {
	orgId: string;
	team: { id: string; name: string };
	onDelete: () => Promise<boolean>;
}) {
	const { t } = useI18n();
	const qc = useQueryClient();
	const [addUserId, setAddUserId] = useState("");

	const {
		data: membersData,
		isError,
		isPending: membersLoading,
		refetch,
	} = useQuery({
		queryKey: ["team-members", orgId, team.id],
		queryFn: async () => {
			const d = await fetchAdminJson<
				ApiResponse<{
					members?: Array<{
						id: string;
						userId: string;
						user?: { email?: string };
					}>;
				}>
			>(`/api/admin/organizations/${orgId}/teams/${team.id}/members`);
			return d.data?.members ?? [];
		},
	});
	const members: Array<{
		id: string;
		userId: string;
		user?: { email?: string };
	}> = membersData ?? [];

	const addMember = useMutation({
		mutationFn: async () => {
			if (!addUserId.trim()) return;
			const r = await fetchAdminResponse(
				`/api/admin/organizations/${orgId}/teams/${team.id}/members`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ userId: addUserId.trim() }),
				},
			);
			if (r.ok) {
				toast.success(t("toast.memberAdded"));
				setAddUserId("");
				await qc.invalidateQueries({
					queryKey: ["team-members", orgId, team.id],
				});
			} else {
				toast.error(t("toast.actionFailed"));
			}
		},
		onError: () => toast.error(t("toast.actionFailed")),
	});
	const removeMember = async (memberId: string) => {
		const r = await fetchAdminResponse(
			`/api/admin/organizations/${orgId}/teams/${team.id}/members/${memberId}`,
			{ method: "DELETE" },
		);
		if (r.ok) {
			toast.success(t("toast.memberRemoved"));
			await qc.invalidateQueries({
				queryKey: ["team-members", orgId, team.id],
			});
			return true;
		}
		toast.error(t("toast.deleteFailed"));
		return false;
	};

	return (
		<div className="rounded-[var(--radius-md)] border border-hairline bg-canvas p-4">
			<div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
				<span className="font-medium text-ink">{team.name}</span>
				<div className="flex items-center gap-2">
					<span className="text-[13px] text-mute">
						{isError || membersLoading ? "—" : members.length}{" "}
						{t("organizations.teamMembers")}
					</span>
					<RoleGuard allow={["super_admin"]}>
						<ConfirmDialog
							trigger={
								<Button variant="ghost" size="sm" className="text-error">
									{t("organizations.deleteTeam")}
								</Button>
							}
							title={t("organizations.deleteTeam")}
							danger
							confirmText={t("common.delete")}
							onConfirm={onDelete}
						/>
					</RoleGuard>
				</div>
			</div>
			{isError && (
				<div className="mb-3 flex items-center justify-between gap-3 rounded-[var(--radius-sm)] bg-error-soft px-3 py-2 text-[13px] text-error">
					<span>{t("error.generic.message")}</span>
					<Button variant="ghost" size="sm" onClick={() => void refetch()}>
						{t("error.retry")}
					</Button>
				</div>
			)}
			{members.map((m) => (
				<div
					key={m.id}
					className="mb-1 flex flex-col gap-1 rounded-[var(--radius-sm)] bg-canvas-soft px-3 py-2 text-[13px] sm:flex-row sm:items-center sm:justify-between"
				>
					<span className="break-all text-ink">
						{m.user?.email ?? m.userId}
					</span>
					<RoleGuard allow={["super_admin"]}>
						<ConfirmDialog
							trigger={
								<Button variant="ghost" size="sm" className="text-error">
									{t("organizations.removeTeamMember")}
								</Button>
							}
							title={t("organizations.removeTeamMember")}
							onConfirm={() => removeMember(m.id)}
						/>
					</RoleGuard>
				</div>
			))}
			<RoleGuard allow={["super_admin"]}>
				<div className="mt-2 flex flex-col gap-2 sm:flex-row">
					<Input
						value={addUserId}
						onChange={(e) => setAddUserId(e.target.value)}
						aria-label={t("organizations.teamMemberUserId")}
						disabled={addMember.isPending}
						placeholder={t("organizations.teamMemberUserId")}
						className="h-8"
					/>
					<Button
						variant="secondary"
						size="sm"
						onClick={() => addMember.mutate()}
						disabled={addMember.isPending || !addUserId.trim()}
					>
						{t("organizations.addMember")}
					</Button>
				</div>
			</RoleGuard>
		</div>
	);
}

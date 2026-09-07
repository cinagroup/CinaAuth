"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { RoleGuard } from "@/components/role-guard";
import { Button } from "@/components/ui/button";
import { fetchAdminResponse } from "@/lib/client-api";
import { useI18n } from "@/lib/i18n/i18n-context";

/**
 * Floating action bar shown when table rows are selected.
 * Supports batch ban and batch delete for the users page.
 */
export function BatchActionBar({
	selectedIds,
	onClear,
}: {
	selectedIds: string[];
	onClear: () => void;
}) {
	const { t } = useI18n();
	const qc = useQueryClient();
	const [loading, setLoading] = useState(false);

	if (selectedIds.length === 0) return null;

	const runBatch = async (action: "ban" | "delete") => {
		setLoading(true);
		try {
			const r = await fetchAdminResponse("/api/admin/users/batch", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ action, userIds: selectedIds }),
			});
			const d = (await r.json().catch(() => ({}))) as {
				ok?: boolean;
				data?: { succeeded: number; failed: number };
			};
			if (r.ok && d.ok) {
				const count = d.data?.succeeded ?? 0;
				toast.success(
					action === "ban"
						? t("batch.result.banned", { count })
						: t("batch.result.deleted", { count }),
				);
			} else if (r.ok && d.data && d.data.failed > 0) {
				toast.warning(
					t("batch.result.partial", {
						ok: d.data.succeeded,
						failed: d.data.failed,
					}),
				);
			} else {
				toast.error(t("toast.saveFailed"));
				return false;
			}
			onClear();
			await qc.invalidateQueries({ queryKey: ["users"] });
			return true;
		} catch {
			toast.error(t("toast.saveFailed"));
			return false;
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="sticky bottom-4 z-20 flex flex-wrap items-center gap-2 rounded-[var(--radius-md)] border border-hairline bg-canvas px-3 py-2.5 shadow-modal sm:gap-3 sm:px-4">
			<span className="text-sm font-medium text-ink">
				{t("batch.selected", { count: selectedIds.length })}
			</span>
			<div className="hidden h-4 w-px bg-hairline sm:block" />
			<RoleGuard allow={["super_admin", "security_admin"]}>
				<ConfirmDialog
					trigger={
						<Button variant="secondary" size="sm" disabled={loading}>
							{t("userDetail.actions.ban")}
						</Button>
					}
					title={t("batch.ban.title")}
					description={t("batch.ban.confirm", { count: selectedIds.length })}
					onConfirm={() => runBatch("ban")}
				/>
			</RoleGuard>
			<RoleGuard allow={["super_admin"]}>
				<ConfirmDialog
					trigger={
						<Button variant="danger" size="sm" disabled={loading}>
							{t("common.delete")}
						</Button>
					}
					title={t("batch.delete.title")}
					description={t("batch.delete.confirm", { count: selectedIds.length })}
					danger
					confirmationText={`DELETE ${selectedIds.length}`}
					confirmationLabel={t("common.typeToConfirm", {
						value: `DELETE ${selectedIds.length}`,
					})}
					onConfirm={() => runBatch("delete")}
				/>
			</RoleGuard>
			<Button variant="ghost" size="sm" onClick={onClear}>
				{t("common.cancel")}
			</Button>
		</div>
	);
}

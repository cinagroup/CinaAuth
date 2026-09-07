"use client";

import type { Table } from "@tanstack/react-table";
import { flexRender } from "@tanstack/react-table";
import { AlertCircle, Inbox } from "lucide-react";
import type { MouseEvent } from "react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/i18n-context";

/**
 * Generic table renderer built on @tanstack/react-table. The caller constructs
 * the table instance (columns + data) and passes it in. Optional `rowClassName`
 * supports per-row highlighting (e.g. audit failure rows).
 *
 * Header typography uses the mono caption eyebrow voice (DESIGN.md
 * `ex-data-table-cell`); rows sit on canvas with hairline dividers.
 */
export function DataTable<T>({
	table,
	rowClassName,
	emptyLabel,
	onRowClick,
	isLoading = false,
	isError = false,
	onRetry,
}: {
	table: Table<T>;
	rowClassName?: (row: T) => string | undefined;
	emptyLabel?: string;
	onRowClick?: (row: T) => void;
	isLoading?: boolean;
	isError?: boolean;
	onRetry?: () => void;
}) {
	const { t } = useI18n();
	const rows = table.getRowModel().rows;
	const columnCount = Math.max(table.getVisibleLeafColumns().length, 1);

	const handleRowClick = (event: MouseEvent, row: T) => {
		if (!onRowClick) return;
		const target = event.target as HTMLElement;
		if (
			target.closest(
				"a, button, input, select, textarea, [role='button'], [role='menuitem']",
			)
		)
			return;
		onRowClick(row);
	};

	return (
		<div
			className="overflow-x-auto rounded-[var(--radius-md)] border border-hairline bg-canvas"
			aria-busy={isLoading}
		>
			<table className="w-full min-w-max">
				<thead className="bg-canvas-soft">
					{table.getHeaderGroups().map((hg) => (
						<tr key={hg.id} className="border-b border-hairline">
							{hg.headers.map((h) => (
								<th
									key={h.id}
									className="whitespace-nowrap px-3 py-2 text-left font-mono text-[12px] font-normal uppercase text-mute"
								>
									{h.isPlaceholder
										? null
										: flexRender(h.column.columnDef.header, h.getContext())}
								</th>
							))}
						</tr>
					))}
				</thead>
				<tbody aria-live="polite">
					{isLoading &&
						rows.length === 0 &&
						Array.from({ length: 5 }).map((_, rowIndex) => (
							<tr
								key={`loading-${rowIndex}`}
								className="border-b border-hairline last:border-b-0"
							>
								{Array.from({ length: columnCount }).map((__, cellIndex) => (
									<td key={cellIndex} className="px-3 py-3">
										<Skeleton className="h-4 w-24" />
									</td>
								))}
							</tr>
						))}
					{isError && (
						<tr>
							<td colSpan={columnCount} className="px-6 py-12 text-center">
								<div
									role="alert"
									className="flex flex-col items-center gap-3 text-[14px] leading-5 text-body"
								>
									<AlertCircle size={20} className="text-error" aria-hidden />
									<span>{t("error.generic.message")}</span>
									{onRetry && (
										<Button variant="secondary" size="sm" onClick={onRetry}>
											{t("error.retry")}
										</Button>
									)}
								</div>
							</td>
						</tr>
					)}
					{!isLoading && !isError && rows.length === 0 && (
						<tr>
							<td colSpan={columnCount} className="px-6 py-12 text-center">
								<div className="flex flex-col items-center gap-2 text-[14px] leading-5 text-mute">
									<Inbox size={20} aria-hidden />
									<span>{emptyLabel ?? t("common.noData")}</span>
								</div>
							</td>
						</tr>
					)}
					{rows.map((row) => (
						<tr
							key={row.id}
							className={cn(
								"border-b border-hairline last:border-b-0 transition-colors hover:bg-canvas-soft",
								onRowClick &&
									"cursor-pointer focus-visible:bg-canvas-soft focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--focus-ring)]",
								rowClassName?.(row.original),
							)}
							onClick={
								onRowClick
									? (event) => handleRowClick(event, row.original)
									: undefined
							}
							onKeyDown={
								onRowClick
									? (event) => {
											if (
												event.key === "Enter" &&
												event.target === event.currentTarget
											) {
												onRowClick(row.original);
											}
										}
									: undefined
							}
							tabIndex={onRowClick ? 0 : undefined}
						>
							{row.getVisibleCells().map((cell) => (
								<td
									key={cell.id}
									className="max-w-[28rem] px-3 py-2.5 text-[14px] leading-5 text-ink"
								>
									{flexRender(cell.column.columnDef.cell, cell.getContext())}
								</td>
							))}
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

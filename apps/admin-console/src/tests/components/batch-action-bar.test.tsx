import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { BatchActionBar } from "@/components/data-table/batch-action-bar";

const session = vi.hoisted(() => ({ role: "security_admin" }));
vi.mock("@/hooks/use-admin-session", () => ({
	useAdminSession: () => ({ data: { role: session.role } }),
}));

/** @see https://github.com/cinagroup/cinaauth/blob/main/packages/auth-web-contract/src/admin-control.ts */
describe("batch user action permissions", () => {
	it.each([
		{ role: "security_admin", ban: true, remove: false },
		{ role: "user, super_admin", ban: true, remove: true },
		{ role: "user", ban: false, remove: false },
	])("matches the control-plane permissions for $role", ({
		role,
		ban,
		remove,
	}) => {
		session.role = role;
		render(
			<QueryClientProvider client={new QueryClient()}>
				<BatchActionBar selectedIds={["user-1"]} onClear={vi.fn()} />
			</QueryClientProvider>,
		);
		expect(Boolean(screen.queryByRole("button", { name: "封禁" }))).toBe(ban);
		expect(Boolean(screen.queryByRole("button", { name: "删除" }))).toBe(
			remove,
		);
	});
});

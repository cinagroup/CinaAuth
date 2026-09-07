import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ remove: vi.fn(), update: vi.fn() }));
vi.mock("@/lib/auth-client", () => ({
	authClient: {
		organization: {
			removeMember: mocks.remove,
			updateMemberRole: mocks.update,
		},
	},
}));

import { removeMember } from "./member-remove-mutation";
import { updateMemberRole } from "./member-role-update-mutation";

/** @see https://github.com/cinagroup/cinaauth/tree/main/packages/cinaauth/src/plugins/organization/routes */
describe("member mutation organization scope", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mocks.remove.mockResolvedValue({ data: {}, error: null });
		mocks.update.mockResolvedValue({ data: {}, error: null });
	});
	it("removes from the displayed organization even if the active session has changed", async () => {
		const target = {
			organizationId: "displayed-organization",
			memberIdOrEmail: "membership-id",
		};
		await removeMember(target);
		expect(mocks.remove).toHaveBeenCalledWith(target);
	});
	it("updates roles in the member's organization", async () => {
		const target = {
			organizationId: "displayed-organization",
			memberId: "membership-id",
			role: ["admin", "auditor"],
		};
		await updateMemberRole(target);
		expect(mocks.update).toHaveBeenCalledWith(target);
	});
	it("propagates rejected changes instead of reporting success", async () => {
		mocks.update.mockResolvedValue({
			data: null,
			error: { message: "Permission denied" },
		});
		await expect(
			updateMemberRole({
				organizationId: "organization",
				memberId: "member",
				role: "admin",
			}),
		).rejects.toThrow("Permission denied");
	});
});

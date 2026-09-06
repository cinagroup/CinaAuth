import type { CinaAuthPlugin } from "@cinaauth/core";
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { admin } from "./admin";

type StoredPasskey = {
	id: string;
	userId: string;
	name?: string;
	publicKey: string;
	credentialID: string;
	counter: number;
	deviceType: string;
	backedUp: boolean;
	transports?: string;
	createdAt: Date;
	aaguid?: string;
};

const passkeyModelPlugin = {
	id: "admin-passkey-test-model",
	schema: {
		passkey: {
			fields: {
				name: { type: "string", required: false },
				publicKey: { type: "string", required: true },
				userId: { type: "string", required: true, index: true },
				credentialID: { type: "string", required: true, index: true },
				counter: { type: "number", required: true },
				deviceType: { type: "string", required: true },
				backedUp: { type: "boolean", required: true },
				transports: { type: "string", required: false },
				createdAt: { type: "date", required: false },
				aaguid: { type: "string", required: false },
			},
		},
	},
} satisfies CinaAuthPlugin;

const createPasskey = (
	userId: string,
	credentialID: string,
	name = "Original passkey",
): Omit<StoredPasskey, "id"> => ({
	userId,
	name,
	publicKey: `public-${credentialID}`,
	credentialID,
	counter: 0,
	deviceType: "singleDevice",
	backedUp: false,
	transports: "internal",
	createdAt: new Date("2026-08-11T00:00:00.000Z"),
	aaguid: "test-aaguid",
});

async function passkeyAdminInstance(
	role: "admin" | "security_admin" = "admin",
) {
	const instance = await getTestInstance(
		{
			plugins: [admin(), passkeyModelPlugin],
			databaseHooks: {
				user: {
					create: {
						async before(user) {
							return {
								data: {
									...user,
									...(user.name === "Passkey Operator" ? { role } : {}),
								},
							};
						},
					},
				},
			},
		},
		{ testUser: { name: "Passkey Operator" } },
	);
	const { headers, user: operator } = await instance.signInWithTestUser();
	const context = await instance.auth.$context;
	const target = await context.internalAdapter.createUser(
		{
			name: "Target User",
			email: `target-${crypto.randomUUID()}@example.com`,
		},
		{ method: "admin" },
	);
	const targetPasskey = await context.adapter.create<
		Omit<StoredPasskey, "id">,
		StoredPasskey
	>({
		model: "passkey",
		data: createPasskey(target.id, `target-${crypto.randomUUID()}`),
	});
	const operatorPasskey = await context.adapter.create<
		Omit<StoredPasskey, "id">,
		StoredPasskey
	>({
		model: "passkey",
		data: createPasskey(operator.id, `operator-${crypto.randomUUID()}`),
	});

	return {
		...instance,
		context,
		headers,
		operator,
		operatorPasskey,
		target,
		targetPasskey,
	};
}

describe("Admin target-user passkey endpoints", () => {
	it("lists only the target user's non-secret passkey metadata", async () => {
		const { auth, headers, target, targetPasskey, operatorPasskey } =
			await passkeyAdminInstance();

		const response = await auth.api.adminListUserPasskeys({
			headers,
			body: { userId: target.id },
		});

		expect(response.passkeys).toHaveLength(1);
		expect(response.passkeys[0]).toMatchObject({
			id: targetPasskey.id,
			name: "Original passkey",
			deviceType: "singleDevice",
			backedUp: false,
			aaguid: "test-aaguid",
		});
		expect(response.passkeys[0]?.id).not.toBe(operatorPasskey.id);
		expect(response.passkeys[0]).not.toHaveProperty("userId");
		expect(response.passkeys[0]).not.toHaveProperty("publicKey");
		expect(response.passkeys[0]).not.toHaveProperty("credentialID");
		expect(response.passkeys[0]).not.toHaveProperty("counter");
	});

	it("refuses delete when passkey id does not belong to the target user", async () => {
		const { auth, context, headers, operator, targetPasskey } =
			await passkeyAdminInstance();

		await expect(
			auth.api.adminDeleteUserPasskey({
				headers,
				body: {
					userId: operator.id,
					passkeyId: targetPasskey.id,
				},
			}),
		).rejects.toMatchObject({ status: "NOT_FOUND" });
		await expect(
			context.adapter.findOne({
				model: "passkey",
				where: [{ field: "id", value: targetPasskey.id }],
			}),
		).resolves.not.toBeNull();
	});

	it("refuses update when passkey id does not belong to the target user", async () => {
		const { auth, context, headers, operator, targetPasskey } =
			await passkeyAdminInstance();

		await expect(
			auth.api.adminUpdateUserPasskey({
				headers,
				body: {
					userId: operator.id,
					passkeyId: targetPasskey.id,
					name: "Cross-user rename",
				},
			}),
		).rejects.toMatchObject({ status: "NOT_FOUND" });
		await expect(
			context.adapter.findOne<StoredPasskey>({
				model: "passkey",
				where: [{ field: "id", value: targetPasskey.id }],
			}),
		).resolves.toMatchObject({ name: "Original passkey" });
	});

	it("deletes and renames only a passkey owned by the explicit target", async () => {
		const { auth, context, headers, target, targetPasskey } =
			await passkeyAdminInstance();

		const updated = await auth.api.adminUpdateUserPasskey({
			headers,
			body: {
				userId: target.id,
				passkeyId: targetPasskey.id,
				name: "Renamed key",
			},
		});
		expect(updated.passkey.name).toBe("Renamed key");

		await expect(
			auth.api.adminDeleteUserPasskey({
				headers,
				body: { userId: target.id, passkeyId: targetPasskey.id },
			}),
		).resolves.toEqual({ success: true });
		await expect(
			context.adapter.findOne({
				model: "passkey",
				where: [{ field: "id", value: targetPasskey.id }],
			}),
		).resolves.toBeNull();
	});

	it("allows security_admin to list and revoke but not rename", async () => {
		const { auth, headers, target, targetPasskey } =
			await passkeyAdminInstance("security_admin");

		await expect(
			auth.api.adminListUserPasskeys({
				headers,
				body: { userId: target.id },
			}),
		).resolves.toMatchObject({ passkeys: [{ id: targetPasskey.id }] });
		await expect(
			auth.api.adminUpdateUserPasskey({
				headers,
				body: {
					userId: target.id,
					passkeyId: targetPasskey.id,
					name: "Blocked rename",
				},
			}),
		).rejects.toMatchObject({ status: "FORBIDDEN" });
		await expect(
			auth.api.adminDeleteUserPasskey({
				headers,
				body: { userId: target.id, passkeyId: targetPasskey.id },
			}),
		).resolves.toEqual({ success: true });
	});
});

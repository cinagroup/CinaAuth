import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../test-utils/test-instance";
import type { User } from "../types";

describe("db", async () => {
	it("should work with custom model names", async () => {
		const { client, db } = await getTestInstance({
			user: {
				modelName: "users",
			},
			session: {
				modelName: "sessions",
			},
			account: {
				modelName: "accounts",
			},
		});
		const res = await client.signUp.email({
			email: "test@email2.com",
			password: "password",
			name: "Test User",
		});
		const users = await db.findMany({
			model: "user",
		});
		const session = await db.findMany({
			model: "session",
		});
		const accounts = await db.findMany({
			model: "account",
		});
		expect(res.data).toBeDefined();
		//including the user that was created in the test instance
		expect(users).toHaveLength(2);
		expect(session).toHaveLength(2);
		expect(accounts).toHaveLength(2);
	});

	it("db hooks", async () => {
		let callback = false;
		const { client } = await getTestInstance({
			session: {
				storeSessionInDatabase: true,
			},
			databaseHooks: {
				user: {
					create: {
						async before(user) {
							return {
								data: {
									...user,
									image: "test-image",
								},
							};
						},
						async after(user) {
							callback = true;
						},
					},
				},
			},
		});
		const res = await client.signUp.email({
			email: "test@email.com",
			name: "test",
			password: "password",
		});
		const session = await client.getSession({
			fetchOptions: {
				headers: {
					Authorization: `Bearer ${res.data?.token}`,
				},
				throw: true,
			},
		});
		expect(session?.user?.image).toBe("test-image");
		expect(callback).toBe(true);
	});

	it("db hooks should preserve a forced UUID on postgres when generateId is uuid", async () => {
		const existingId = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
		const email = `forced-id-${crypto.randomUUID()}@test.com`;
		const { auth, db } = await getTestInstance(
			{
				advanced: {
					database: {
						generateId: "uuid",
					},
				},
				databaseHooks: {
					user: {
						create: {
							async before(user) {
								return {
									data: {
										...user,
										id: existingId,
									},
								};
							},
						},
					},
				},
			},
			{
				testWith: "postgres",
				disableTestUser: true,
			},
		);

		const result = await auth.api.signUpEmail({
			body: {
				email,
				name: "forced-id-user",
				password: "password",
			},
		});

		expect(result.user.id).toBe(existingId);

		const createdUser = await db.findOne<User>({
			model: "user",
			where: [{ field: "id", value: existingId }],
		});

		expect(createdUser?.id).toBe(existingId);
		expect(createdUser?.email).toBe(email);
	});

	it("should work with custom field names", async () => {
		const { client } = await getTestInstance({
			user: {
				fields: {
					email: "email_address",
				},
			},
		});
		const res = await client.signUp.email({
			email: "test@email.com",
			password: "password",
			name: "Test User",
		});
		const session = await client.getSession({
			fetchOptions: {
				headers: {
					Authorization: `Bearer ${res.data?.token}`,
				},
				throw: true,
			},
		});
		expect(session?.user.email).toBe("test@email.com");
	});

	it("delete hooks", async () => {
		const hookUserDeleteBefore = vi.fn();
		const hookUserDeleteAfter = vi.fn();
		const hookSessionDeleteBefore = vi.fn();
		const hookSessionDeleteAfter = vi.fn();

		const { client } = await getTestInstance({
			session: {
				storeSessionInDatabase: true,
			},
			user: {
				deleteUser: {
					enabled: true,
				},
			},
			databaseHooks: {
				user: {
					delete: {
						async before(user, context) {
							hookUserDeleteBefore(user, context);
							return true;
						},
						async after(user, context) {
							hookUserDeleteAfter(user, context);
						},
					},
				},
				session: {
					delete: {
						async before(session, context) {
							hookSessionDeleteBefore(session, context);
							return true;
						},
						async after(session, context) {
							hookSessionDeleteAfter(session, context);
						},
					},
				},
			},
		});

		const res = await client.signUp.email({
			email: "delete-test@email.com",
			password: "password",
			name: "Delete Test User",
		});

		expect(res.data).toBeDefined();
		const userId = res.data?.user.id;

		await client.deleteUser({
			fetchOptions: {
				headers: {
					Authorization: `Bearer ${res.data?.token}`,
				},
				throw: true,
			},
		});

		expect(hookUserDeleteBefore).toHaveBeenCalledOnce();
		expect(hookUserDeleteAfter).toHaveBeenCalledOnce();
		expect(hookSessionDeleteBefore).toHaveBeenCalledOnce();
		expect(hookSessionDeleteAfter).toHaveBeenCalledOnce();

		expect(hookUserDeleteBefore).toHaveBeenCalledWith(
			expect.objectContaining({
				id: userId,
				email: "delete-test@email.com",
				name: "Delete Test User",
			}),
			expect.any(Object),
		);

		expect(hookUserDeleteAfter).toHaveBeenCalledWith(
			expect.objectContaining({
				id: userId,
				email: "delete-test@email.com",
				name: "Delete Test User",
			}),
			expect.any(Object),
		);
	});

	it("delete hooks abort", async () => {
		const hookUserDeleteBefore = vi.fn();
		const hookUserDeleteAfter = vi.fn();

		const { auth, client } = await getTestInstance({
			session: {
				storeSessionInDatabase: true,
			},
			user: {
				deleteUser: {
					enabled: true,
				},
			},
			databaseHooks: {
				user: {
					delete: {
						async before(user, context) {
							hookUserDeleteBefore(user, context);
							return false;
						},
						async after(user, context) {
							hookUserDeleteAfter(user, context);
						},
					},
				},
			},
		});

		const res = await client.signUp.email({
			email: "abort-delete-test@email.com",
			password: "password",
			name: "Abort Delete Test User",
		});

		expect(res.data).toBeDefined();
		const userId = res.data?.user.id;

		try {
			await client.deleteUser({
				fetchOptions: {
					headers: {
						Authorization: `Bearer ${res.data?.token}`,
					},
					throw: true,
				},
			});
		} catch {
			// Expected to fail due to hook returning false
		}

		expect(hookUserDeleteBefore).toHaveBeenCalledOnce();
		expect(hookUserDeleteAfter).not.toHaveBeenCalled();

		expect(hookUserDeleteBefore).toHaveBeenCalledWith(
			expect.objectContaining({
				id: userId,
				email: "abort-delete-test@email.com",
				name: "Abort Delete Test User",
			}),
			expect.any(Object),
		);

		const context = await auth.$context;
		expect(await context.internalAdapter.findUserById(userId!)).not.toBeNull();
		expect(await context.internalAdapter.findAccounts(userId!)).toHaveLength(1);
		expect(await context.internalAdapter.listSessions(userId!)).toHaveLength(1);
	});

	it("fails closed before cascading when the user delete snapshot cannot be read", async () => {
		const storageDelete = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			session: { storeSessionInDatabase: true },
			secondaryStorage: {
				set() {},
				get() {
					return null;
				},
				delete: storageDelete,
				getAndDelete() {
					return null;
				},
				increment() {
					return 1;
				},
			},
		});
		const { user } = await signInWithTestUser();
		const context = await auth.$context;
		const adapter = context.adapter;
		const originalFindMany = adapter.findMany.bind(adapter);
		vi.spyOn(adapter, "findMany").mockImplementation(async (input) => {
			if (input.model === "user") {
				throw new Error("user snapshot unavailable");
			}
			return originalFindMany(input);
		});
		vi.spyOn(adapter, "transaction").mockImplementation(async (callback) =>
			callback(adapter),
		);
		const deleteMany = vi.spyOn(adapter, "deleteMany");
		storageDelete.mockClear();

		await expect(context.internalAdapter.deleteUser(user.id)).rejects.toThrow(
			"user snapshot unavailable",
		);

		expect(storageDelete).not.toHaveBeenCalled();
		expect(deleteMany).not.toHaveBeenCalled();
	});
});

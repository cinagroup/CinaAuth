import { decodeProtectedHeader } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { jwt } from ".";
import type { Jwk } from "./types";

describe("jwt rotation", async () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("should return a newly created key from one empty JWKS read", async () => {
		const storage: Jwk[] = [];
		const getJwks = vi.fn(async () => [...storage]);
		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					adapter: {
						getJwks,
						createJwk: async (data) => {
							const key = { ...data, id: crypto.randomUUID() };
							storage.push(key);
							return key;
						},
					},
				}),
			],
		});

		const jwks = await auth.api.getJwks();

		expect(getJwks).toHaveBeenCalledTimes(1);
		expect(storage).toHaveLength(1);
		expect(jwks.keys).toHaveLength(1);
		expect(jwks.keys[0]?.kid).toBe(storage[0]?.id);
	});

	it("should stop publishing an immutably expired key with no grace period", async () => {
		let storage: Jwk[] = [];
		const adapter = {
			getJwks: async () => storage.map((key) => ({ ...key })),
			createJwk: async (data: Omit<Jwk, "id">) => {
				const key = { ...data, id: crypto.randomUUID() };
				storage = [...storage, key];
				return { ...key };
			},
			expireJwk: async (id: string, expiresAt: Date) => {
				const key = storage.find((candidate) => candidate.id === id);
				if (!key) return null;
				const expiredKey = { ...key, expiresAt };
				storage = storage.map((candidate) =>
					candidate.id === id ? expiredKey : candidate,
				);
				return { ...expiredKey };
			},
		};
		const first = await getTestInstance({
			plugins: [
				jwt({
					jwks: { disablePrivateKeyEncryption: true },
					adapter,
				}),
			],
		});
		await first.auth.api.signJWT({
			body: { payload: { sub: "user1" } },
		});
		expect(storage.map((key) => key.alg)).toEqual(["EdDSA"]);

		const second = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						keyPairConfig: { alg: "ES256" },
						disablePrivateKeyEncryption: true,
						gracePeriod: 0,
					},
					adapter,
				}),
			],
		});

		expect(
			(await second.auth.api.getJwks()).keys.map((key) => key.alg),
		).toEqual(["ES256"]);
		expect(storage[0]?.expiresAt).toBeInstanceOf(Date);
	});

	it("should rotate keys when expired", async () => {
		vi.useFakeTimers();
		const storage: Jwk[] = [];
		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						rotationInterval: 1, // 1 second
					},
					adapter: {
						getJwks: async () => storage,
						createJwk: async (data) => {
							const key = {
								...data,
								id: crypto.randomUUID(),
							};
							storage.push(key);
							return key;
						},
					},
				}),
			],
		});

		// First key creation
		await auth.api.signJWT({
			body: { payload: { sub: "user1" } },
		});
		expect(storage.length).toBe(1);
		const firstKey = storage[0];

		// Advance time past rotation interval
		vi.advanceTimersByTime(1100);

		// Second key creation (should rotate)
		await auth.api.signJWT({
			body: { payload: { sub: "user1" } },
		});
		expect(storage.length).toBe(2);
		const secondKey = storage[1];
		expect(secondKey!.id).not.toBe(firstKey!.id);

		vi.useRealTimers();
	});

	it("should return keys within grace period", async () => {
		vi.useFakeTimers();
		const storage: Jwk[] = [];
		const rotationInterval = 1; // 1 second
		const gracePeriod = 1; // 1 second

		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						rotationInterval,
						gracePeriod,
					},
					adapter: {
						getJwks: async () => storage,
						createJwk: async (data) => {
							const key = {
								...data,
								id: crypto.randomUUID(),
							};
							storage.push(key);
							return key;
						},
					},
				}),
			],
		});

		// Create first key
		await auth.api.signJWT({ body: { payload: { sub: "user1" } } });

		// Advance time past rotation interval but within grace period
		vi.advanceTimersByTime(1100);

		// Trigger rotation by signing
		await auth.api.signJWT({ body: { payload: { sub: "user1" } } });
		expect(storage.length).toBe(2);

		// Check JWKS endpoint
		const jwks = await auth.api.getJwks();
		expect(jwks.keys.length).toBe(2); // Both keys should be present

		// Advance time past grace period
		vi.advanceTimersByTime(1000);

		const jwksAfterGrace = await auth.api.getJwks();
		expect(jwksAfterGrace.keys.length).toBe(1); // First key should be gone
		expect(jwksAfterGrace.keys[0]?.kid).toBe(storage.at(-1)!.id);

		vi.useRealTimers();
	});

	it("should rotate immediately when the configured algorithm changes", async () => {
		vi.useFakeTimers();
		const storage: Jwk[] = [];
		const adapter = {
			getJwks: async () => storage,
			createJwk: async (data: Omit<Jwk, "id">) => {
				const key = { ...data, id: crypto.randomUUID() };
				storage.push(key);
				return key;
			},
			expireJwk: async (id: string, expiresAt: Date) => {
				const key = storage.find((candidate) => candidate.id === id);
				if (!key) return null;
				key.expiresAt = expiresAt;
				return key;
			},
		};
		const first = await getTestInstance({
			plugins: [
				jwt({
					jwks: { disablePrivateKeyEncryption: true },
					adapter,
				}),
			],
		});
		const previousToken = await first.auth.api.signJWT({
			body: { payload: { sub: "user1" } },
		});
		expect(storage).toHaveLength(1);
		expect(storage[0]?.alg).toBe("EdDSA");

		const second = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						keyPairConfig: { alg: "ES256" },
						disablePrivateKeyEncryption: true,
						gracePeriod: 30,
					},
					adapter,
				}),
			],
		});
		const token = await second.auth.api.signJWT({
			body: { payload: { sub: "user1" } },
		});
		expect(decodeProtectedHeader(token.token).alg).toBe("ES256");
		expect(
			(await second.auth.api.getJwks()).keys.map((key) => key.alg),
		).toEqual(["EdDSA", "ES256"]);
		expect(storage).toHaveLength(2);
		expect(storage[0]?.expiresAt).toBeInstanceOf(Date);
		expect(
			(
				await second.auth.api.verifyJWT({
					body: { token: previousToken.token },
				})
			).payload?.sub,
		).toBe("user1");
		vi.advanceTimersByTime(30_001);
		expect(
			(await second.auth.api.getJwks()).keys.map((key) => key.alg),
		).toEqual(["ES256"]);
	});
});

import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { siweChallengeIdentifier } from "./challenge";
import { siweClient } from "./client";
import { toCaip10AccountId } from "./identity";
import type { SIWEPluginOptions } from "./index";
import { siwe } from "./index";
import type { SIWEVerifyMessageArgs } from "./types";

describe("siwe v2 challenges", () => {
	const walletAddress = "0x000000000000000000000000000000000000dEaD";
	const domain = "accounts.example.com";
	const uri = `https://${domain}/sign-in?channel=wallet`;

	const setup = async (
		overrides: Partial<SIWEPluginOptions> = {},
		verifyCalls: SIWEVerifyMessageArgs[] = [],
	) =>
		getTestInstance(
			{
				plugins: [
					siwe({
						domain,
						uri,
						allowedChainIds: [1],
						async getNonce() {
							return "LegacyNonce123";
						},
						async verifyMessage(args) {
							verifyCalls.push(args);
							return args.signature === "valid_signature";
						},
						...overrides,
					}),
				],
			},
			{ clientOptions: { plugins: [siweClient()] } },
		);

	it("issues a purpose-bound server-generated sign-in challenge", async () => {
		const { client } = await setup();
		const response = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});

		expect(response.error).toBeNull();
		expect(response.data).toMatchObject({
			purpose: "sign-in",
			walletAddress,
			chainId: 1,
		});
		expect(response.data).toEqual(
			expect.objectContaining({
				challengeId: expect.stringMatching(/^[A-Za-z0-9]{32}$/),
				nonce: expect.stringMatching(/^[A-Za-z0-9]{32}$/),
				message: expect.stringContaining(`URI: ${uri}`),
				expiresAt: expect.any(Date),
			}),
		);
		const challenge = response.data;
		expect(challenge).not.toBeNull();
		expect(challenge!.message).toContain(
			`Request ID: ${challenge!.challengeId}`,
		);
	});

	it("verifies the canonical challenge once and publishes CAIP identity to the verifier", async () => {
		const verifyCalls: SIWEVerifyMessageArgs[] = [];
		const { client } = await setup({}, verifyCalls);
		const challenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});
		expect(challenge.data).not.toBeNull();

		const proof = {
			challengeId: challenge.data!.challengeId,
			message: challenge.data!.message,
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
		};
		const first = await client.siwe.verify(proof);
		expect(first.error).toBeNull();
		expect(first.data?.success).toBe(true);
		expect(verifyCalls).toHaveLength(1);
		expect(verifyCalls[0]?.cacao?.p).toMatchObject({
			aud: uri,
			iss: `did:pkh:${toCaip10AccountId(walletAddress, 1)}`,
			requestId: challenge.data!.challengeId,
		});

		const replay = await client.siwe.verify(proof);
		expect(replay.data).toBeNull();
		expect(replay.error?.code).toBe("UNAUTHORIZED_SIWE_CHALLENGE_MISMATCH");
		expect(verifyCalls).toHaveLength(1);
	});

	it("allows only one concurrent consumer of a v2 challenge", async () => {
		const verifyCalls: SIWEVerifyMessageArgs[] = [];
		const { client } = await setup({}, verifyCalls);
		const challenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});
		const proof = {
			challengeId: challenge.data!.challengeId,
			message: challenge.data!.message,
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
		};
		const results = await Promise.all([
			client.siwe.verify(proof),
			client.siwe.verify(proof),
		]);
		expect(results.filter((result) => result.data?.success)).toHaveLength(1);
		expect(
			results.filter(
				(result) =>
					result.error?.code === "UNAUTHORIZED_SIWE_CHALLENGE_MISMATCH",
			),
		).toHaveLength(1);
		expect(verifyCalls).toHaveLength(1);
	});

	it("rejects an expired v2 challenge before signature verification", async () => {
		const verifyCalls: SIWEVerifyMessageArgs[] = [];
		const { auth, client } = await setup({}, verifyCalls);
		const challenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});
		const ctx = await auth.$context;
		await ctx.internalAdapter.updateVerificationByIdentifier(
			siweChallengeIdentifier(challenge.data!.challengeId),
			{ expiresAt: new Date(Date.now() - 1000) },
		);
		const result = await client.siwe.verify({
			challengeId: challenge.data!.challengeId,
			message: challenge.data!.message,
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
		});
		expect(result.error?.code).toBe("UNAUTHORIZED_SIWE_CHALLENGE_MISMATCH");
		expect(verifyCalls).toHaveLength(0);
	});

	it("rejects changes to the server-generated URI query or statement", async () => {
		const { client } = await setup();
		for (const mutate of [
			(message: string) => message.replace("channel=wallet", "channel=email"),
			(message: string) =>
				message.replace("Sign in with Ethereum.", "Approve another action."),
		]) {
			const challenge = await client.siwe.challenge({
				walletAddress,
				chainId: 1,
				purpose: "sign-in",
			});
			const result = await client.siwe.verify({
				challengeId: challenge.data!.challengeId,
				message: mutate(challenge.data!.message),
				signature: "valid_signature",
				walletAddress,
				chainId: 1,
			});
			expect(result.error?.code).toBe("UNAUTHORIZED_SIWE_MESSAGE_MISMATCH");
		}
	});

	it("requires and binds a fresh session for link-wallet challenges", async () => {
		const { client, signInWithTestUser } = await setup();
		const unauthenticated = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "link-wallet",
		});
		expect(unauthenticated.error?.status).toBe(401);

		const { headers: firstHeaders } = await signInWithTestUser();
		const challenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "link-wallet",
			fetchOptions: { headers: firstHeaders },
		});
		expect(challenge.error).toBeNull();

		const { headers: secondHeaders } = await signInWithTestUser();
		const wrongSession = await client.siwe.linkWallet({
			challengeId: challenge.data!.challengeId,
			message: challenge.data!.message,
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
			fetchOptions: { headers: secondHeaders },
		});
		expect(wrongSession.error?.code).toBe(
			"UNAUTHORIZED_SIWE_CHALLENGE_MISMATCH",
		);

		const validChallenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "link-wallet",
			fetchOptions: { headers: firstHeaders },
		});
		const linked = await client.siwe.linkWallet({
			challengeId: validChallenge.data!.challengeId,
			message: validChallenge.data!.message,
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
			fetchOptions: { headers: firstHeaders },
		});
		expect(linked.error).toBeNull();
		expect(linked.data?.success).toBe(true);
	});

	it("does not allow a challenge to cross purpose boundaries", async () => {
		const { client, signInWithTestUser } = await setup();
		const { headers } = await signInWithTestUser();
		const challenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});
		const result = await client.siwe.linkWallet({
			challengeId: challenge.data!.challengeId,
			message: challenge.data!.message,
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
			fetchOptions: { headers },
		});
		expect(result.error?.code).toBe("UNAUTHORIZED_SIWE_CHALLENGE_MISMATCH");
	});

	it("enforces allowed chains and the server kill switches", async () => {
		const { client } = await setup({ legacyNonce: false });
		const chain = await client.siwe.challenge({
			walletAddress,
			chainId: 137,
			purpose: "sign-in",
		});
		expect(chain.error?.code).toBe("SIWE_CHAIN_NOT_ALLOWED");
		const legacy = await client.siwe.nonce({ walletAddress, chainId: 1 });
		expect(legacy.error?.code).toBe("SIWE_LEGACY_NONCE_DISABLED");

		const disabled = await setup({ enabled: false });
		const result = await disabled.client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});
		expect(result.error?.code).toBe("SIWE_DISABLED");
	});

	it("rejects oversized proof fields before verification", async () => {
		const verifyCalls: SIWEVerifyMessageArgs[] = [];
		const { client } = await setup({}, verifyCalls);
		for (const message of ["m".repeat(16_385), "界".repeat(6_000)]) {
			const oversizedMessage = await client.siwe.verify({
				message,
				signature: "valid_signature",
				walletAddress,
				chainId: 1,
			});
			expect(oversizedMessage.error?.status).toBe(400);
		}

		const challenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});
		const oversizedSignature = await client.siwe.verify({
			challengeId: challenge.data!.challengeId,
			message: challenge.data!.message,
			signature: "s".repeat(513),
			walletAddress,
			chainId: 1,
		});
		expect(oversizedSignature.error?.status).toBe(400);
		expect(verifyCalls).toHaveLength(0);
	});

	it("applies a dedicated per-path rate limit to challenge issuance", async () => {
		const { client } = await getTestInstance(
			{
				rateLimit: { enabled: true, window: 60, max: 300 },
				plugins: [
					siwe({
						domain,
						uri,
						allowedChainIds: [1],
						async verifyMessage() {
							return true;
						},
					}),
				],
			},
			{ clientOptions: { plugins: [siweClient()] } },
		);
		const results = [];
		for (let request = 0; request < 11; request++) {
			results.push(
				await client.siwe.challenge({
					walletAddress,
					chainId: 1,
					purpose: "sign-in",
				}),
			);
		}
		expect(results.slice(0, 10).every((result) => !result.error)).toBe(true);
		expect(results[10]?.error?.status).toBe(429);
	});

	it("disables automatic user creation while preserving bound-wallet login", async () => {
		const { auth, client } = await setup({ allowUserCreation: false });
		const challenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});
		const result = await client.siwe.verify({
			challengeId: challenge.data!.challengeId,
			message: challenge.data!.message,
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
		});
		expect(result.error?.code).toBe("SIWE_USER_CREATION_DISABLED");

		const context = await auth.$context;
		const user = await context.internalAdapter.createUser(
			{
				name: "Existing wallet user",
				email: "existing-wallet@example.com",
				emailVerified: true,
			},
			{ method: "siwe" },
		);
		await context.adapter.create({
			model: "walletAddress",
			data: {
				userId: user.id,
				address: walletAddress,
				chainId: 1,
				isPrimary: true,
				createdAt: new Date(),
			},
		});
		await context.internalAdapter.createAccount({
			userId: user.id,
			providerId: "siwe",
			accountId: `${walletAddress}:1`,
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const boundChallenge = await client.siwe.challenge({
			walletAddress,
			chainId: 1,
			purpose: "sign-in",
		});
		const signedIn = await client.siwe.verify({
			challengeId: boundChallenge.data!.challengeId,
			message: boundChallenge.data!.message,
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
		});
		expect(signedIn.error).toBeNull();
		expect(signedIn.data?.user.id).toBe(user.id);
	});

	it("validates RP and timing options at initialization", () => {
		const base = {
			domain,
			async verifyMessage() {
				return true;
			},
		};
		expect(() => siwe({ ...base, domain: "https://example.com/path" })).toThrow(
			/domain/,
		);
		expect(() =>
			siwe({ ...base, uri: "https://other.example.com/sign-in" }),
		).toThrow(/uri/);
		expect(() => siwe({ ...base, maxMessageAge: -1 })).toThrow(/maxMessageAge/);
		expect(() =>
			siwe({ ...base, clockSkew: Number.POSITIVE_INFINITY }),
		).toThrow(/clockSkew/);
		expect(() => siwe({ ...base, rateLimit: { max: 0 } })).toThrow(
			/rateLimit\.max/,
		);
	});
});

describe("strict legacy SIWE validation", () => {
	const walletAddress = "0x000000000000000000000000000000000000dEaD";
	const domain = "example.com";
	const nonce = "LegacyNonce123";

	const message = (input: {
		uri?: string;
		version?: string;
		chainId?: number;
		issuedAt?: string;
		expirationTime?: string;
		notBefore?: string;
	}) => {
		let value =
			`${domain} wants you to sign in with your Ethereum account:\n` +
			`${walletAddress}\n\nSign in.\n\n` +
			`URI: ${input.uri ?? `https://${domain}`}\n` +
			`Version: ${input.version ?? "1"}\n` +
			`Chain ID: ${input.chainId ?? 1}\n` +
			`Nonce: ${nonce}\n` +
			`Issued At: ${input.issuedAt ?? new Date().toISOString()}`;
		if (input.expirationTime) {
			value += `\nExpiration Time: ${input.expirationTime}`;
		}
		if (input.notBefore) value += `\nNot Before: ${input.notBefore}`;
		return value;
	};

	const attempt = async (body: Parameters<typeof message>[0]) => {
		const { client } = await getTestInstance(
			{
				plugins: [
					siwe({
						domain,
						allowedChainIds: [1],
						maxMessageAge: 300,
						clockSkew: 0,
						async getNonce() {
							return nonce;
						},
						async verifyMessage() {
							return true;
						},
					}),
				],
			},
			{ clientOptions: { plugins: [siweClient()] } },
		);
		await client.siwe.nonce({ walletAddress, chainId: 1 });
		return client.siwe.verify({
			message: message(body),
			signature: "valid_signature",
			walletAddress,
			chainId: 1,
		});
	};

	it.each([
		["URI", { uri: "https://example.com/other?next=%2Fadmin" }],
		["Version", { version: "2" }],
		["Chain ID", { chainId: 137 }],
	])("rejects a mismatched %s", async (_field, body) => {
		const result = await attempt(body);
		expect(result.error?.code).toBe("UNAUTHORIZED_SIWE_MESSAGE_MISMATCH");
	});

	it("rejects a stale or future Issued At timestamp", async () => {
		for (const issuedAt of [
			new Date(Date.now() - 10 * 60 * 1000).toISOString(),
			new Date(Date.now() + 10 * 60 * 1000).toISOString(),
		]) {
			const result = await attempt({ issuedAt });
			expect(result.error?.code).toBe("UNAUTHORIZED_SIWE_MESSAGE_ISSUED_AT");
		}
	});

	it("rejects expiration and not-before violations", async () => {
		const expired = await attempt({
			expirationTime: new Date(Date.now() - 1000).toISOString(),
		});
		expect(expired.error?.code).toBe("UNAUTHORIZED_SIWE_MESSAGE_EXPIRED");
		const future = await attempt({
			notBefore: new Date(Date.now() + 60_000).toISOString(),
		});
		expect(future.error?.code).toBe("UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID");
	});
});

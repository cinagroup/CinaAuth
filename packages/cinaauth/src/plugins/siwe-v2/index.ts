import type { CinaAuthPlugin } from "@cinaauth/core";
import { createAuthEndpoint } from "@cinaauth/core/api";
import * as z from "zod";
import { APIError, getFreshSessionFromCtx } from "../../api";
import { setSessionCookie } from "../../cookies";
import { generateRandomString } from "../../crypto";
import { mergeSchema } from "../../db/schema";
import type { InferOptionSchema, User } from "../../types";
import { toChecksumAddress } from "../../utils/hashing";
import { isAPIError } from "../../utils/is-api-error";
import { getOrigin } from "../../utils/url";
import { PACKAGE_VERSION } from "../../version";
import {
	createSiweChallengeValues,
	createSiweMessage,
	serializeSiweChallenge,
	siweChallengeIdentifier,
} from "./challenge";
import type { WalletAddressSchema } from "./schema";
import { schema } from "./schema";
import type {
	ENSLookupArgs,
	ENSLookupResult,
	SIWEVerifyMessageArgs,
	WalletAddress,
} from "./types";
import {
	isSiweMessageWithinLimit,
	SIWE_MESSAGE_MAX_LENGTH,
	SIWE_SIGNATURE_MAX_LENGTH,
} from "./types";
import {
	assertSiweChainAllowed,
	assertSiweEnabled,
	getSiweUri,
	verifySiweProof,
} from "./verify-proof";
import { createSiweWalletEndpoints } from "./wallets";

export type { SIWEChallengePurpose } from "./challenge";
export { toCaip10AccountId } from "./identity";

declare module "@cinaauth/core" {
	interface CinaAuthPluginRegistry<AuthOptions, Options> {
		"siwe-v2": {
			creator: typeof siwe;
		};
	}
}

/** Configure EIP-4361 wallet authentication and wallet lifecycle endpoints. */
export interface SIWEPluginOptions {
	/** Relying-party authority (`host[:port]`) shown in the signed message. */
	domain: string;
	/** Exact relying-party HTTPS URI, including any path and query. */
	uri?: string | undefined;
	/** Disable SIWE proof issuance and verification without removing the plugin. */
	enabled?: boolean | undefined;
	/** EVM Chain IDs accepted by challenge and verification endpoints. */
	allowedChainIds?: readonly number[] | undefined;
	/** Keep address-keyed legacy nonce endpoints enabled. Defaults to `true`. */
	legacyNonce?: boolean | undefined;
	/** Allow a verified unknown wallet to create a user. Defaults to `true`. */
	allowUserCreation?: boolean | undefined;
	/** V2 challenge lifetime in seconds. Defaults to 900; maximum 3600. */
	challengeExpiresIn?: number | undefined;
	/** Maximum accepted `Issued At` age in seconds. Defaults to 900. */
	maxMessageAge?: number | undefined;
	/** Allowed timestamp clock skew in seconds. Defaults to 60; maximum 300. */
	clockSkew?: number | undefined;
	/** Per-path SIWE abuse limit. Defaults to 10 requests per 60 seconds. */
	rateLimit?:
		| {
				/** Rate-limit window in seconds. Defaults to 60. */
				window?: number | undefined;
				/** Requests allowed per IP and endpoint path. Defaults to 10. */
				max?: number | undefined;
		  }
		| undefined;
	emailDomainName?: string | undefined;
	anonymous?: boolean | undefined;
	getNonce?: (() => Promise<string>) | undefined;
	verifyMessage: (args: SIWEVerifyMessageArgs) => Promise<boolean>;
	ensLookup?: ((args: ENSLookupArgs) => Promise<ENSLookupResult>) | undefined;
	schema?: InferOptionSchema<typeof schema> | undefined;
}

const walletAddressInputSchema = z
	.string()
	.regex(/^0[xX][a-fA-F0-9]{40}$/i)
	.length(42);

const chainIdInputSchema = z
	.number()
	.int()
	.positive()
	.max(Number.MAX_SAFE_INTEGER);

const SIWE_OAUTH_QUERY_MAX_LENGTH = 16_384;

// Reserved cross-plugin input. The OAuth provider client supplies this signed
// continuation and its server plugin verifies it before the SIWE handler runs.
// Declaring only this extension preserves strict rejection of all other keys.
const oauthQueryInputSchema = z
	.string()
	.min(1)
	.max(SIWE_OAUTH_QUERY_MAX_LENGTH)
	.optional();

const getSiweNonceBodySchema = z
	.object({
		walletAddress: walletAddressInputSchema.optional(),
		address: walletAddressInputSchema.optional(),
		chainId: chainIdInputSchema.optional().default(1),
	})
	.strict()
	.refine((body) => body.walletAddress || body.address, {
		message: "walletAddress or address is required",
		path: ["walletAddress"],
	});

const siweChallengeBodySchema = z
	.object({
		walletAddress: walletAddressInputSchema,
		chainId: chainIdInputSchema,
		purpose: z.enum(["sign-in", "link-wallet"]),
		oauth_query: oauthQueryInputSchema,
	})
	.strict();

const challengeIdSchema = z
	.string()
	.regex(/^[A-Za-z0-9]{32}$/)
	.length(32)
	.optional();

const assertSecondsOption = (name: string, value: number, maximum: number) => {
	if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
		throw new TypeError(
			`${name} must be a safe integer between 0 and ${maximum}`,
		);
	}
};

export const siwe = (options: SIWEPluginOptions) => {
	const challengeExpiresIn = options.challengeExpiresIn ?? 15 * 60;
	assertSecondsOption("challengeExpiresIn", challengeExpiresIn, 60 * 60);
	if (challengeExpiresIn === 0) {
		throw new TypeError("challengeExpiresIn must be greater than zero");
	}
	const maxMessageAge = options.maxMessageAge ?? 15 * 60;
	assertSecondsOption("maxMessageAge", maxMessageAge, 60 * 60);
	if (maxMessageAge === 0) {
		throw new TypeError("maxMessageAge must be greater than zero");
	}
	assertSecondsOption("clockSkew", options.clockSkew ?? 60, 5 * 60);
	const rateLimitWindow = options.rateLimit?.window ?? 60;
	const rateLimitMax = options.rateLimit?.max ?? 10;
	if (
		!Number.isSafeInteger(rateLimitWindow) ||
		rateLimitWindow <= 0 ||
		rateLimitWindow > 24 * 60 * 60
	) {
		throw new TypeError("rateLimit.window must be between 1 and 86400 seconds");
	}
	if (
		!Number.isSafeInteger(rateLimitMax) ||
		rateLimitMax <= 0 ||
		rateLimitMax > 10_000
	) {
		throw new TypeError("rateLimit.max must be between 1 and 10000 requests");
	}
	if (
		options.allowedChainIds?.some(
			(chainId) => !Number.isSafeInteger(chainId) || chainId <= 0,
		)
	) {
		throw new TypeError("allowedChainIds must contain positive safe integers");
	}
	if (
		!options.domain ||
		/[\s/?#@]/.test(options.domain) ||
		options.domain.includes("://")
	) {
		throw new TypeError(
			"domain must be an RFC 3986 authority without a scheme or path",
		);
	}
	let configuredUri: URL;
	try {
		configuredUri = new URL(getSiweUri(options));
	} catch {
		throw new TypeError("uri must be an absolute HTTP(S) URI");
	}
	if (
		(configuredUri.protocol !== "https:" &&
			configuredUri.protocol !== "http:") ||
		configuredUri.username !== "" ||
		configuredUri.password !== "" ||
		configuredUri.hash !== "" ||
		configuredUri.host.toLowerCase() !== options.domain.toLowerCase()
	) {
		throw new TypeError(
			"uri must be an absolute HTTP(S) URI on the configured domain",
		);
	}
	if (
		configuredUri.protocol === "http:" &&
		configuredUri.hostname !== "localhost" &&
		configuredUri.hostname !== "127.0.0.1" &&
		configuredUri.hostname !== "[::1]"
	) {
		throw new TypeError("uri must use HTTPS outside localhost development");
	}

	const createSiweNonceEndpoint = (path: "/siwe/nonce" | "/siwe/get-nonce") =>
		createAuthEndpoint(
			path,
			{
				method: "POST",
				body: getSiweNonceBodySchema,
			},
			async (ctx) => {
				assertSiweEnabled(options);
				if (options.legacyNonce === false) {
					throw APIError.fromStatus("FORBIDDEN", {
						message: "Legacy SIWE nonce issuance is disabled",
						status: 403,
						code: "SIWE_LEGACY_NONCE_DISABLED",
					});
				}
				const rawWalletAddress = ctx.body.walletAddress ?? ctx.body.address;
				if (!rawWalletAddress) {
					throw APIError.fromStatus("BAD_REQUEST", {
						message: "walletAddress or address is required",
						status: 400,
					});
				}
				const { chainId } = ctx.body;
				assertSiweChainAllowed(chainId, options);
				const walletAddress = toChecksumAddress(rawWalletAddress);
				const nonce = options.getNonce
					? await options.getNonce()
					: generateRandomString(32, "a-z", "A-Z", "0-9");
				if (!/^[A-Za-z0-9]{8,}$/.test(nonce)) {
					throw APIError.fromStatus("INTERNAL_SERVER_ERROR", {
						message:
							"SIWE nonce must contain at least 8 alphanumeric characters",
						status: 500,
						code: "SIWE_INVALID_NONCE_CONFIGURATION",
					});
				}

				// Store nonce with wallet address and chain ID context
				await ctx.context.internalAdapter.createVerificationValue({
					identifier: `siwe:${walletAddress}:${chainId}`,
					value: nonce,
					expiresAt: new Date(Date.now() + 15 * 60 * 1000),
				});

				return ctx.json({ nonce });
			},
		);

	return {
		id: "siwe-v2",
		version: PACKAGE_VERSION,
		schema: mergeSchema(schema, options?.schema) as WalletAddressSchema,
		endpoints: {
			getSiweNonce: createSiweNonceEndpoint("/siwe/nonce"),
			getNonce: createSiweNonceEndpoint("/siwe/get-nonce"),
			createSiweChallenge: createAuthEndpoint(
				"/siwe/challenge",
				{
					method: "POST",
					body: siweChallengeBodySchema,
					requireRequest: true,
				},
				async (ctx) => {
					assertSiweEnabled(options);
					assertSiweChainAllowed(ctx.body.chainId, options);
					const session =
						ctx.body.purpose === "link-wallet"
							? (await getFreshSessionFromCtx(ctx)).session
							: null;
					const walletAddress = toChecksumAddress(ctx.body.walletAddress);
					const { challengeId, nonce } = createSiweChallengeValues();
					const issuedAt = new Date();
					const expiresAt = new Date(
						issuedAt.getTime() + challengeExpiresIn * 1000,
					);
					const uri = getSiweUri(options);
					const message = createSiweMessage({
						domain: options.domain,
						uri,
						walletAddress,
						chainId: ctx.body.chainId,
						nonce,
						challengeId,
						purpose: ctx.body.purpose,
						issuedAt,
						expiresAt,
					});
					await ctx.context.internalAdapter.createVerificationValue({
						identifier: siweChallengeIdentifier(challengeId),
						value: serializeSiweChallenge({
							version: 2,
							challengeId,
							nonce,
							purpose: ctx.body.purpose,
							walletAddress,
							chainId: ctx.body.chainId,
							domain: options.domain,
							uri,
							message,
							userId: session?.user.id,
							sessionId: session?.session.id,
						}),
						expiresAt,
					});
					return ctx.json({
						challengeId,
						nonce,
						message,
						expiresAt: expiresAt.toISOString(),
						purpose: ctx.body.purpose,
						walletAddress,
						chainId: ctx.body.chainId,
					});
				},
			),
			verifySiweMessage: createAuthEndpoint(
				"/siwe/verify",
				{
					method: "POST",
					body: z
						.object({
							message: z
								.string()
								.min(1)
								.max(SIWE_MESSAGE_MAX_LENGTH)
								.refine(isSiweMessageWithinLimit, {
									message: "SIWE message must not exceed 16 KiB",
								}),
							signature: z.string().min(1).max(SIWE_SIGNATURE_MAX_LENGTH),
							walletAddress: z
								.string()
								.regex(/^0[xX][a-fA-F0-9]{40}$/i)
								.length(42),
							chainId: chainIdInputSchema.optional().default(1),
							challengeId: challengeIdSchema,
							email: z.email().max(320).optional(),
							oauth_query: oauthQueryInputSchema,
						})
						.strict()
						.refine((data) => options.anonymous !== false || !!data.email, {
							message:
								"Email is required when the anonymous plugin option is disabled.",
							path: ["email"],
						}),
					requireRequest: true,
				},
				async (ctx) => {
					const {
						message,
						signature,
						walletAddress: rawWalletAddress,
						chainId,
						email,
					} = ctx.body;
					const isAnon = options.anonymous ?? true;

					if (!isAnon && !email) {
						throw APIError.fromStatus("BAD_REQUEST", {
							message: "Email is required when anonymous is disabled.",
							status: 400,
						});
					}

					try {
						const walletAddress = await verifySiweProof(
							ctx,
							{
								message,
								signature,
								walletAddress: rawWalletAddress,
								chainId,
								challengeId: ctx.body.challengeId,
							},
							options,
							{ purpose: "sign-in" },
						);

						// Look for existing user by their wallet addresses
						let user: User | null = null;

						// Check if there's a wallet address record for this exact address+chainId combination
						const existingWalletAddress: WalletAddress | null =
							await ctx.context.adapter.findOne({
								model: "walletAddress",
								where: [
									{ field: "address", operator: "eq", value: walletAddress },
									{ field: "chainId", operator: "eq", value: chainId },
								],
							});

						if (existingWalletAddress) {
							// Get the user associated with this wallet address
							user = await ctx.context.adapter.findOne({
								model: "user",
								where: [
									{
										field: "id",
										operator: "eq",
										value: existingWalletAddress.userId,
									},
								],
							});
						} else {
							// No exact match found, check if this address exists on any other chain
							const anyWalletAddress: WalletAddress | null =
								await ctx.context.adapter.findOne({
									model: "walletAddress",
									where: [
										{ field: "address", operator: "eq", value: walletAddress },
									],
								});

							if (anyWalletAddress) {
								// Same address exists on different chain, get that user
								user = await ctx.context.adapter.findOne({
									model: "user",
									where: [
										{
											field: "id",
											operator: "eq",
											value: anyWalletAddress.userId,
										},
									],
								});
							}
						}

						// Create new user if none exists
						if (!user) {
							if (options.allowUserCreation === false) {
								throw APIError.fromStatus("FORBIDDEN", {
									message: "SIWE user creation is disabled",
									status: 403,
									code: "SIWE_USER_CREATION_DISABLED",
								});
							}
							const domain =
								options.emailDomainName ?? getOrigin(ctx.context.baseURL);
							const normalizedEmail = email?.toLowerCase();
							// SIWE proves wallet control, not email ownership: bind the caller
							// email only when unclaimed, else keep the wallet-derived address.
							// Silent fallback (no distinct error) avoids an enumeration oracle.
							// FIXME(siwe-contact-ownership): non-breaking floor; the durable fix
							// drops the `email` body field and attaches a verified email via a
							// separate authenticated link flow. Land on `next` after main->next sync.
							let userEmail = `${walletAddress}@${domain}`;
							if (!isAnon && normalizedEmail) {
								const existingUser =
									await ctx.context.internalAdapter.findUserByEmail(
										normalizedEmail,
									);
								if (!existingUser) {
									userEmail = normalizedEmail;
								}
							}
							const { name, avatar } =
								(await options.ensLookup?.({ walletAddress })) ?? {};

							user = await ctx.context.internalAdapter.createUser(
								{
									name: name ?? walletAddress,
									email: userEmail,
									image: avatar ?? "",
								},
								{ method: "siwe" },
							);

							// Create wallet address record
							await ctx.context.adapter.create({
								model: "walletAddress",
								data: {
									userId: user.id,
									address: walletAddress,
									chainId,
									isPrimary: true, // First address is primary
									createdAt: new Date(),
								},
							});

							// Create account record for wallet authentication
							await ctx.context.internalAdapter.createAccount({
								userId: user.id,
								providerId: "siwe",
								accountId: `${walletAddress}:${chainId}`,
								createdAt: new Date(),
								updatedAt: new Date(),
							});
						} else {
							// User exists, but check if this specific address/chain combo exists
							if (!existingWalletAddress) {
								// Add this new chainId to existing user's addresses
								await ctx.context.adapter.create({
									model: "walletAddress",
									data: {
										userId: user.id,
										address: walletAddress,
										chainId,
										isPrimary: false, // Additional addresses are not primary by default
										createdAt: new Date(),
									},
								});

								// Create account record for this new wallet+chain combination
								await ctx.context.internalAdapter.createAccount({
									userId: user.id,
									providerId: "siwe",
									accountId: `${walletAddress}:${chainId}`,
									createdAt: new Date(),
									updatedAt: new Date(),
								});
							}
						}

						const session = await ctx.context.internalAdapter.createSession(
							user.id,
						);

						if (!session) {
							throw APIError.fromStatus("INTERNAL_SERVER_ERROR", {
								message: "Internal Server Error",
								status: 500,
							});
						}

						await setSessionCookie(ctx, { session, user });

						return ctx.json({
							token: session.token,
							success: true,
							user: {
								id: user.id,
								walletAddress,
								chainId,
							},
						});
					} catch (error: unknown) {
						if (isAPIError(error)) throw error;
						throw APIError.fromStatus("UNAUTHORIZED", {
							message: "Something went wrong. Please try again later.",
							error: error instanceof Error ? error.message : "Unknown error",
							status: 401,
						});
					}
				},
			),
			...createSiweWalletEndpoints(options),
		},
		rateLimit: [
			{
				pathMatcher(path) {
					return [
						"/siwe/challenge",
						"/siwe/nonce",
						"/siwe/get-nonce",
						"/siwe/verify",
						"/siwe/link-wallet",
					].includes(path);
				},
				window: rateLimitWindow,
				max: rateLimitMax,
			},
		],
		options,
	} satisfies CinaAuthPlugin;
};

import { createAuthEndpoint } from "@cinaauth/core/api";
import { BASE_ERROR_CODES } from "@cinaauth/core/error";
import * as z from "zod";
import {
	APIError,
	freshSessionMiddleware,
	sensitiveSessionMiddleware,
} from "../../api";
import type { Account } from "../../types";
import type { WalletAddress } from "./types";
import {
	isSiweMessageWithinLimit,
	SIWE_MESSAGE_MAX_LENGTH,
	SIWE_SIGNATURE_MAX_LENGTH,
} from "./types";
import type { SIWEProofOptions } from "./verify-proof";
import { verifySiweProof } from "./verify-proof";

const walletAddressSchema = z
	.string()
	.regex(/^0[xX][a-fA-F0-9]{40}$/i)
	.length(42);

const walletSelectorSchema = z
	.object({
		walletAddress: walletAddressSchema,
		chainId: z
			.number()
			.int()
			.positive()
			.max(Number.MAX_SAFE_INTEGER)
			.optional()
			.default(1),
	})
	.strict();

const linkWalletSchema = walletSelectorSchema
	.extend({
		message: z
			.string()
			.min(1)
			.max(SIWE_MESSAGE_MAX_LENGTH)
			.refine(isSiweMessageWithinLimit, {
				message: "SIWE message must not exceed 16 KiB",
			}),
		signature: z.string().min(1).max(SIWE_SIGNATURE_MAX_LENGTH),
		challengeId: z
			.string()
			.regex(/^[A-Za-z0-9]{32}$/)
			.length(32)
			.optional(),
	})
	.strict();

type SIWEWalletOptions = SIWEProofOptions;

const eq = (field: string, value: string | number | boolean) => ({
	field,
	operator: "eq" as const,
	value,
});

const eqAddress = (value: string) => ({
	...eq("address", value),
	mode: "insensitive" as const,
});

const walletAccountId = (address: string, chainId: number) =>
	`${address}:${chainId}`;

const walletNotFound = () =>
	APIError.fromStatus("BAD_REQUEST", {
		message: "Wallet not found",
		status: 400,
		code: "WALLET_NOT_FOUND",
	});

const walletAlreadyLinked = () =>
	APIError.fromStatus("BAD_REQUEST", {
		message: "Wallet is already linked to another user",
		status: 400,
		code: "WALLET_ALREADY_LINKED",
	});

/** Create authenticated self-service SIWE wallet lifecycle endpoints. */
export const createSiweWalletEndpoints = (options: SIWEWalletOptions) => ({
	listSiweWallets: createAuthEndpoint(
		"/siwe/list-wallets",
		{
			method: "GET",
			use: [sensitiveSessionMiddleware],
		},
		async (ctx) => {
			const wallets = await ctx.context.adapter.findMany<WalletAddress>({
				model: "walletAddress",
				where: [eq("userId", ctx.context.session.user.id)],
				limit: 100,
				sortBy: { field: "createdAt", direction: "asc" },
			});
			return ctx.json({
				wallets: wallets.map(
					({ id, address, chainId, isPrimary, createdAt }) => ({
						id,
						address,
						chainId,
						isPrimary,
						createdAt,
					}),
				),
			});
		},
	),
	linkSiweWallet: createAuthEndpoint(
		"/siwe/link-wallet",
		{
			method: "POST",
			body: linkWalletSchema,
			use: [freshSessionMiddleware],
			requireRequest: true,
		},
		async (ctx) => {
			const userId = ctx.context.session.user.id;
			const walletAddress = await verifySiweProof(ctx, ctx.body, options, {
				purpose: "link-wallet",
				userId,
				sessionId: ctx.context.session.session.id,
			});
			const { chainId } = ctx.body;
			const result = await ctx.context.adapter.transaction(async (trx) => {
				const addressOwner = await trx.findOne<WalletAddress>({
					model: "walletAddress",
					where: [eqAddress(walletAddress)],
				});
				if (addressOwner && addressOwner.userId !== userId) {
					throw walletAlreadyLinked();
				}

				const exactWallet = await trx.findOne<WalletAddress>({
					model: "walletAddress",
					where: [
						eq("userId", userId),
						eqAddress(walletAddress),
						eq("chainId", chainId),
					],
				});
				const accountId = walletAccountId(walletAddress, chainId);
				const existingAccount = await trx.findOne<Account>({
					model: "account",
					where: [
						eq("providerId", "siwe"),
						{
							...eq("accountId", accountId),
							mode: "insensitive",
						},
					],
				});
				if (existingAccount && existingAccount.userId !== userId) {
					throw walletAlreadyLinked();
				}

				const currentWallets = await trx.findMany<WalletAddress>({
					model: "walletAddress",
					where: [eq("userId", userId)],
				});
				const isPrimary = exactWallet?.isPrimary ?? currentWallets.length === 0;
				if (!exactWallet) {
					await trx.create({
						model: "walletAddress",
						data: {
							userId,
							address: walletAddress,
							chainId,
							isPrimary,
							createdAt: new Date(),
						},
					});
				}
				if (!existingAccount) {
					const now = new Date();
					await trx.create({
						model: "account",
						data: {
							userId,
							providerId: "siwe",
							accountId,
							createdAt: now,
							updatedAt: now,
						},
					});
				}

				return { alreadyLinked: !!exactWallet, isPrimary };
			});

			return ctx.json({
				success: true,
				...result,
				walletAddress,
				chainId,
				user: { id: userId },
			});
		},
	),
	setPrimarySiweWallet: createAuthEndpoint(
		"/siwe/set-primary-wallet",
		{
			method: "POST",
			body: walletSelectorSchema,
			use: [freshSessionMiddleware],
		},
		async (ctx) => {
			const userId = ctx.context.session.user.id;
			const { walletAddress, chainId } = ctx.body;
			const wallet = await ctx.context.adapter.transaction(async (trx) => {
				const target = await trx.findOne<WalletAddress>({
					model: "walletAddress",
					where: [
						eq("userId", userId),
						eqAddress(walletAddress),
						eq("chainId", chainId),
					],
				});
				if (!target) throw walletNotFound();
				await trx.updateMany({
					model: "walletAddress",
					where: [eq("userId", userId)],
					update: { isPrimary: false },
				});
				await trx.update({
					model: "walletAddress",
					where: [eq("id", target.id), eq("userId", userId)],
					update: { isPrimary: true },
				});
				return target;
			});

			return ctx.json({
				success: true,
				walletAddress: wallet.address,
				chainId: wallet.chainId,
				isPrimary: true,
				user: { id: userId },
			});
		},
	),
	unlinkSiweWallet: createAuthEndpoint(
		"/siwe/unlink-wallet",
		{
			method: "POST",
			body: walletSelectorSchema,
			use: [freshSessionMiddleware],
		},
		async (ctx) => {
			const userId = ctx.context.session.user.id;
			const { walletAddress, chainId } = ctx.body;
			const result = await ctx.context.adapter.transaction(async (trx) => {
				const target = await trx.findOne<WalletAddress>({
					model: "walletAddress",
					where: [
						eq("userId", userId),
						eqAddress(walletAddress),
						eq("chainId", chainId),
					],
				});
				if (!target) throw walletNotFound();

				const accounts = await trx.findMany<Account>({
					model: "account",
					where: [eq("userId", userId)],
				});
				const accountId = walletAccountId(target.address, target.chainId);
				const walletAccount = accounts.find(
					(account) =>
						account.providerId === "siwe" &&
						account.accountId.toLowerCase() === accountId.toLowerCase(),
				);
				if (
					walletAccount &&
					accounts.length === 1 &&
					!ctx.context.options.account?.accountLinking?.allowUnlinkingAll
				) {
					throw APIError.from(
						"BAD_REQUEST",
						BASE_ERROR_CODES.FAILED_TO_UNLINK_LAST_ACCOUNT,
					);
				}

				await trx.delete({
					model: "walletAddress",
					where: [eq("id", target.id), eq("userId", userId)],
				});
				if (walletAccount) {
					await trx.delete({
						model: "account",
						where: [eq("id", walletAccount.id), eq("userId", userId)],
					});
				}

				const remaining = await trx.findMany<WalletAddress>({
					model: "walletAddress",
					where: [eq("userId", userId)],
					sortBy: { field: "createdAt", direction: "asc" },
				});
				let newPrimary = remaining.find((wallet) => wallet.isPrimary) ?? null;
				if (remaining.length > 0 && (target.isPrimary || !newPrimary)) {
					newPrimary = remaining[0]!;
					await trx.updateMany({
						model: "walletAddress",
						where: [eq("userId", userId)],
						update: { isPrimary: false },
					});
					await trx.update({
						model: "walletAddress",
						where: [eq("id", newPrimary.id), eq("userId", userId)],
						update: { isPrimary: true },
					});
				}

				return {
					walletAddress: target.address,
					chainId: target.chainId,
					newPrimary: newPrimary
						? {
								walletAddress: newPrimary.address,
								chainId: newPrimary.chainId,
							}
						: null,
				};
			});

			return ctx.json({
				success: true,
				...result,
				user: { id: userId },
			});
		},
	),
});

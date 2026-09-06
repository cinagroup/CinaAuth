import type { GenericEndpointContext } from "@cinaauth/core";
import { APIError } from "../../api";
import { toChecksumAddress } from "../../utils/hashing";
import type { SIWEChallengePurpose } from "./challenge";
import { parseStoredSiweChallenge, siweChallengeIdentifier } from "./challenge";
import { toCaip10AccountId } from "./identity";
import {
	normalizeSiweDomain,
	parseSiweDateTime,
	parseSiweMessageStrict,
} from "./parse-message";
import type { SIWEVerifyMessageArgs } from "./types";

interface SIWEProofInput {
	message: string;
	signature: string;
	walletAddress: string;
	chainId: number;
	challengeId?: string | undefined;
}

export interface SIWEProofOptions {
	domain: string;
	uri?: string | undefined;
	enabled?: boolean | undefined;
	allowedChainIds?: readonly number[] | undefined;
	legacyNonce?: boolean | undefined;
	maxMessageAge?: number | undefined;
	clockSkew?: number | undefined;
	verifyMessage: (args: SIWEVerifyMessageArgs) => Promise<boolean>;
}

interface SIWEProofBinding {
	purpose: SIWEChallengePurpose;
	userId?: string | undefined;
	sessionId?: string | undefined;
}

const unauthorized = (message: string, code: string) =>
	APIError.fromStatus("UNAUTHORIZED", { message, status: 401, code });

export function getSiweUri(options: Pick<SIWEProofOptions, "domain" | "uri">) {
	return options.uri ?? `https://${normalizeSiweDomain(options.domain)}`;
}

export function assertSiweEnabled(
	options: Pick<SIWEProofOptions, "enabled">,
): void {
	if (options.enabled === false) {
		throw APIError.fromStatus("FORBIDDEN", {
			message: "Sign in with Ethereum is disabled",
			status: 403,
			code: "SIWE_DISABLED",
		});
	}
}

export function assertSiweChainAllowed(
	chainId: number,
	options: Pick<SIWEProofOptions, "allowedChainIds">,
): void {
	if (options.allowedChainIds && !options.allowedChainIds.includes(chainId)) {
		throw APIError.fromStatus("BAD_REQUEST", {
			message: "The requested chain is not allowed for SIWE",
			status: 400,
			code: "SIWE_CHAIN_NOT_ALLOWED",
		});
	}
}

/** Consume and verify a server-issued EIP-4361 proof. */
export async function verifySiweProof(
	ctx: GenericEndpointContext,
	input: SIWEProofInput,
	options: SIWEProofOptions,
	binding: SIWEProofBinding,
): Promise<string> {
	assertSiweEnabled(options);
	assertSiweChainAllowed(input.chainId, options);
	const walletAddress = toChecksumAddress(input.walletAddress);
	let expectedNonce: string;
	let expectedUri = getSiweUri(options);
	let canonicalMessage: string | undefined;

	if (input.challengeId) {
		const verification =
			await ctx.context.internalAdapter.consumeVerificationValue(
				siweChallengeIdentifier(input.challengeId),
			);
		const challenge = verification
			? parseStoredSiweChallenge(verification.value)
			: null;
		const challengeMatches =
			!!challenge &&
			challenge.challengeId === input.challengeId &&
			challenge.purpose === binding.purpose &&
			challenge.walletAddress.toLowerCase() === walletAddress.toLowerCase() &&
			challenge.chainId === input.chainId &&
			normalizeSiweDomain(challenge.domain) ===
				normalizeSiweDomain(options.domain) &&
			challenge.uri === expectedUri &&
			(binding.purpose !== "link-wallet" ||
				(!!binding.userId &&
					!!binding.sessionId &&
					challenge.userId === binding.userId &&
					challenge.sessionId === binding.sessionId));
		if (!challengeMatches || !challenge) {
			throw unauthorized(
				"Unauthorized: Invalid, expired, or mismatched SIWE challenge",
				"UNAUTHORIZED_SIWE_CHALLENGE_MISMATCH",
			);
		}
		expectedNonce = challenge.nonce;
		expectedUri = challenge.uri;
		canonicalMessage = challenge.message;
	} else {
		if (options.legacyNonce === false) {
			throw unauthorized(
				"Unauthorized: Legacy SIWE nonce verification is disabled",
				"SIWE_LEGACY_NONCE_DISABLED",
			);
		}
		const verification =
			await ctx.context.internalAdapter.consumeVerificationValue(
				`siwe:${walletAddress}:${input.chainId}`,
			);
		if (!verification) {
			throw unauthorized(
				"Unauthorized: Invalid or expired nonce",
				"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
			);
		}
		expectedNonce = verification.value;
	}

	const parsedMessage = parseSiweMessageStrict(input.message);
	const nonceMatches = parsedMessage?.nonce === expectedNonce;
	const addressMatches =
		!!parsedMessage?.address &&
		parsedMessage.address.toLowerCase() === walletAddress.toLowerCase();
	const chainMatches = parsedMessage?.chainId === input.chainId;
	const domainMatches =
		!!parsedMessage?.domain &&
		normalizeSiweDomain(parsedMessage.domain) ===
			normalizeSiweDomain(options.domain);
	const uriMatches = parsedMessage?.uri === expectedUri;
	const schemeMatches =
		!parsedMessage?.scheme ||
		parsedMessage.scheme.toLowerCase() ===
			new URL(expectedUri).protocol.slice(0, -1).toLowerCase();
	const canonicalMessageMatches =
		canonicalMessage === undefined || canonicalMessage === input.message;
	const requestIdMatches =
		!input.challengeId || parsedMessage?.requestId === input.challengeId;

	if (
		!parsedMessage ||
		!nonceMatches ||
		!addressMatches ||
		!chainMatches ||
		!domainMatches ||
		!uriMatches ||
		!schemeMatches ||
		!canonicalMessageMatches ||
		!requestIdMatches ||
		parsedMessage.version !== "1"
	) {
		throw unauthorized(
			"Unauthorized: SIWE message does not match the server-issued challenge",
			"UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
		);
	}

	const now = Date.now();
	const clockSkewMs = (options.clockSkew ?? 60) * 1000;
	const maxMessageAgeMs = (options.maxMessageAge ?? 15 * 60) * 1000;
	const issuedAt = parseSiweDateTime(parsedMessage.issuedAt);
	if (
		issuedAt === null ||
		issuedAt > now + clockSkewMs ||
		now - issuedAt > maxMessageAgeMs + clockSkewMs
	) {
		throw unauthorized(
			"Unauthorized: SIWE message has an invalid or stale Issued At value",
			"UNAUTHORIZED_SIWE_MESSAGE_ISSUED_AT",
		);
	}
	if (parsedMessage.expirationTime) {
		const expiresAt = parseSiweDateTime(parsedMessage.expirationTime);
		if (expiresAt === null || now - clockSkewMs >= expiresAt) {
			throw unauthorized(
				"Unauthorized: SIWE message has expired",
				"UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
			);
		}
	}
	if (parsedMessage.notBefore) {
		const notBefore = parseSiweDateTime(parsedMessage.notBefore);
		if (notBefore === null || now + clockSkewMs < notBefore) {
			throw unauthorized(
				"Unauthorized: SIWE message is not yet valid",
				"UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
			);
		}
	}

	const verified = await options.verifyMessage({
		message: input.message,
		signature: input.signature,
		address: walletAddress,
		chainId: input.chainId,
		cacao: {
			h: { t: "caip122" },
			p: {
				domain: options.domain,
				aud: input.challengeId ? expectedUri : options.domain,
				nonce: expectedNonce,
				iss: input.challengeId
					? `did:pkh:${toCaip10AccountId(walletAddress, input.chainId)}`
					: options.domain,
				version: "1",
				iat: parsedMessage.issuedAt,
				nbf: parsedMessage.notBefore,
				exp: parsedMessage.expirationTime,
				requestId: parsedMessage.requestId,
				resources: parsedMessage.resources,
			},
			s: { t: "eip191", s: input.signature },
		},
	});

	if (!verified) {
		throw unauthorized(
			"Unauthorized: Invalid SIWE signature",
			"UNAUTHORIZED_SIWE_SIGNATURE",
		);
	}

	return walletAddress;
}

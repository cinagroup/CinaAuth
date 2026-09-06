import { generateRandomString } from "../../crypto";
import { toChecksumAddress } from "../../utils/hashing";

/** A v2 SIWE challenge's single authorized operation. */
export type SIWEChallengePurpose = "sign-in" | "link-wallet";

export interface StoredSiweChallenge {
	version: 2;
	challengeId: string;
	nonce: string;
	purpose: SIWEChallengePurpose;
	walletAddress: string;
	chainId: number;
	domain: string;
	uri: string;
	message: string;
	userId?: string | undefined;
	sessionId?: string | undefined;
}

export const siweChallengeIdentifier = (challengeId: string) =>
	`siwe:v2:${challengeId}`;

export function createSiweChallengeValues(): {
	challengeId: string;
	nonce: string;
} {
	return {
		challengeId: generateRandomString(32, "a-z", "A-Z", "0-9"),
		nonce: generateRandomString(32, "a-z", "A-Z", "0-9"),
	};
}

export function serializeSiweChallenge(challenge: StoredSiweChallenge): string {
	return JSON.stringify(challenge);
}

export function parseStoredSiweChallenge(
	value: string,
): StoredSiweChallenge | null {
	try {
		const parsed: unknown = JSON.parse(value);
		if (!parsed || typeof parsed !== "object") return null;
		const candidate = parsed as Record<string, unknown>;
		if (
			candidate.version !== 2 ||
			typeof candidate.challengeId !== "string" ||
			!/^[A-Za-z0-9]{32}$/.test(candidate.challengeId) ||
			typeof candidate.nonce !== "string" ||
			!/^[A-Za-z0-9]{32}$/.test(candidate.nonce) ||
			(candidate.purpose !== "sign-in" &&
				candidate.purpose !== "link-wallet") ||
			typeof candidate.walletAddress !== "string" ||
			!/^0[xX][a-fA-F0-9]{40}$/.test(candidate.walletAddress) ||
			typeof candidate.chainId !== "number" ||
			!Number.isSafeInteger(candidate.chainId) ||
			candidate.chainId <= 0 ||
			typeof candidate.domain !== "string" ||
			typeof candidate.uri !== "string" ||
			typeof candidate.message !== "string" ||
			(candidate.userId !== undefined &&
				typeof candidate.userId !== "string") ||
			(candidate.sessionId !== undefined &&
				typeof candidate.sessionId !== "string")
		) {
			return null;
		}
		return {
			version: 2,
			challengeId: candidate.challengeId,
			nonce: candidate.nonce,
			purpose: candidate.purpose,
			walletAddress: toChecksumAddress(candidate.walletAddress),
			chainId: candidate.chainId,
			domain: candidate.domain,
			uri: candidate.uri,
			message: candidate.message,
			userId: candidate.userId,
			sessionId: candidate.sessionId,
		};
	} catch {
		return null;
	}
}

export function createSiweMessage(input: {
	domain: string;
	uri: string;
	walletAddress: string;
	chainId: number;
	nonce: string;
	challengeId: string;
	purpose: SIWEChallengePurpose;
	issuedAt: Date;
	expiresAt: Date;
}): string {
	const statement =
		input.purpose === "link-wallet"
			? "Link this wallet to your account."
			: "Sign in with Ethereum.";
	return (
		`${input.domain} wants you to sign in with your Ethereum account:\n` +
		`${input.walletAddress}\n\n` +
		`${statement}\n\n` +
		`URI: ${input.uri}\n` +
		"Version: 1\n" +
		`Chain ID: ${input.chainId}\n` +
		`Nonce: ${input.nonce}\n` +
		`Issued At: ${input.issuedAt.toISOString()}\n` +
		`Expiration Time: ${input.expiresAt.toISOString()}\n` +
		`Request ID: ${input.challengeId}`
	);
}

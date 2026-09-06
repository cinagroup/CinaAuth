import type { CinaAuthRateLimitStorage, RateLimit } from "cinaauth";
import type { RateLimitRule } from "./rate-limit-policy";

type RateLimitStub = {
	consume: (
		key: string,
		rule: RateLimitRule,
	) => Promise<{ allowed: boolean; retryAfter: number | null }>;
	get: (key: string) => Promise<RateLimit | null>;
	set: (key: string, value: RateLimit) => Promise<void>;
};

type RateLimitStorageBindings = {
	RATE_LIMITER: {
		getByName: (name: string) => RateLimitStub;
	};
};

export const LOGIN_RATE_LIMIT_RULES = {
	"/sign-in/*": { window: 60, max: 5 },
} as const;

export const SIWE_RATE_LIMIT_RULES = {
	"/siwe/challenge": { window: 60, max: 10 },
	"/siwe/verify": { window: 60, max: 10 },
	"/siwe/link-wallet": { window: 60, max: 10 },
} as const;

export const EMAIL_OTP_SEND_RATE_LIMIT_RULES = {
	"/email-otp/send-verification-otp": { window: 60, max: 10 },
} as const;

export const AUTH_RATE_LIMIT_RULES = {
	...LOGIN_RATE_LIMIT_RULES,
	...EMAIL_OTP_SEND_RATE_LIMIT_RULES,
	...SIWE_RATE_LIMIT_RULES,
} as const;

/**
 * Hashes a CinaAuth bucket into one of 256 stable Durable Object shards.
 */
export const getRateLimitShardName = async (key: string) => {
	const digest = new Uint8Array(
		await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)),
	);
	return `rate-limit-v1-${digest[0]!.toString(16).padStart(2, "0")}`;
};

/**
 * Adapts the Durable Object RPC surface to CinaAuth custom rate-limit storage.
 */
export const createDurableObjectRateLimitStorage = (
	env: RateLimitStorageBindings,
): CinaAuthRateLimitStorage => {
	const getStub = async (key: string) =>
		env.RATE_LIMITER.getByName(await getRateLimitShardName(key));

	return {
		consume: async (key, rule) => (await getStub(key)).consume(key, rule),
	};
};

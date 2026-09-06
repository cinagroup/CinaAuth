import { describe, expect, it, vi } from "vitest";
import { decideRateLimit } from "../src/rate-limit-policy";
import {
	AUTH_RATE_LIMIT_RULES,
	createDurableObjectRateLimitStorage,
	EMAIL_OTP_SEND_RATE_LIMIT_RULES,
	getRateLimitShardName,
	LOGIN_RATE_LIMIT_RULES,
	SIWE_RATE_LIMIT_RULES,
} from "../src/rate-limit-storage";

describe("Durable Object rate-limit policy", () => {
	it("allows, blocks, and resets a login bucket", () => {
		const rule = LOGIN_RATE_LIMIT_RULES["/sign-in/*"];
		const now = 1_000_000;
		expect(decideRateLimit(null, rule, now)).toEqual({
			action: "reset",
			allowed: true,
			retryAfter: null,
		});
		expect(
			decideRateLimit(
				{ key: "ip|/sign-in/email", count: 4, lastRequest: now - 1_000 },
				rule,
				now,
			),
		).toEqual({ action: "increment", allowed: true, retryAfter: null });
		expect(
			decideRateLimit(
				{ key: "ip|/sign-in/email", count: 5, lastRequest: now - 1_000 },
				rule,
				now,
			),
		).toEqual({ action: "block", allowed: false, retryAfter: 59 });
		expect(
			decideRateLimit(
				{ key: "ip|/sign-in/email", count: 5, lastRequest: now - 61_000 },
				rule,
				now,
			),
		).toEqual({ action: "reset", allowed: true, retryAfter: null });
	});

	it("rejects invalid rate-limit rules", () => {
		expect(() => decideRateLimit(null, { window: 0, max: 5 }, 0)).toThrow(
			RangeError,
		);
	});

	it("applies narrow write limits to every SIWE proof endpoint", () => {
		expect(SIWE_RATE_LIMIT_RULES).toEqual({
			"/siwe/challenge": { window: 60, max: 10 },
			"/siwe/verify": { window: 60, max: 10 },
			"/siwe/link-wallet": { window: 60, max: 10 },
		});
		expect(AUTH_RATE_LIMIT_RULES).toEqual({
			...LOGIN_RATE_LIMIT_RULES,
			...EMAIL_OTP_SEND_RATE_LIMIT_RULES,
			...SIWE_RATE_LIMIT_RULES,
		});
	});

	it("limits email code sends per IP before the per-recipient quota", () => {
		expect(EMAIL_OTP_SEND_RATE_LIMIT_RULES).toEqual({
			"/email-otp/send-verification-otp": { window: 60, max: 10 },
		});
	});
});

describe("Durable Object storage adapter", () => {
	it("routes the same CinaAuth bucket to the same deterministic shard", async () => {
		const consume = vi.fn(async () => ({
			allowed: true,
			retryAfter: null,
		}));
		const get = vi.fn(async () => null);
		const set = vi.fn(async () => undefined);
		const getByName = vi.fn(() => ({ consume, get, set }));
		const storage = createDurableObjectRateLimitStorage({
			RATE_LIMITER: { getByName },
		});
		const key = "203.0.113.10|/sign-in/email";
		const rule = LOGIN_RATE_LIMIT_RULES["/sign-in/*"];

		await storage.consume?.(key, rule);
		await storage.consume?.(key, rule);

		expect(getByName).toHaveBeenNthCalledWith(
			1,
			await getRateLimitShardName(key),
		);
		expect(getByName.mock.calls[0]?.[0]).toBe(getByName.mock.calls[1]?.[0]);
		expect(consume).toHaveBeenCalledTimes(2);
		expect(consume).toHaveBeenLastCalledWith(key, rule);
	});

	it("exposes only atomic consumption and preserves blocked responses", async () => {
		const consume = vi.fn(async () => ({ allowed: false, retryAfter: 59 }));
		const get = vi.fn(async () => null);
		const set = vi.fn(async () => undefined);
		const storage = createDurableObjectRateLimitStorage({
			RATE_LIMITER: { getByName: () => ({ consume, get, set }) },
		});
		expect(Object.keys(storage)).toEqual(["consume"]);
		await expect(
			storage.consume("bucket", { window: 60, max: 5 }),
		).resolves.toEqual({ allowed: false, retryAfter: 59 });
		expect(get).not.toHaveBeenCalled();
		expect(set).not.toHaveBeenCalled();
	});
});

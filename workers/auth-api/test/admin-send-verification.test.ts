import { getTestInstance } from "cinaauth/test";
import { describe, expect, it, vi } from "vitest";
import type { AdminVerificationDependencies } from "../src/admin-send-verification";
import {
	ADMIN_VERIFICATION_RATE_LIMIT_RULE,
	getAdminVerificationRateLimitKey,
	getAdminVerificationServerApi,
	handleAdminSendVerification as handleAdminSendVerificationRequest,
} from "../src/admin-send-verification";
import { TURNSTILE_PROTECTED_ENDPOINTS } from "../src/captcha-config";
import { createAuthPlugins } from "../src/plugins";
import { makeOriginEnv } from "./origin-test-env";

const handleAdminSendVerification = (
	dependencies: AdminVerificationDependencies,
	body: unknown,
) =>
	handleAdminSendVerificationRequest(dependencies, async () => ({
		ok: true,
		body,
	}));

const makeDependencies = (role: string | null = "security_admin") => {
	const getSession = vi.fn(
		async (): Promise<{
			user: { id: string; role?: string | null };
			session: { createdAt: Date | string };
		} | null> =>
			role === null
				? null
				: {
						user: { id: "admin-1", role },
						session: { createdAt: new Date() },
					},
	);
	const findUserById = vi.fn(
		async (
			_userId: string,
		): Promise<{
			id?: unknown;
			email?: unknown;
			phoneNumber?: unknown;
		} | null> => ({
			id: "user-2",
			email: "user@example.com",
			phoneNumber: "+6591234567",
		}),
	);
	const sendEmailOtp = vi.fn(
		async (_input: {
			email: string;
			type: "email-verification";
		}): Promise<void> => undefined,
	);
	const sendPhoneOtp = vi.fn(
		async (_input: { phoneNumber: string }): Promise<void> => undefined,
	);
	const consumeRateLimit = vi.fn(
		async (_key: string, _rule: { window: number; max: number }) => ({
			allowed: true,
			retryAfter: null,
		}),
	);
	const writeAuditEvent = vi.fn(
		async (_event: {
			actorId: string;
			targetId: string;
			channel: "email-otp" | "phone-number";
		}): Promise<void> => undefined,
	);
	const logEvent = vi.fn();

	const dependencies: AdminVerificationDependencies = {
		serverApiAvailable: true,
		getSession,
		findUserById,
		sendEmailOtp,
		sendPhoneOtp,
		consumeRateLimit,
		writeAuditEvent,
		logEvent,
	};
	return {
		dependencies,
		getSession,
		findUserById,
		sendEmailOtp,
		sendPhoneOtp,
		consumeRateLimit,
		writeAuditEvent,
		logEvent,
	};
};

describe("Admin verification delivery boundary", () => {
	it("keeps only enabled public delivery endpoints Turnstile-protected", () => {
		expect(TURNSTILE_PROTECTED_ENDPOINTS).toEqual(
			expect.arrayContaining(["/phone-number/send-otp", "/sign-in/email"]),
		);
		expect(TURNSTILE_PROTECTED_ENDPOINTS).not.toContain(
			"/email-otp/send-verification-otp",
		);
		expect(TURNSTILE_PROTECTED_ENDPOINTS).not.toContain("/sign-in/magic-link");
		expect(TURNSTILE_PROTECTED_ENDPOINTS).not.toContain(
			"/email-otp/request-password-reset",
		);
		expect(TURNSTILE_PROTECTED_ENDPOINTS).not.toContain(
			"/forget-password/email-otp",
		);
		expect(TURNSTILE_PROTECTED_ENDPOINTS).not.toContain(
			"/admin/send-verification",
		);
	});

	it("fails closed when a configured server delivery API is missing", () => {
		expect(getAdminVerificationServerApi({})).toBeNull();
		expect(
			getAdminVerificationServerApi({
				sendVerificationOTP: vi.fn(),
				sendPhoneNumberOTP: vi.fn(),
				logAudit: vi.fn(),
			}),
		).not.toBeNull();
		expect(
			getAdminVerificationServerApi({
				sendVerificationOTP: vi.fn(),
				sendPhoneNumberOTP: vi.fn(),
			}),
		).toBeNull();
	});

	/** @see https://www.better-auth.com/docs/guides/1-7-upgrade-guide */
	it("exposes the enabled server APIs from the configured Worker plugins after initialization", async () => {
		const env = makeOriginEnv();
		const { auth } = await getTestInstance(
			{
				baseURL: env.CINAAUTH_URL,
				secret: env.CINAAUTH_SECRET,
				plugins: createAuthPlugins(env, { advancedOrganization: true }),
			},
			{ disableTestUser: true },
		);

		await auth.$context;
		expect(getAdminVerificationServerApi(auth.api)).not.toBeNull();
	});

	it("reports a missing server API only after authorization", async () => {
		const authorized = makeDependencies();
		authorized.dependencies.serverApiAvailable = false;
		const unavailable = await handleAdminSendVerification(
			authorized.dependencies,
			{ userId: "user-2", type: "email-otp" },
		);
		expect(unavailable).toMatchObject({
			status: 503,
			body: { error: { code: "VERIFICATION_DELIVERY_UNAVAILABLE" } },
		});
		expect(authorized.findUserById).not.toHaveBeenCalled();

		const unauthenticated = makeDependencies(null);
		unauthenticated.dependencies.serverApiAvailable = false;
		const rejected = await handleAdminSendVerification(
			unauthenticated.dependencies,
			{ userId: "user-2", type: "email-otp" },
		);
		expect(rejected.status).toBe(401);
	});

	it("rejects a missing authoritative session before target lookup", async () => {
		const { dependencies, findUserById } = makeDependencies(null);

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 401,
			body: { error: { code: "UNAUTHORIZED" } },
		});
		expect(findUserById).not.toHaveBeenCalled();
	});

	it("rejects a role without the dedicated control-plane permission", async () => {
		const { dependencies, findUserById } = makeDependencies("user");

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 403,
			body: { error: { code: "FORBIDDEN" } },
		});
		expect(findUserById).not.toHaveBeenCalled();
	});

	it("rejects a stale authoritative session before reading the body or sending", async () => {
		const { dependencies, findUserById, consumeRateLimit, sendEmailOtp } =
			makeDependencies();
		dependencies.getSession = vi.fn(async () => ({
			user: { id: "admin-1", role: "security_admin" },
			session: { createdAt: new Date(Date.now() - 16 * 60 * 1000) },
		}));
		const readBody = vi.fn(async () => ({
			ok: true as const,
			body: { userId: "user-2", type: "email-otp" },
		}));

		const result = await handleAdminSendVerificationRequest(
			dependencies,
			readBody,
		);

		expect(result).toMatchObject({
			status: 403,
			body: { error: { code: "SESSION_NOT_FRESH" } },
		});
		expect(readBody).not.toHaveBeenCalled();
		expect(consumeRateLimit).not.toHaveBeenCalled();
		expect(findUserById).not.toHaveBeenCalled();
		expect(sendEmailOtp).not.toHaveBeenCalled();
	});

	it("fails closed without the Durable Object limiter and does not send", async () => {
		const { dependencies, findUserById, sendEmailOtp } = makeDependencies();
		dependencies.consumeRateLimit = undefined;

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 503,
			body: { error: { code: "RATE_LIMIT_UNAVAILABLE" } },
		});
		expect(findUserById).not.toHaveBeenCalled();
		expect(sendEmailOtp).not.toHaveBeenCalled();
	});

	it("returns 429 without sending when the actor-target-channel bucket is exhausted", async () => {
		const { dependencies, findUserById, consumeRateLimit, sendEmailOtp } =
			makeDependencies();
		consumeRateLimit.mockResolvedValueOnce({
			allowed: false,
			retryAfter: 120,
		});

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 429,
			body: { error: { code: "RATE_LIMITED" } },
		});
		expect(consumeRateLimit).toHaveBeenCalledWith(
			getAdminVerificationRateLimitKey("admin-1", "user-2", "email-otp"),
			ADMIN_VERIFICATION_RATE_LIMIT_RULE,
		);
		expect(findUserById).not.toHaveBeenCalled();
		expect(sendEmailOtp).not.toHaveBeenCalled();
	});

	it("fails closed and logs a structured error when the limiter RPC fails", async () => {
		const {
			dependencies,
			findUserById,
			consumeRateLimit,
			sendEmailOtp,
			logEvent,
		} = makeDependencies();
		consumeRateLimit.mockRejectedValueOnce(new Error("limiter unavailable"));

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 503,
			body: { error: { code: "RATE_LIMIT_UNAVAILABLE" } },
		});
		expect(logEvent).toHaveBeenCalledWith({
			level: "error",
			message: "cinaauth.admin_verification.failed",
			code: "RATE_LIMIT_UNAVAILABLE",
			actorId: "admin-1",
			targetId: "user-2",
			channel: "email-otp",
			error: "limiter unavailable",
		});
		expect(findUserById).not.toHaveBeenCalled();
		expect(sendEmailOtp).not.toHaveBeenCalled();
	});

	it.each([
		"super_admin",
		"security_admin",
	])("allows %s to send an email verification OTP through the server API", async (role) => {
		const {
			dependencies,
			findUserById,
			sendEmailOtp,
			consumeRateLimit,
			writeAuditEvent,
		} = makeDependencies(role);

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toEqual({
			status: 200,
			body: { ok: true, data: { sent: true } },
		});
		expect(findUserById).toHaveBeenCalledWith("user-2");
		expect(consumeRateLimit).toHaveBeenCalledWith(
			getAdminVerificationRateLimitKey("admin-1", "user-2", "email-otp"),
			ADMIN_VERIFICATION_RATE_LIMIT_RULE,
		);
		expect(sendEmailOtp).toHaveBeenCalledWith({
			email: "user@example.com",
			type: "email-verification",
		});
		expect(writeAuditEvent).toHaveBeenCalledWith({
			actorId: "admin-1",
			targetId: "user-2",
			channel: "email-otp",
		});
	});

	it("rejects malformed JSON after authentication but before rate limiting", async () => {
		const { dependencies, consumeRateLimit, findUserById } = makeDependencies();

		const result = await handleAdminSendVerificationRequest(
			dependencies,
			async () => ({ ok: false }),
		);

		expect(result).toMatchObject({
			status: 400,
			body: { error: { code: "INVALID_JSON" } },
		});
		expect(consumeRateLimit).not.toHaveBeenCalled();
		expect(findUserById).not.toHaveBeenCalled();
	});

	it.each([
		{},
		{ userId: "user-2" },
		{ userId: "user-2", type: "push" },
	])("rejects an invalid body before target lookup %#", async (body) => {
		const { dependencies, findUserById } = makeDependencies();

		const result = await handleAdminSendVerification(dependencies, body);

		expect(result.status).toBe(400);
		expect(result.body).toMatchObject({
			error: { code: "INVALID_VERIFICATION_REQUEST" },
		});
		expect(findUserById).not.toHaveBeenCalled();
	});

	it("returns 404 when the path-selected target does not exist", async () => {
		const { dependencies, findUserById } = makeDependencies();
		findUserById.mockResolvedValueOnce(null);

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 404,
			body: { error: { code: "USER_NOT_FOUND" } },
		});
	});

	it("rejects an invalid target email for email OTP", async () => {
		const { dependencies, findUserById, sendEmailOtp } = makeDependencies();
		findUserById.mockResolvedValueOnce({
			id: "user-2",
			email: "not-an-email",
		});

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 400,
			body: { error: { code: "INVALID_EMAIL" } },
		});
		expect(sendEmailOtp).not.toHaveBeenCalled();
	});

	it("does not write a success audit and logs a delivery failure", async () => {
		const { dependencies, sendEmailOtp, writeAuditEvent, logEvent } =
			makeDependencies();
		sendEmailOtp.mockRejectedValueOnce(new Error("provider rejected"));

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 502,
			body: { error: { code: "VERIFICATION_DELIVERY_FAILED" } },
		});
		expect(writeAuditEvent).not.toHaveBeenCalled();
		expect(logEvent).toHaveBeenCalledWith({
			level: "error",
			message: "cinaauth.admin_verification.failed",
			code: "VERIFICATION_DELIVERY_FAILED",
			actorId: "admin-1",
			targetId: "user-2",
			channel: "email-otp",
			error: "provider rejected",
		});
	});

	it("validates E.164 before routing phone OTP through the server API", async () => {
		const { dependencies, findUserById, sendPhoneOtp } = makeDependencies();
		findUserById.mockResolvedValueOnce({
			id: "user-2",
			phoneNumber: "91234567",
		});

		const rejected = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "phone-number",
		});

		expect(rejected).toMatchObject({
			status: 400,
			body: { error: { code: "INVALID_PHONE" } },
		});
		expect(sendPhoneOtp).not.toHaveBeenCalled();

		findUserById.mockResolvedValueOnce({
			id: "user-2",
			phoneNumber: "+6591234567",
		});
		const accepted = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "phone-number",
		});

		expect(accepted.status).toBe(200);
		expect(sendPhoneOtp).toHaveBeenCalledWith({
			phoneNumber: "+6591234567",
		});
	});

	it("fails closed when lookup returns a different target id", async () => {
		const { dependencies, findUserById, sendEmailOtp } = makeDependencies();
		findUserById.mockResolvedValueOnce({
			id: "another-user",
			email: "other@example.com",
		});

		const result = await handleAdminSendVerification(dependencies, {
			userId: "user-2",
			type: "email-otp",
		});

		expect(result).toMatchObject({
			status: 502,
			body: { error: { code: "USER_ID_MISMATCH" } },
		});
		expect(sendEmailOtp).not.toHaveBeenCalled();
	});
});

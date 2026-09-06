import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	createMcpHandler: vi.fn(),
	fetchAuthServiceRequest: vi.fn(),
	mcpHandler: vi.fn(),
}));

vi.mock("@cinaauth/mcp", () => ({
	createMcpProtectedRequestHandler: mocks.mcpHandler,
}));
vi.mock("mcp-handler", () => ({
	createMcpHandler: mocks.createMcpHandler,
}));
vi.mock("@/lib/auth", () => ({
	fetchAuthServiceRequest: mocks.fetchAuthServiceRequest,
}));

describe("Account server routes fail closed on invalid Auth configuration", () => {
	afterEach(() => {
		mocks.fetchAuthServiceRequest.mockReset();
		mocks.mcpHandler.mockReset();
		vi.unstubAllEnvs();
		vi.unstubAllGlobals();
		vi.resetModules();
	});

	it("uses the binding-aware transport for configured diagnostic probes", async () => {
		vi.stubEnv("CINAAUTH_REQUIRE_AUTH_WORKER_BINDING", "true");
		vi.stubEnv("CINAAUTH_URL", "https://auth.example.com");
		mocks.fetchAuthServiceRequest.mockImplementation(
			async (pathname: string) =>
				pathname === "/api/auth/get-session"
					? Response.json(null)
					: new Response(null, { status: 204 }),
		);
		const publicFetch = vi.fn(async () => Response.json({ unexpected: true }));
		vi.stubGlobal("fetch", publicFetch);
		const { GET } = await import("../app/api/diagnose/route");

		const response = await GET();

		expect(response.status).toBe(200);
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(mocks.fetchAuthServiceRequest).toHaveBeenCalledTimes(2);
		expect(mocks.fetchAuthServiceRequest).toHaveBeenCalledWith(
			"/",
			expect.objectContaining({ method: "GET" }),
		);
		expect(mocks.fetchAuthServiceRequest).toHaveBeenCalledWith(
			"/api/auth/get-session",
			expect.objectContaining({ method: "GET" }),
		);
		expect(publicFetch).not.toHaveBeenCalled();
		await expect(response.json()).resolves.toMatchObject({
			status: "ok",
			tests: {
				authApiRoot: { success: true },
				authApiSession: { success: true },
			},
		});
	});

	it("returns the generic unavailable response when an Auth probe is unavailable", async () => {
		vi.stubEnv("CINAAUTH_REQUIRE_AUTH_WORKER_BINDING", "true");
		vi.stubEnv("CINAAUTH_URL", "https://auth.example.com");
		mocks.fetchAuthServiceRequest.mockResolvedValue(
			Response.json({ internal: "binding missing" }, { status: 503 }),
		);
		const publicFetch = vi.fn(async () => Response.json({ unexpected: true }));
		vi.stubGlobal("fetch", publicFetch);
		const { GET } = await import("../app/api/diagnose/route");

		const response = await GET();

		expect(response.status).toBe(503);
		expect(response.headers.get("cache-control")).toBe("no-store");
		await expect(response.json()).resolves.toEqual({
			code: "AUTH_SERVICE_UNAVAILABLE",
			message: "Authentication service is temporarily unavailable.",
		});
		expect(mocks.fetchAuthServiceRequest).toHaveBeenCalledOnce();
		expect(publicFetch).not.toHaveBeenCalled();
	});

	it("does not expose binding exception details from the diagnostic route", async () => {
		vi.stubEnv("CINAAUTH_REQUIRE_AUTH_WORKER_BINDING", "true");
		vi.stubEnv("CINAAUTH_URL", "https://auth.example.com");
		mocks.fetchAuthServiceRequest.mockRejectedValue(
			new Error("private binding topology leaked"),
		);
		const { GET } = await import("../app/api/diagnose/route");

		const response = await GET();

		expect(response.status).toBe(503);
		await expect(response.text()).resolves.not.toContain(
			"private binding topology leaked",
		);
	});

	it("loads MCP JWKS through the binding-aware transport", async () => {
		vi.stubEnv("CINAAUTH_REQUIRE_AUTH_WORKER_BINDING", "true");
		vi.stubEnv("CINAAUTH_URL", "https://auth.example.com");
		mocks.fetchAuthServiceRequest.mockResolvedValue(
			Response.json({ keys: [{ kty: "EC", crv: "P-256" }] }),
		);
		mocks.mcpHandler.mockReturnValue(
			async () => new Response(null, { status: 204 }),
		);
		const publicFetch = vi.fn(async () => Response.json({ unexpected: true }));
		vi.stubGlobal("fetch", publicFetch);

		await import("../app/api/mcp/route");

		const config = mocks.mcpHandler.mock.calls[0]?.[0] as
			| {
					jwksFetch?: () => Promise<unknown>;
					jwksUrl?: string;
			  }
			| undefined;
		expect(config?.jwksUrl).toBeUndefined();
		await expect(config?.jwksFetch?.()).resolves.toEqual({
			keys: [{ kty: "EC", crv: "P-256" }],
		});
		expect(mocks.fetchAuthServiceRequest).toHaveBeenCalledWith(
			"/api/auth/jwks",
			expect.objectContaining({ method: "GET" }),
		);
		expect(publicFetch).not.toHaveBeenCalled();
	});

	it.each([
		{
			name: "the Auth transport returns 503",
			prepare: () =>
				mocks.fetchAuthServiceRequest.mockResolvedValue(
					Response.json({ internal: "binding missing" }, { status: 503 }),
				),
		},
		{
			name: "the Auth transport throws",
			prepare: () =>
				mocks.fetchAuthServiceRequest.mockRejectedValue(
					new Error("private binding topology leaked"),
				),
		},
	])("returns a generic MCP 503 when $name", async ({ prepare }) => {
		vi.stubEnv("CINAAUTH_REQUIRE_AUTH_WORKER_BINDING", "true");
		vi.stubEnv("CINAAUTH_URL", "https://auth.example.com");
		prepare();
		mocks.mcpHandler.mockImplementation(
			(config: { jwksFetch: () => Promise<unknown> }) => async () => {
				await config.jwksFetch();
				return new Response(null, { status: 204 });
			},
		);
		const { GET } = await import("../app/api/mcp/route");

		const response = await GET(
			new NextRequest("https://accounts.example.com/api/mcp"),
		);

		expect(response.status).toBe(503);
		expect(response.headers.get("cache-control")).toBe("no-store");
		await expect(response.text()).resolves.not.toContain("binding");
	});

	it("keeps the diagnostic route from probing production without CINAAUTH_URL", async () => {
		vi.stubEnv("CINAAUTH_REQUIRE_AUTH_WORKER_BINDING", "true");
		vi.stubEnv("CINAAUTH_URL", undefined);
		const publicFetch = vi.fn(async () => Response.json({ unexpected: true }));
		vi.stubGlobal("fetch", publicFetch);
		const { GET } = await import("../app/api/diagnose/route");

		const response = await GET();

		expect(response.status).toBe(503);
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(publicFetch).not.toHaveBeenCalled();
	});

	it("keeps every MCP method closed for an invalid required Auth URL", async () => {
		vi.stubEnv("CINAAUTH_REQUIRE_AUTH_WORKER_BINDING", "true");
		vi.stubEnv("CINAAUTH_URL", "https://auth.example.com/not-an-origin");
		const publicFetch = vi.fn(async () => Response.json({ unexpected: true }));
		vi.stubGlobal("fetch", publicFetch);
		const { GET, OPTIONS, POST } = await import("../app/api/mcp/route");
		const request = new NextRequest("https://accounts.example.com/api/mcp");

		const [getResponse, postResponse, optionsResponse] = await Promise.all([
			GET(request),
			POST(request),
			OPTIONS(request),
		]);

		for (const response of [getResponse, postResponse, optionsResponse]) {
			expect(response.status).toBe(503);
			expect(response.headers.get("cache-control")).toBe("no-store");
		}
		expect(publicFetch).not.toHaveBeenCalled();
	});
});

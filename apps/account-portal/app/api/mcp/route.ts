import { createMcpProtectedRequestHandler } from "@cinaauth/mcp";
import { createMcpHandler } from "mcp-handler";
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import * as z from "zod";
import { fetchAuthServiceRequest } from "@/lib/auth";
import {
	createAuthServiceUnavailableResponse,
	resolveAuthRuntimeConfiguration,
} from "@/lib/auth-runtime-config";

const AUTH_JWKS_CACHE_KEY = {};
const AUTH_TRANSPORT_UNAVAILABLE_CODE = "CINAAUTH_AUTH_TRANSPORT_UNAVAILABLE";

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

const loadAuthJwks = async () => {
	try {
		const response = await fetchAuthServiceRequest("/api/auth/jwks", {
			method: "GET",
			headers: { Accept: "application/json" },
			cache: "no-store",
		});
		if (!response.ok) throw new Error(AUTH_TRANSPORT_UNAVAILABLE_CODE);
		const body: unknown = await response.json();
		if (
			!isRecord(body) ||
			!Array.isArray(body.keys) ||
			!body.keys.every(isRecord)
		) {
			throw new Error(AUTH_TRANSPORT_UNAVAILABLE_CODE);
		}
		return { keys: body.keys };
	} catch {
		throw new Error(AUTH_TRANSPORT_UNAVAILABLE_CODE);
	}
};

const isTrustedCorsOrigin = (origin: string) => {
	try {
		const url = new URL(origin);
		if (
			process.env.NODE_ENV === "development" &&
			url.protocol === "http:" &&
			(url.hostname === "localhost" || url.hostname === "127.0.0.1")
		) {
			return true;
		}
		return (
			url.protocol === "https:" &&
			(url.hostname === "cinagroup.com" ||
				url.hostname.endsWith(".cinagroup.com"))
		);
	} catch {
		return false;
	}
};

/**
 * Example derived from https://www.npmjs.com/package/mcp-handler
 */
const createConfiguredMcpHandler = (baseURL: string) =>
	createMcpProtectedRequestHandler(
		{
			jwksFetch: loadAuthJwks,
			jwksCacheKey: AUTH_JWKS_CACHE_KEY,
			audience: baseURL + "/api/mcp",
			issuer: baseURL,
		},
		(req, jwt) => {
			return createMcpHandler(
				(server) => {
					server.registerTool(
						"echo",
						{
							description: "Echo a message",
							inputSchema: {
								message: z.string(),
							},
						},
						async ({ message }) => {
							const org = jwt?.[baseURL + "/org"];
							return {
								content: [
									{
										type: "text",
										text: `Echo: ${message}${
											jwt?.sub ? ` for user ${jwt?.sub}` : ""
										}${org ? ` for organization ${org}` : ""}`,
									},
								],
							};
						},
					);
				},
				{
					serverInfo: {
						name: "CinaSeek Accounts",
						version: "1.0.0",
					},
				},
				{
					basePath: "/api",
					maxDuration: 60,
					verboseLogs: true,
				},
			)(req);
		},
	);

function addCorsHeaders(headers: Headers, request: Request) {
	const origin = request.headers.get("origin");
	if (origin && isTrustedCorsOrigin(origin)) {
		headers.set("Access-Control-Allow-Origin", origin);
		headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
		headers.set(
			"Access-Control-Allow-Headers",
			"authorization, content-type, mcp-protocol-version",
		);
		headers.append("Vary", "Origin");
	}
}

function withCors(handler: (req: Request) => Promise<Response> | Response) {
	return async (req: Request) => {
		const res = await handler(req);
		addCorsHeaders(res.headers, req);
		return res;
	};
}

const withAuthAvailability =
	(handler: (req: Request) => Promise<Response> | Response) =>
	async (req: Request) => {
		try {
			return await handler(req);
		} catch (error) {
			if (
				error instanceof Error &&
				(error.message === AUTH_TRANSPORT_UNAVAILABLE_CODE ||
					error.message === `Error: ${AUTH_TRANSPORT_UNAVAILABLE_CODE}`)
			) {
				return createAuthServiceUnavailableResponse();
			}
			throw error;
		}
	};

const runtimeConfiguration = resolveAuthRuntimeConfiguration();
const configuredHandler = runtimeConfiguration.baseURL
	? withCors(
			withAuthAvailability(
				createConfiguredMcpHandler(runtimeConfiguration.baseURL),
			),
		)
	: null;
const unavailableHandler = async () => createAuthServiceUnavailableResponse();

export const GET = configuredHandler ?? unavailableHandler;
export const POST = configuredHandler ?? unavailableHandler;
export async function OPTIONS(req: NextRequest): Promise<Response> {
	if (!configuredHandler) return createAuthServiceUnavailableResponse();
	const headers = new Headers();
	addCorsHeaders(headers, req);
	return new NextResponse(null, {
		headers,
	});
}

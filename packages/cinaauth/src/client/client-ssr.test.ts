// @vitest-environment node
import { expect, it, vi } from "vitest";
import { createAuthClient as createVueClient } from "./vue";

it("should call '/api/auth' for vue client", async () => {
	const customFetchImpl = vi.fn(async (url: string | Request | URL) => {
		expect(url).toBe("/api/auth/get-session");
		return new Response();
	});
	process.env.CINAAUTH_URL = "http://localhost:3000";
	// use DisposableStack when Node.js 24 is the minimum requirement
	using _ = {
		[Symbol.dispose]() {
			process.env.CINAAUTH_URL = undefined;
		},
	};
	const client = createVueClient({
		fetchOptions: {
			customFetchImpl,
		},
	});
	await client.getSession();
	expect(customFetchImpl).toBeCalled();
});

/**
 * @see https://github.com/better-auth/better-auth/issues/5358
 */
it("uses stable Nuxt options for a session fetch", () => {
	const headers = {
		cookie: "cinaauth.session_token=session",
		"x-optional": undefined,
	};
	const pendingFetch = new Promise<never>(() => undefined);
	const useFetch = vi.fn(() => pendingFetch);
	const client = createVueClient({
		baseURL: "http://localhost:3000",
		fetchOptions: { headers },
	});

	void client.useSession(useFetch);

	expect(useFetch).toHaveBeenCalledWith(
		"http://localhost:3000/api/auth/get-session",
		{
			headers: { cookie: "cinaauth.session_token=session" },
			key: "cinaauth:session:http://localhost:3000:/api/auth",
			watch: [expect.anything()],
		},
	);
});

/**
 * @see https://github.com/better-auth/better-auth/issues/5358
 */
it.each([
	[
		"Headers",
		new Headers({ cookie: "cinaauth.session_token=session" }),
		new Headers({ cookie: "cinaauth.session_token=session" }),
	],
	[
		"tuple array",
		[["cookie", "cinaauth.session_token=session"]] satisfies [string, string][],
		[["cookie", "cinaauth.session_token=session"]] satisfies [string, string][],
	],
])("preserves %s for a Nuxt session fetch", (_name, headers, expectedHeaders) => {
	const pendingFetch = new Promise<never>(() => undefined);
	const useFetch = vi.fn(() => pendingFetch);
	const client = createVueClient({
		baseURL: "http://localhost:3000",
		fetchOptions: { headers },
	});

	void client.useSession(useFetch);

	expect(useFetch).toHaveBeenCalledWith(
		"http://localhost:3000/api/auth/get-session",
		{
			headers: expectedHeaders,
			key: "cinaauth:session:http://localhost:3000:/api/auth",
			watch: [expect.anything()],
		},
	);
});

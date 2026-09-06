import { base64Url } from "@better-auth/utils/base64";
import type { BetterFetch, CreateFetchOption } from "@better-fetch/fetch";
import type { CinaAuthClientOptions } from "@cinaauth/core";
import type { User } from "@cinaauth/core/db";
import { CinaAuthError } from "@cinaauth/core/error";
import { APIError, getBaseURL, safeJSONParse } from "cinaauth";
import { signInSocial } from "cinaauth/api";
import { generateRandomString } from "cinaauth/crypto";
import { generateCodeChallenge } from "cinaauth/oauth2";
import { shell } from "electron";
import * as z from "zod";
import type { ElectronClientOptions } from "./types/client";
import { normalizeUserOutput } from "./user";
import { getChannelPrefixWithDelimiter, isProcessType } from "./utils";

export const kElectron = Symbol.for("cinaauth:electron");

const requestAuthOptionsSchema = (() => {
	const { provider, idToken, loginHint, ...signInSocialBody } =
		signInSocial().options.body.shape;

	return z.object({
		...signInSocialBody,
		provider: z.string().nonempty().optional(),
	});
})();
export type ElectronRequestAuthOptions = z.infer<
	typeof requestAuthOptionsSchema
>;

/**
 * Opens the system browser to request user authentication.
 */
export async function requestAuth(
	clientOptions: CinaAuthClientOptions | undefined,
	options: ElectronClientOptions,
	cfg?: ElectronRequestAuthOptions | undefined,
) {
	if (!isProcessType("browser")) {
		throw new CinaAuthError(
			"`requestAuth` can only be called in the main process",
		);
	}
	const { randomBytes } = await import("node:crypto");

	const state = generateRandomString(16, "A-Z", "a-z", "0-9");

	const codeVerifier = base64Url.encode(randomBytes(32), { padding: false });
	const codeChallenge = await generateCodeChallenge(codeVerifier);

	((globalThis as any)[kElectron] ??= new Map<string, string>()).set(
		state,
		codeVerifier,
	);

	let url: URL | null = null;
	if (cfg?.provider) {
		const baseURL = getBaseURL(
			clientOptions?.baseURL,
			clientOptions?.basePath,
			undefined,
			true,
		);

		if (!baseURL) {
			console.log("No base URL found in client options");
			throw APIError.from("INTERNAL_SERVER_ERROR", {
				code: "NO_BASE_URL",
				message: "Base URL is required to use provider-based sign-in.",
			});
		}
		url = new URL(`${baseURL}/electron/init-oauth-proxy`);
		for (const [key, value] of Object.entries(cfg)) {
			url.searchParams.set(
				key,
				typeof value === "string" ? value : JSON.stringify(value),
			);
		}
	} else {
		url = new URL(options.signInURL);
	}
	url.searchParams.set("client_id", options.clientID || "electron");
	url.searchParams.set("code_challenge", codeChallenge);
	url.searchParams.set("state", state);

	await shell.openExternal(url.toString(), {
		activate: true,
	});
}

export interface ElectronAuthenticateOptions {
	fetchOptions?: Omit<CreateFetchOption, "method"> | undefined;
	token: string;
}

/**
 * Exchanges the authorization code for a session.
 */
export async function authenticate({
	$fetch,
	options,
	token,
	getWindow,
	fetchOptions,
}: ElectronAuthenticateOptions & {
	$fetch: BetterFetch;
	options: ElectronClientOptions;
	getWindow: () => Electron.BrowserWindow | null | undefined;
}) {
	if (!isProcessType("browser")) {
		throw new CinaAuthError(
			"`authenticate` can only be called in the main process.",
		);
	}

	const decoded = safeJSONParse(
		new TextDecoder().decode(base64Url.decode(decodeURIComponent(token))),
	) as { identifier: string; state: string };

	const codeVerifier = (globalThis as any)[kElectron]?.get(decoded?.state);
	(globalThis as any)[kElectron]?.delete(decoded?.state);

	if (!codeVerifier) {
		throw new CinaAuthError("Code verifier not found.");
	}

	return await $fetch<{
		token: string;
		user: User & Record<string, any>;
	}>("/electron/token", {
		...fetchOptions,
		method: "POST",
		body: {
			...(fetchOptions?.body || {}),
			token: decoded.identifier,
			state: decoded.state,
			code_verifier: codeVerifier,
		},
		onSuccess: async (ctx) => {
			let user: (User & Record<string, any>) | null = ctx.data?.user ?? null;
			if (user !== null && typeof options.sanitizeUser === "function") {
				try {
					user = await options.sanitizeUser(user);
				} catch (error) {
					console.error("Error while sanitizing user", error);
					user = null;
				}
			}
			if (user === null) return;
			user = normalizeUserOutput(user, options);

			await fetchOptions?.onSuccess?.(ctx);
			getWindow()?.webContents.send(
				`${getChannelPrefixWithDelimiter(options.channelPrefix)}authenticated`,
				user,
			);
		},
	});
}

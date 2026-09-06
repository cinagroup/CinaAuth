import type { CinaAuthPlugin } from "@cinaauth/core";
import { middlewareResponse } from "../../utils/middleware-response";
import { wildcardMatch } from "../../utils/wildcard";
import { PACKAGE_VERSION } from "../../version";
import { defaultEndpoints, Providers, siteVerifyMap } from "./constants";
import { EXTERNAL_ERROR_CODES, INTERNAL_ERROR_CODES } from "./error-codes";
import type { CaptchaOptions } from "./types";

declare module "@cinaauth/core" {
	interface CinaAuthPluginRegistry<AuthOptions, Options> {
		captcha: {
			creator: typeof captcha;
		};
	}
}

import * as verifyHandlers from "./verify-handlers";

export type * from "./types";

const normalizeEndpointPath = (pathname: string, basePath: string) => {
	const pathWithoutBase = pathname.startsWith(basePath)
		? pathname.slice(basePath.length)
		: pathname;
	let normalizedPathname = pathWithoutBase.replace(/\/{2,}/g, "/");
	if (!normalizedPathname.startsWith("/")) {
		normalizedPathname = `/${normalizedPathname}`;
	}
	if (normalizedPathname.length > 1 && normalizedPathname.endsWith("/")) {
		normalizedPathname = normalizedPathname.slice(0, -1);
	}
	return normalizedPathname;
};

export const captcha = (options: CaptchaOptions) =>
	({
		id: "captcha",
		version: PACKAGE_VERSION,
		$ERROR_CODES: EXTERNAL_ERROR_CODES,
		onRequest: async (request, ctx) => {
			try {
				const endpoints = options.endpoints?.length
					? options.endpoints
					: defaultEndpoints;

				const url = new URL(request.url);
				const basePath = ctx.options.basePath ?? "/api/auth";
				const pathname = normalizeEndpointPath(url.pathname, basePath);

				const match = endpoints.some((endpoint) =>
					endpoint.includes("*")
						? wildcardMatch(endpoint)(pathname)
						: endpoint === pathname,
				);

				if (!match) {
					return undefined;
				}

				if (!options.secretKey) {
					throw new Error(INTERNAL_ERROR_CODES.MISSING_SECRET_KEY.message);
				}

				const captchaResponse = request.headers.get("x-captcha-response");

				if (!captchaResponse) {
					return middlewareResponse({
						message: EXTERNAL_ERROR_CODES.MISSING_RESPONSE.message,
						code: EXTERNAL_ERROR_CODES.MISSING_RESPONSE.code,
						status: 400,
					});
				}

				const siteVerifyURL =
					options.siteVerifyURLOverride || siteVerifyMap[options.provider];

				// The visitor IP is deliberately not forwarded to siteverify.
				// getIp applies IPv6 subnet normalization by default, and a
				// browser may also solve the challenge over a different address
				// family than the API request; either mismatch rejects every
				// legitimate token. remoteip is optional for all providers.
				const handlerParams = {
					siteVerifyURL,
					captchaResponse,
					secretKey: options.secretKey,
				};

				if (options.provider === Providers.CLOUDFLARE_TURNSTILE) {
					return await verifyHandlers.cloudflareTurnstile({
						...handlerParams,
						expectedAction: options.expectedAction,
						allowedHostnames: options.allowedHostnames,
					});
				}

				if (options.provider === Providers.GOOGLE_RECAPTCHA) {
					return await verifyHandlers.googleRecaptcha({
						...handlerParams,
						minScore: options.minScore,
						expectedAction: options.expectedAction,
						allowedHostnames: options.allowedHostnames,
					});
				}

				if (options.provider === Providers.HCAPTCHA) {
					return await verifyHandlers.hCaptcha({
						...handlerParams,
						siteKey: options.siteKey,
					});
				}

				if (options.provider === Providers.CAPTCHAFOX) {
					return await verifyHandlers.captchaFox({
						...handlerParams,
						siteKey: options.siteKey,
					});
				}
			} catch (_error) {
				const errorMessage =
					_error instanceof Error ? _error.message : undefined;

				ctx.logger.error(errorMessage ?? "Unknown error", {
					endpoint: request.url,
					message: _error,
				});

				return middlewareResponse({
					message: EXTERNAL_ERROR_CODES.UNKNOWN_ERROR.message,
					code: EXTERNAL_ERROR_CODES.UNKNOWN_ERROR.code,
					status: 500,
				});
			}
		},
		options,
	}) satisfies CinaAuthPlugin;

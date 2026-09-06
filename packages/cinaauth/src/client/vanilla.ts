import type {
	BetterFetchError,
	BetterFetchResponse,
} from "@better-fetch/fetch";
import type { CinaAuthClientOptions } from "@cinaauth/core";
import type { BASE_ERROR_CODES } from "@cinaauth/core/error";
import { capitalizeFirstLetter } from "@cinaauth/core/utils/string";
import type { Atom } from "nanostores";
import type { PrettifyDeep, UnionToIntersection } from "../types/helper";
import { getClientConfig } from "./config";
import { createDynamicPathProxy } from "./proxy";
import type {
	InferActions,
	InferClientAPI,
	InferErrorCodes,
	IsSignal,
	SessionQueryParams,
} from "./types";

type InferResolvedHooks<O extends CinaAuthClientOptions> = O extends {
	plugins: Array<infer Plugin>;
}
	? UnionToIntersection<
			Plugin extends {
				getAtoms?: infer GetAtoms;
			}
				? GetAtoms extends (fetch: any) => infer Atoms
					? Atoms extends Record<string, any>
						? {
								[key in keyof Atoms as IsSignal<key> extends true
									? never
									: key extends string
										? `use${Capitalize<key>}`
										: never]: Atoms[key];
							}
						: {}
					: {}
				: {}
		>
	: {};

type ClientConfig = ReturnType<typeof getClientConfig>;
type ClientSession<Option extends CinaAuthClientOptions> =
	InferClientAPI<Option> extends {
		getSession: () => Promise<infer Res>;
	}
		? Res extends BetterFetchResponse<infer S>
			? S
			: Res
		: never;

/**
 * Client returned by `createAuthClient`.
 */
export type AuthClient<Option extends CinaAuthClientOptions> =
	UnionToIntersection<InferResolvedHooks<Option>> &
		InferClientAPI<Option> &
		InferActions<Option> & {
			hydrateSession(session: NonNullable<ClientSession<Option>> | null): void;
			useSession: Atom<{
				data: ClientSession<Option>;
				error: BetterFetchError | null;
				isPending: boolean;
				isRefetching: boolean;
				refetch: (
					queryParams?: { query?: SessionQueryParams } | undefined,
				) => Promise<void>;
			}>;
			$fetch: ClientConfig["$fetch"];
			$store: ClientConfig["$store"];
			$Infer: {
				Session: NonNullable<ClientSession<Option>>;
			};
			$ERROR_CODES: PrettifyDeep<
				InferErrorCodes<Option> & typeof BASE_ERROR_CODES
			>;
		};

export function createAuthClient<Option extends CinaAuthClientOptions>(
	options?: Option | undefined,
): AuthClient<Option> {
	const {
		pluginPathMethods,
		pluginsActions,
		pluginsAtoms,
		hydrateSession,
		$fetch,
		atomListeners,
		$store,
	} = getClientConfig(options);
	const resolvedHooks: Record<string, any> = {};
	for (const [key, value] of Object.entries(pluginsAtoms)) {
		resolvedHooks[`use${capitalizeFirstLetter(key)}`] = value;
	}
	const routes = {
		...pluginsActions,
		...resolvedHooks,
		hydrateSession,
		$fetch,
		$store,
	};
	const proxy = createDynamicPathProxy(
		routes,
		$fetch,
		pluginPathMethods,
		pluginsAtoms,
		atomListeners,
	);
	return proxy as AuthClient<Option>;
}

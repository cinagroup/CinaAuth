import type { AsyncLocalStorage } from "@cinaauth/core/async_hooks";
import { getAsyncLocalStorage } from "@cinaauth/core/async_hooks";
import type { EndpointContext, InputContext } from "better-call";
import type { AuthContext } from "../types";
import { __getCinaAuthGlobal, __getCurrentEndpointContext } from "./global";

export type AuthEndpointContext = Partial<
	InputContext<string, any> & EndpointContext<string, any>
> & {
	context: AuthContext;
};

type AuthEndpointContextStorage = AsyncLocalStorage<AuthEndpointContext>;

const getExistingEndpointContextStorage = () => {
	return __getCinaAuthGlobal().context.endpointContextAsyncStorage as
		| AuthEndpointContextStorage
		| undefined;
};

const getOrCreateEndpointContextStorage = async () => {
	const existing = getExistingEndpointContextStorage();
	if (existing) {
		return existing;
	}
	const AsyncLocalStorage = await getAsyncLocalStorage();
	const globalContext = __getCinaAuthGlobal().context;
	const storage = (globalContext.endpointContextAsyncStorage ??=
		new AsyncLocalStorage<AuthEndpointContext>()) as AuthEndpointContextStorage;
	return storage;
};

/**
 * @deprecated Use `getCurrentAuthEndpointContext`,
 * `tryGetCurrentAuthEndpointContext`, or `runWithEndpointContext` instead.
 */
export async function getCurrentAuthContextAsyncLocalStorage() {
	return getOrCreateEndpointContextStorage();
}

/**
 * Returns the current auth endpoint context, or `undefined` when called outside
 * of `runWithEndpointContext`.
 */
export function tryGetCurrentAuthEndpointContext() {
	return __getCurrentEndpointContext<AuthEndpointContext>();
}

/**
 * Returns the current auth endpoint context.
 *
 * @throws When called outside of `runWithEndpointContext`.
 */
export function getCurrentAuthEndpointContext() {
	const authEndpointContext = tryGetCurrentAuthEndpointContext();
	if (!authEndpointContext) {
		throw new Error(
			"No auth context found. Please make sure you are calling this function within a `runWithEndpointContext` callback.",
		);
	}
	return authEndpointContext;
}

/**
 * @deprecated Use `getCurrentAuthEndpointContext` instead.
 */
export async function getCurrentAuthContext() {
	return getCurrentAuthEndpointContext();
}

export async function runWithEndpointContext<T>(
	authEndpointContext: AuthEndpointContext,
	fn: () => T,
): Promise<T> {
	const storage = await getOrCreateEndpointContextStorage();
	return storage.run(authEndpointContext, fn);
}

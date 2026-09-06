import type { AsyncLocalStorage } from "@cinaauth/core/async_hooks";

interface CinaAuthGlobal {
	/**
	 * The version of CinaAuth.
	 */
	version: string;
	/**
	 * Used to track the number of CinaAuth instances in the same process.
	 *
	 * Debugging purposes only.
	 */
	epoch: number;
	/**
	 * Stores the AsyncLocalStorage instances for each context.
	 */
	context: Record<string, AsyncLocalStorage<unknown>>;
}

const symbol = Symbol.for("cinaauth:global");
let bind: CinaAuthGlobal | null = null;

const __context: Record<string, AsyncLocalStorage<unknown>> = {};
const __CinaAuthVersion: string = import.meta.env.CINAAUTH_VERSION as string;

/**
 * We store context instance in the globalThis.
 *
 * The reason we do this is that some bundlers, web framework, or package managers might
 * create multiple copies of CinaAuth in the same process intentionally or unintentionally.
 *
 * For example, yarn v1, Next.js, SSR, Vite...
 *
 * @internal
 */
export function __getCinaAuthGlobal(): CinaAuthGlobal {
	if (!(globalThis as any)[symbol]) {
		(globalThis as any)[symbol] = {
			version: __CinaAuthVersion,
			epoch: 1,
			context: __context,
		};
		bind = (globalThis as any)[symbol] as CinaAuthGlobal;
	}
	bind = (globalThis as any)[symbol] as CinaAuthGlobal;
	if (bind.version !== __CinaAuthVersion) {
		bind.version = __CinaAuthVersion;
		// Different versions of CinaAuth are loaded in the same process.
		bind.epoch++;
	}
	return (globalThis as any)[symbol] as CinaAuthGlobal;
}

export function __getCurrentEndpointContext<T>(): T | undefined {
	const storage = __getCinaAuthGlobal().context.endpointContextAsyncStorage as
		| AsyncLocalStorage<T>
		| undefined;
	return storage?.getStore();
}

export function getCinaAuthVersion(): string {
	return __getCinaAuthGlobal().version;
}

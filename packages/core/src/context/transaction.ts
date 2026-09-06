import type { AsyncLocalStorage } from "@cinaauth/core/async_hooks";
import { getAsyncLocalStorage } from "@cinaauth/core/async_hooks";
import type { DBAdapter, DBTransactionAdapter } from "../db/adapter";
import { schemaCheckFor } from "../db/schema-check";
import type { CinaAuthOptions } from "../types";
import { __getCinaAuthGlobal } from "./global";

type StoredAdapter = DBTransactionAdapter<CinaAuthOptions>;

type HookContext = {
	adapter: StoredAdapter;
	pendingHooks: Array<() => Promise<void>>;
	isTransactionActive: boolean;
};

const ensureAsyncStorage = async () => {
	const CinaAuthGlobal = __getCinaAuthGlobal();
	const existing = CinaAuthGlobal.context.adapterAsyncStorage;
	if (existing) {
		return existing as AsyncLocalStorage<HookContext>;
	}
	const AsyncLocalStorage = await getAsyncLocalStorage();
	CinaAuthGlobal.context.adapterAsyncStorage ??= new AsyncLocalStorage();
	return CinaAuthGlobal.context
		.adapterAsyncStorage as AsyncLocalStorage<HookContext>;
};

/**
 * This is for internal use only. Most users should use `getCurrentAdapter` instead.
 *
 * It is exposed for advanced use cases where you need direct access to the AsyncLocalStorage instance.
 */
export const getCurrentDBAdapterAsyncLocalStorage = async () => {
	return ensureAsyncStorage();
};

export const getCurrentAdapter = async <
	Options extends CinaAuthOptions = CinaAuthOptions,
>(
	fallback: DBTransactionAdapter<Options>,
): Promise<DBTransactionAdapter<Options>> => {
	return ensureAsyncStorage()
		.then((als) => {
			const store = als.getStore();
			return (
				(store?.adapter as DBTransactionAdapter<Options> | undefined) ||
				fallback
			);
		})
		.catch(() => {
			return fallback;
		});
};

export const runWithAdapter = async <
	R,
	Options extends CinaAuthOptions = CinaAuthOptions,
>(
	adapter: DBAdapter<Options>,
	fn: () => R,
): Promise<R> => {
	let called = false;
	return ensureAsyncStorage()
		.then(async (als) => {
			called = true;
			const pendingHooks: Array<() => Promise<void>> = [];
			let result: Awaited<R>;
			let error: unknown;
			let hasError = false;
			try {
				result = await als.run(
					{
						adapter: adapter as unknown as StoredAdapter,
						pendingHooks,
						isTransactionActive: false,
					},
					fn,
				);
			} catch (err) {
				error = err;
				hasError = true;
			}
			// Execute pending hooks after the function completes (even if it threw)
			for (const hook of pendingHooks) {
				await hook();
			}
			if (hasError) {
				throw error;
			}
			return result!;
		})
		.catch((err) => {
			if (!called) {
				return fn();
			}
			throw err;
		});
};

export const runWithTransaction = async <
	R,
	Options extends CinaAuthOptions = CinaAuthOptions,
>(
	adapter: DBAdapter<Options>,
	fn: () => R,
	options?: {
		onAfterCommitHookError?: (error: unknown) => void | Promise<void>;
	},
): Promise<R> => {
	let called = false;
	return ensureAsyncStorage()
		.then(async (als) => {
			called = true;
			const store = als.getStore();
			if (store?.isTransactionActive) {
				return fn();
			}
			// Settle the schema verdict before this transaction holds the
			// connection a single-connection store would need for the lookup.
			const pendingSchemaCheck = schemaCheckFor(adapter)?.();
			if (pendingSchemaCheck) await pendingSchemaCheck;
			const pendingHooks: Array<() => Promise<void>> = [];
			let result: Awaited<R>;
			let error: unknown;
			let hasError = false;
			try {
				result = await adapter.transaction(async (trx) => {
					return als.run(
						{
							adapter: trx as unknown as StoredAdapter,
							pendingHooks,
							isTransactionActive: true,
						},
						fn,
					);
				});
			} catch (e) {
				hasError = true;
				error = e;
			}
			if (hasError) {
				throw error;
			}
			for (const hook of pendingHooks) {
				try {
					await hook();
				} catch (error) {
					if (!options?.onAfterCommitHookError) throw error;
					try {
						await options.onAfterCommitHookError(error);
					} catch {
						// Reporting cannot roll back committed work or suppress later hooks.
					}
				}
			}
			return result!;
		})
		.catch((err) => {
			if (!called) {
				return fn();
			}
			throw err;
		});
};

/**
 * Queue a hook to be executed after the current transaction commits.
 * If not in a transaction, the hook will execute immediately.
 */
export const queueAfterTransactionHook = async (
	hook: () => Promise<void>,
	options?: {
		/** Handles a queued hook failure after the surrounding work has committed. */
		onError?: (error: unknown) => void | Promise<void>;
	},
): Promise<void> => {
	const executeHook = async () => {
		try {
			await hook();
		} catch (error) {
			if (!options?.onError) throw error;
			await options.onError(error);
		}
	};
	let storage: Awaited<ReturnType<typeof ensureAsyncStorage>>;
	try {
		storage = await ensureAsyncStorage();
	} catch {
		return executeHook();
	}

	const store = storage.getStore();
	if (!store?.isTransactionActive) return executeHook();
	store.pendingHooks.push(executeHook);
};

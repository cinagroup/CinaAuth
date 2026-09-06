import * as z from "zod";
import type { Prettify } from "../../types";
import type { CinaAuthOptions } from "../../types/init-options";
import type {
	InferDBFieldsFromOptions,
	InferDBFieldsFromPlugins,
} from "../type";
import { coreSchema } from "./shared";

export const accountSchema = coreSchema.extend({
	providerId: z.string(),
	accountId: z.string(),
	userId: z.coerce.string(),
	accessToken: z.string().nullish(),
	refreshToken: z.string().nullish(),
	idToken: z.string().nullish(),
	/**
	 * Access token expires at
	 */
	accessTokenExpiresAt: z.date().nullish(),
	/**
	 * Refresh token expires at
	 */
	refreshTokenExpiresAt: z.date().nullish(),
	/**
	 * The set of OAuth scopes the user has granted to this account, stored
	 * as a comma-separated list. Represents the accumulated grant rather
	 * than the latest token's `scope` claim, since per RFC 6749 Section 1.5 a
	 * token's scope may be narrower than the user's grant.
	 */
	scope: z.string().nullish(),
	/**
	 * Password is only stored in the credential provider
	 */
	password: z.string().nullish(),
});

export type BaseAccount = z.infer<typeof accountSchema>;

/** The stable provider-side key used to recognize an account. */
export type AccountKey = Readonly<
	Pick<BaseAccount, "providerId" | "accountId">
>;

/**
 * Account schema type used by cinaauth, note that it's possible that account could have additional fields
 */
export type Account<
	DBOptions extends CinaAuthOptions["account"] = CinaAuthOptions["account"],
	Plugins extends CinaAuthOptions["plugins"] = CinaAuthOptions["plugins"],
> = Prettify<
	BaseAccount &
		InferDBFieldsFromOptions<DBOptions> &
		InferDBFieldsFromPlugins<"account", Plugins>
>;

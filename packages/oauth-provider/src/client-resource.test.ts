import type { Auth, CinaAuthOptions } from "cinaauth/types";
import { expectTypeOf, it } from "vitest";
import { oauthProviderResourceClient } from "./client-resource";

it("accepts auth options that omit base URL configuration", () => {
	const options = { plugins: [] } satisfies CinaAuthOptions;
	type AuthWithoutBaseURL = Auth<typeof options>;
	const createResourceClient = oauthProviderResourceClient<AuthWithoutBaseURL>;

	expectTypeOf(createResourceClient)
		.parameter(0)
		.toEqualTypeOf<AuthWithoutBaseURL | undefined>();
});

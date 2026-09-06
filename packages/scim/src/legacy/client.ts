import type { CinaAuthClientPlugin } from "cinaauth/client";
import type { scim } from "./index";
import { PACKAGE_VERSION } from "./version";

export const scimClient = () => {
	return {
		id: "scim-legacy-client",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof scim>,
	} satisfies CinaAuthClientPlugin;
};

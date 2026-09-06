import type { CinaAuthClientPlugin } from "@cinaauth/core";
import { PACKAGE_VERSION } from "../../version";
import type { siwe } from ".";

export const siweClient = () => {
	return {
		id: "siwe-v2",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof siwe>,
		pathMethods: {
			"/siwe/challenge": "POST",
			"/siwe/nonce": "POST",
			"/siwe/get-nonce": "POST",
			"/siwe/link-wallet": "POST",
			"/siwe/set-primary-wallet": "POST",
			"/siwe/unlink-wallet": "POST",
		},
	} satisfies CinaAuthClientPlugin;
};

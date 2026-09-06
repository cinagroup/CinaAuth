import { oauthProviderResourceClient } from "@cinaauth/oauth-provider/resource-client";
import { createAuthClient } from "cinaauth/client";
import { auth } from "./auth";

export const serverClient = createAuthClient({
	plugins: [oauthProviderResourceClient(auth)],
});

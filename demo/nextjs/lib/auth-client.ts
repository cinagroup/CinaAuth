import { dashClient } from "@better-auth/infra/client";
import { electronProxyClient } from "@cinaauth/electron/proxy";
import { oauthProviderClient } from "@cinaauth/oauth-provider/client";
import { passkeyClient } from "@cinaauth/passkey/client";
import { ssoClient } from "@cinaauth/sso/client";
import { stripeClient } from "@cinaauth/stripe/client";
import {
	adminClient,
	customSessionClient,
	deviceAuthorizationClient,
	lastLoginMethodClient,
	multiSessionClient,
	oneTapClient,
	organizationClient,
	twoFactorClient,
} from "cinaauth/client/plugins";
import { createAuthClient } from "cinaauth/react";
import { toast } from "sonner";
import type { auth } from "./auth";

export const authClient = createAuthClient({
	plugins: [
		dashClient(),
		ssoClient(),
		organizationClient(),
		twoFactorClient({
			onTwoFactorRedirect() {
				window.location.href = "/two-factor";
			},
		}),
		passkeyClient(),
		adminClient(),
		multiSessionClient(),
		oneTapClient({
			clientId: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID!,
			promptOptions: {
				maxAttempts: 1,
			},
		}),
		oauthProviderClient(),
		stripeClient({
			subscription: true,
		}),
		customSessionClient<typeof auth>(),
		deviceAuthorizationClient(),
		lastLoginMethodClient(),
		electronProxyClient({
			protocol: {
				scheme: "com.cinaauth.demo",
			},
		}),
	],
	fetchOptions: {
		onError(e) {
			if (e.error.status === 429) {
				toast.error("Too many requests. Please try again later.");
			}
		},
	},
});

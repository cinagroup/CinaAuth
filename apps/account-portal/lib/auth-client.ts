import { apiKeyClient } from "@cinaauth/api-key/client";
import { electronProxyClient } from "@cinaauth/electron/proxy";
import { oauthProviderClient } from "@cinaauth/oauth-provider/client";
import { passkeyClient } from "@cinaauth/passkey/client";
import { scimClient } from "@cinaauth/scim/legacy/client";
import { ssoClient } from "@cinaauth/sso/client";
import { stripeClient } from "@cinaauth/stripe/client";
import {
	adminClient,
	anonymousClient,
	deviceAuthorizationClient,
	emailOTPClient,
	jwtClient,
	lastLoginMethodClient,
	multiSessionClient,
	oauthPopupClient,
	oneTimeTokenClient,
	organizationClient,
	phoneNumberClient,
	twoFactorClient,
} from "cinaauth/client/plugins";
import { siweClient } from "cinaauth/plugins/siwe-v2/client";
import { createAuthClient } from "cinaauth/react";
import { toast } from "sonner";
import { adminAccessControl, adminRoles } from "./admin-access";
import { resolveAuthClientBaseURL } from "./auth-api";
import { dashClient } from "./infra";
import {
	buildTwoFactorAuthPath,
	getPreferredTwoFactorPath,
} from "./two-factor-navigation";

export const authClient = createAuthClient({
	baseURL: resolveAuthClientBaseURL(
		typeof window === "undefined" ? undefined : window.location.origin,
	),
	plugins: [
		dashClient(),
		apiKeyClient(),
		jwtClient(),
		anonymousClient(),
		organizationClient({
			dynamicAccessControl: { enabled: true },
			teams: { enabled: true },
		}),
		twoFactorClient({
			onTwoFactorRedirect({ twoFactorMethods }) {
				window.location.href = buildTwoFactorAuthPath(
					getPreferredTwoFactorPath(twoFactorMethods),
					new URLSearchParams(window.location.search),
				);
			},
		}),
		passkeyClient(),
		adminClient({ ac: adminAccessControl, roles: adminRoles }),
		multiSessionClient(),
		oauthProviderClient(),
		oauthPopupClient(),
		ssoClient({
			domainVerification: {
				enabled: true,
			},
		}),
		scimClient(),
		stripeClient({
			subscription: true,
		}),
		deviceAuthorizationClient(),
		lastLoginMethodClient(),
		emailOTPClient(),
		phoneNumberClient(),
		oneTimeTokenClient(),
		siweClient(),
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

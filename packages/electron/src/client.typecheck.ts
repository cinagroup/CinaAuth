import { createAuthClient } from "cinaauth/client";
import { oneTapClient } from "cinaauth/client/plugins";
import { electronClient } from "./client";

const client = createAuthClient({
	plugins: [
		oneTapClient({ clientId: "test-client-id" }),
		electronClient({
			protocol: { scheme: "com.example.app" },
			signInURL: "https://example.com/sign-in",
			storage: {
				getItem: () => null,
				setItem: () => {},
			},
		}),
	],
});

void client.setupMain;
void client.oneTap;

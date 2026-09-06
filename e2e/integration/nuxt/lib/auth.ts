import { CinaAuth } from "cinaauth";
import { memoryAdapter } from "cinaauth/adapters/memory";

const database = {
	user: [],
	session: [],
	account: [],
	verification: [],
};

export const auth = CinaAuth({
	baseURL: {
		allowedHosts: ["127.0.0.1:*"],
		protocol: "http",
	},
	database: memoryAdapter(database),
	secret: "cinaauth-nuxt-test-secret",
	emailAndPassword: {
		enabled: true,
	},
});

import type { AgentAuthOptions } from "@better-auth/agent-auth";
import {
	AGENT_AUTH_ERROR_CODES,
	agentError,
	asyncResult,
	agentAuth as createUpstreamAgentAuth,
	streamResult,
	verifyAgentRequest,
} from "@better-auth/agent-auth";
import type { CinaAuthPlugin } from "@cinaauth/core";

/**
 * Adds Agent Auth Protocol discovery, registration, approval, and scoped
 * capability execution to a CinaAuth server.
 */
export const agentAuth = (options?: AgentAuthOptions) =>
	createUpstreamAgentAuth(options) as unknown as CinaAuthPlugin &
		ReturnType<typeof createUpstreamAgentAuth>;

declare module "@cinaauth/core" {
	interface CinaAuthPluginRegistry<AuthOptions, Options> {
		"agent-auth": {
			creator: typeof agentAuth;
		};
	}
}

export type * from "@better-auth/agent-auth";
export {
	AGENT_AUTH_ERROR_CODES,
	agentError,
	asyncResult,
	streamResult,
	verifyAgentRequest,
};

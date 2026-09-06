import type { AuthContext, CinaAuthOptions } from "@cinaauth/core";
import type { BASE_ERROR_CODES } from "@cinaauth/core/error";
import type { router } from "../api";
import type { InferAPI } from "./api";
import type { InferPluginTypes, Session, User } from "./models";
import type { InferPluginContext, InferPluginErrorCodes } from "./plugins";

export type Auth<Options extends CinaAuthOptions = CinaAuthOptions> = {
	handler: (request: Request) => Promise<Response>;
	/**
	 * Alias for {@link Auth.handler}.
	 */
	fetch: (request: Request) => Promise<Response>;
	api: InferAPI<ReturnType<typeof router<Options>>["endpoints"]>;
	options: Options;
	$ERROR_CODES: InferPluginErrorCodes<Options> & typeof BASE_ERROR_CODES;
	$context: Promise<AuthContext<Options> & InferPluginContext<Options>>;
	/**
	 * Share types
	 */
	$Infer: InferPluginTypes<Options> extends {
		Session: any;
	}
		? InferPluginTypes<Options>
		: {
				Session: {
					session: Session<Options["session"], Options["plugins"]>;
					user: User<Options["user"], Options["plugins"]>;
				};
			} & InferPluginTypes<Options>;
};

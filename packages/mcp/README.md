# @cinaauth/mcp

Model Context Protocol (MCP) plugin for [CinaAuth](https://www.better-auth.com).

`mcp()` turns your CinaAuth app into an OAuth 2.1 authorization server and
protected resource for MCP clients, built on
[`@cinaauth/oauth-provider`](https://www.better-auth.com/docs/plugins/oauth-provider).
It serves RFC 9728 protected resource metadata and binds issued tokens to the
configured resource. Compose it with `cimd()` for the MCP 2026-07-28 Client ID
Metadata Document flow, which pins CIMD draft-00 through an explicit metadata
profile. Dynamic Client Registration is disabled unless explicitly enabled.

`@cinaauth/mcp` owns authorization, not MCP protocol transport. Serve MCP
2026-07-28 requests with version 2 of the official
[`@modelcontextprotocol/server`](https://www.npmjs.com/package/@modelcontextprotocol/server)
package, configure `createMcpHandler` with `legacy: "reject"`, mount it behind
`requireMcpAuth`, and expose only the HTTP `POST` route. The modern protocol
handles each request independently and does not need a Redis-backed MCP
session store. Multi-instance `subscriptions/listen` deployments can supply a
shared SDK event bus without introducing protocol-level sessions.

```ts
import { CinaAuth } from "cinaauth";
import { jwt } from "cinaauth/plugins";
import { cimd } from "@cinaauth/cimd";
import { fetchClientMetadataResource } from "@cinaauth/cimd/node";
import { mcp } from "@cinaauth/mcp";

export const auth = CinaAuth({
  plugins: [
    jwt(),
    mcp({
      loginPage: "/login",
      consentPage: "/consent",
      resource: "https://api.example.com/mcp",
    }),
    cimd({
      fetchClientMetadataResource,
      metadataProfile: "mcp-2026-07-28",
    }),
  ],
});
```

See the [MCP plugin documentation](https://www.better-auth.com/docs/plugins/mcp).

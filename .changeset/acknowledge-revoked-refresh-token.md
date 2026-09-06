---
"@cinaauth/oauth-provider": patch
---

Acknowledge repeated refresh-token revocation and revocation that loses a race with token rotation with HTTP 200, while preserving token-family invalidation.

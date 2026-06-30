# AuthClaw Python SDK

This package currently contains the Phase 1 SDK contracts, Phase 2 synchronous
HTTP client foundation, Phase 3 SDK-side streaming support, and Phase 4
authentication/retry configuration hardening for AuthClaw.

## Scope

- Public request and response contracts
- SDK configuration contracts
- SDK version metadata
- Public enum identifiers
- SDK exception hierarchy
- Stable package exports
- Synchronous `AuthClawClient`
- Configuration loading
- HTTP transport abstraction
- Non-streaming chat completion, health, and version calls
- SDK-side SSE parsing
- Synchronous streaming chat completion iterator
- API key manager and authenticated header helpers
- Retry policy, retry decisions, and backoff calculations

## Non-scope

This phase intentionally does not implement async clients, reconnection, or
AuthClaw server runtime imports.

## Compatibility

- SDK version: `0.1.0`
- Supported AuthClaw API version: `v1`
- Minimum compatible AuthClaw release: `0.11.0`

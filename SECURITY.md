# Security policy

## Supported versions

Only the latest published minor version is supported once public releases begin.
Before the first public release, the `main` branch is the supported line.

| Version | Supported |
| --- | --- |
| 1.0.x | Yes, after publication |
| earlier development snapshots | No |

## Reporting a vulnerability

Do not open a public issue for an unpatched vulnerability. Use the private
security reporting channel provided by the repository host when available, or
open a minimal public issue that asks for a private contact without including
reproduction details.

Include:

- the affected version and commit
- whether ESM, CommonJS, middleware, Fetch adapter or CLI behavior is affected
- a minimal reproduction
- the security impact and whether credentials, wildcard origins, Private
  Network Access or cache behavior are involved

Do not include secrets, cookies, private infrastructure addresses or personal
data in a report.

## Scope

In scope:

- origin canonicalization or matching bypasses
- wildcard or subdomain boundary bypasses
- credential, null-origin or universal-wildcard invariant violations
- preflight method or header validation bypasses
- cache poisoning caused by incorrect `Vary` behavior
- Private Network Access emitted without explicit opt-in and authorization
- CORS headers emitted for rejected origins by an adapter

Out of scope:

- the fact that CORS does not authenticate non-browser clients
- DNS rebinding or network-layer attacks unrelated to CORS decisions
- applications intentionally configuring insecure options after explicit warnings
- reverse proxies or frameworks modifying headers outside this library
- denial of service requiring resources already available to the host process

## Hardening expectations

Fixes must preserve zero runtime dependencies, strict parsing, fail-closed
predicates, immutable policies and compatibility with Node 18 or newer unless a
security necessity requires otherwise.

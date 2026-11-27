# Security policy

## Supported versions

Only the latest published minor version is supported once public releases begin.
Before the first public release, the `main` branch is the supported line.

| Version | Supported |
| --- | --- |
| 1.0.x | Yes, after publication |
| earlier development snapshots | No |

## Reporting a vulnerability

Use the private GitHub Security Advisories form: [Report a vulnerability](https://github.com/draarivpatel-ui/corscage/security/advisories/new). Do not open a public issue for an exploitable finding.

Include:

- the affected version and commit
- whether ESM, CommonJS, middleware, Fetch adapter or CLI behavior is affected
- a minimal reproduction
- the security impact and whether credentials, wildcard origins, Private
  Network Access or cache behavior are involved

Do not include secrets, cookies, private infrastructure addresses or personal
data in a report.

We acknowledge reports within 48 hours. We aim to confirm or reject the report within 7 days, release a fix as soon as practical, and coordinate public disclosure with the reporter. Unless a shorter deadline is required by an actively exploited issue, please allow up to 90 days for a coordinated fix and disclosure.

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

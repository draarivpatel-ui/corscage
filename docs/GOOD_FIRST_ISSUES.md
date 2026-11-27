# Good first issues

These ten starter specifications are intentionally narrow. Each one should be
implemented with tests and documentation, and none may weaken the security
invariants in the README.

## 1. Public suffix fixtures

Add a data-driven test fixture of additional known public suffixes and verify
that wildcard bases using them are rejected. Keep the fixture small, auditable
and dependency-free.

## 2. CLI help snapshot

Add tests that compare `corscage --help` output against a checked-in snapshot
covering both commands, every flag and the exit-code table.

## 3. Connect compatibility example

Add a dependency-free example showing middleware composition with a plain
Connect-style `(req, res, next)` chain. Test the ordering behavior with mock
functions rather than adding Connect as a dependency.

## 4. Vary edge-case matrix

Expand the `mergeVary` tests for duplicate casing, arrays, whitespace, existing
star values and invalid tokens. Document exactly which invalid existing tokens
are dropped.

## 5. Additional IPv6 canonicalization vectors

Add pairwise valid and invalid IPv6 cases covering longest zero-run selection,
embedded IPv4 forms, uppercase input and boundary compression. Do not relax the
strict parser.

## 6. Preflight cap fuzz corpus

Generate deterministic comma-list fixtures around the configured header count
and byte caps. Assert that rejection happens before allowlist evaluation and
remains linear-time.

## 7. Fetch response preservation tests

Add tests for status text, custom status codes where permitted, header ordering
expectations and streaming bodies in the Fetch adapter. The adapter must copy
rather than mutate immutable response headers.

## 8. Linter remediation quality review

Review every lint finding message for a specific remediation. Add tests that
stable codes, severity, path and remediation fields are present for malformed
realistic configurations.

## 9. TypeScript consumer fixture

Add a small TypeScript compile fixture in CI that imports the types from ESM
and CommonJS shapes. Use the compiler only if it can be introduced without
becoming a runtime dependency and without weakening the zero-dependency claim.

## 10. Threat-model documentation examples

Add one concise example for each threat in the README threat model showing the
insecure pattern and the corscage-safe replacement. Keep examples free of real
domains, secrets and personally identifying information.

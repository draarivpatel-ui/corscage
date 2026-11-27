# corscage

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/corscage/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/corscage)

Zero-dependency strict CORS origin validation, preflight policy enforcement,
middleware and configuration auditing for Node.js.

`corscage` treats Cross-Origin Resource Sharing as a security boundary rather
than a string-concatenation feature. It never reflects arbitrary origins, never
combines the universal wildcard or the opaque `null` origin with credentials,
canonicalizes origins before matching, validates preflight method and header
tokens, handles Private Network Access explicitly, and preserves cache safety
with disciplined `Vary` merging.

- Zero runtime dependencies and zero devDependencies
- ESM, CommonJS and hand-authored TypeScript definitions
- 718 deterministic tests verified live with `npm test`
- Node 18 or newer
- Exact origins and strictly bounded single-label subdomain wildcards
- Optional multi-label subdomain matching only as an explicit opt-in
- Fail-closed synchronous origin predicates
- Express, Connect, Node `http`, Web Fetch API and CLI adapters
- Structured policy lint findings with stable machine-readable codes

## Publication status

This repository is prepared for npm publication as `corscage@1.0.0`, but the
package is not claimed to be published yet. Until the first npm release is
announced in the repository, use a local checkout or a reviewed git reference:

```sh
npm install /path/to/corscage
```

After publication the intended install command will be:

```sh
npm install corscage
```

## Threat model

CORS is a browser-enforced read and request permission system. It is not an
authentication system, not a firewall, and not protection against non-browser
clients. A server must still authenticate and authorize every request. This
library addresses the CORS-specific failure modes that frequently weaken that
server-side authorization:

- Reflection of arbitrary `Origin` values, including `origin: true` footguns
- Credentialed CORS combined with `*` or the opaque `null` origin
- malformed, whitespace-padded, control-character, userinfo, path-bearing or
  comma-joined origin values
- Unicode confusables and non-ASCII host smuggling
- port confusion, explicit default-port canonicalization mistakes, leading-zero
  ports and invalid numeric ranges
- subdomain matching mistakes such as matching the apex, `evil-example.com`,
  `example.com.evil.com`, empty labels or the wrong scheme and port
- broad wildcard bases such as `https://*.com`, `https://*.co.uk` and
  `https://*`
- cross-method or cross-header cache poisoning caused by missing or clobbered
  `Vary` tokens
- preflight method/header injection, excessive preflight header lists, and
  browser-forbidden headers
- accidental Private Network Access exposure
- exposing `Set-Cookie` or other forbidden response headers to JavaScript

Outside scope: DNS rebinding, application authentication, CSRF, reverse proxy
behavior, non-browser clients, and origins carried by nonstandard schemes.
Only `http` and `https` serialized origins are supported. Production policies
are HTTPS-only. Plain HTTP is limited to explicit localhost development use.

## Quick start

```js
import { createCorsPolicy } from 'corscage';

const policy = createCorsPolicy({
  allowedOrigins: ['https://app.example.com'],
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['content-type', 'authorization'],
  exposeHeaders: ['x-request-id'],
  maxAge: 600
});

const result = policy.evaluate({
  method: 'OPTIONS',
  headers: {
    origin: 'https://app.example.com',
    'access-control-request-method': 'POST',
    'access-control-request-headers': 'content-type'
  }
});

if (result.allowed) {
  // result.statusCode is 204 and result.headers is a lower-case header map.
}
```

`createCorsPolicy` validates and copies the caller's options, then freezes the
returned policy. It never mutates the input object.

## Strict origin parsing

```js
import { parseOrigin, normalizeOrigin } from 'corscage';

normalizeOrigin('HTTPS://EXAMPLE.COM:443');
// 'https://example.com'

normalizeOrigin('https://example.com:8443');
// 'https://example.com:8443'

normalizeOrigin('https://[2001:0db8:0:0:0:ff00:0042:8329]:443');
// 'https://[2001:db8::ff00:42:8329]'

parseOrigin('https://user@example.com').valid;
// false
```

The parser rejects, rather than repairs:

- leading or trailing whitespace
- control characters, spaces and raw non-ASCII characters
- comma-separated multiple origins
- userinfo such as `user:pass@host`
- paths, trailing slashes, queries, fragments and backslashes
- percent-encoded host text and IPv6 zone identifiers
- empty, oversized, hyphen-invalid or non-ASCII hostname labels
- obfuscated IPv4 forms such as `127.1`, octal-looking octets and out-of-range octets
- unbracketed or malformed IPv6 literals
- empty ports, non-digit ports, leading-zero ports, port 0 and ports above 65535
- schemes other than `http` and `https`

The string `null` is recognized as the opaque origin serialization, not as a
hostname. It is denied unless `allowNullOrigin` is explicitly true, and it can
never be allowed when `credentials` is true.

## Exact origins and subdomain wildcards

Exact origins bind scheme, hostname and effective port:

```js
const policy = createCorsPolicy({
  allowedOrigins: [
    'https://app.example.com',
    'https://admin.example.com:8443'
  ]
});
```

A wildcard replaces exactly one complete leftmost host label by default:

```js
const tenantPolicy = createCorsPolicy({
  allowedOrigins: ['https://*.example.com']
});
```

With that configuration:

```text
https://tenant.example.com        allowed
https://example.com               denied
https://deep.tenant.example.com   denied
https://evil-example.com          denied
https://example.com.evil.example  denied
http://tenant.example.com         denied
https://tenant.example.com:8443   denied
```

Set `multiLevelSubdomain: true` only when every nested subdomain of the base is
part of the same trust boundary:

```js
createCorsPolicy({
  allowedOrigins: ['https://*.example.com'],
  multiLevelSubdomain: true
});
```

Wildcard bases that are public suffixes or too broad are rejected at policy
creation time. The built-in conservative detector covers single-label suffixes
such as `com`, common aggregated country-code suffixes such as `co.uk`, and
common shared hosting suffixes such as `github.io`. No bundled suffix list can
be complete, so exact origins remain the recommended default.


The standalone `matchOrigin` helper applies the same production scheme floor as
policy evaluation. Non-local plaintext HTTP never matches, and localhost HTTP
matches only exact origins. Use `createCorsPolicy` when the explicit
`allowHttpLocalhost` development opt-in is needed.

## Credentials, `null` and the universal wildcard

The universal wildcard entry `*` is available only for intentionally public,
uncredentialed resources:

```js
const publicPolicy = createCorsPolicy({
  allowedOrigins: ['*'],
  credentials: false
});
```

Because `corscage` enforces a scheme floor, this entry still does not authorize
non-local plaintext HTTP origins. Localhost HTTP requires
`allowHttpLocalhost: true` or an exact localhost HTTP entry. If your design
requires universal plaintext HTTP, this library is intentionally not a fit.

These combinations are hard errors at configuration time and can never be
activated at runtime:

```js
createCorsPolicy({ allowedOrigins: ['*'], credentials: true });
// throws CorsCageError

createCorsPolicy({ allowNullOrigin: true, credentials: true });
// throws CorsCageError
```

Credentialed responses echo the exact canonical origin. They never use `*`.
Uncredentialed wildcard responses use `*` only after the origin has passed
strict syntax and scheme validation.

## Origin predicates

An optional synchronous predicate can authorize origins that are not in the
static list. It is evaluated only after the origin has been fully parsed and
the scheme floor has passed. It is never called for malformed origins or the
opaque `null` origin.

```js
const predicatePolicy = createCorsPolicy({
  originPredicate(origin) {
    return origin.scheme === 'https' &&
      origin.host.endsWith('.example.com') &&
      origin.host.split('.').length === 3;
  }
});
```

The predicate must return a boolean. Exceptions, promises, missing values and
every non-boolean result fail closed. Static exact origins are preferable.
A predicate is powerful enough to recreate unsafe reflection if written
incorrectly, so `lintCorsPolicy` marks predicate configurations for review when
they are broad or credentialed.

## Preflight validation

A true CORS preflight is exactly an `OPTIONS` request with both `Origin` and
`Access-Control-Request-Method`. A plain `OPTIONS` request is treated as an
actual request.

For preflights, the library enforces:

- one string `Origin` value, never repeated or comma-joined
- one RFC 9110 token in `Access-Control-Request-Method`
- exact method allowlist membership, with `TRACE` and `CONNECT` always rejected
- strict comma-separated header tokens in `Access-Control-Request-Headers`
- a default cap of 32 requested headers and 2048 bytes, configurable within
  hard ceilings
- case-insensitive configured header matching with canonical lower-case output
- rejection of CORS control, hop-by-hop and browser-forbidden headers unless
  an explicit dangerous override is configured
- `Access-Control-Max-Age` limited to an integer from 0 through 86400 seconds,
  with 600 seconds as the default

`Access-Control-Request-Private-Network: true` is denied by default. Set
`allowPrivateNetwork: true` only when the authorized origin is intentionally
allowed to reach private-network resources. The response header
`Access-Control-Allow-Private-Network: true` is emitted only for an authorized
origin and an otherwise valid preflight. Private Network Access can never be
combined with the universal wildcard origin, even when exact origins are also
present in the same policy.

## Node, Express and Connect middleware

```js
import http from 'node:http';
import { createNodeCorsMiddleware } from 'corscage';

const cors = createNodeCorsMiddleware({
  allowedOrigins: ['https://app.example.com'],
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['content-type', 'authorization']
});

const server = http.createServer((req, res) => {
  cors(req, res, () => {
    if (req.url === '/data') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });
});

server.listen(8080);
```

The middleware:

- emits `204` for an authorized preflight
- emits `403` for a rejected preflight by default
- calls downstream for a rejected preflight only when
  `rejectDisallowedPreflight: false` is explicitly configured
- never blocks an actual request solely because CORS is disallowed, because
  CORS is not non-browser access control
- omits CORS headers for rejected actual requests
- removes stale `Access-Control-*` response headers before applying the policy
- keeps policy CORS headers authoritative when downstream code uses response
  header mutation APIs
- merges `Vary` case-insensitively without dropping existing tokens and
  preserves required `Vary` tokens against downstream overwrites or removal

Express usage is the same:

```js
app.use(createNodeCorsMiddleware({
  allowedOrigins: ['https://app.example.com'],
  credentials: true
}));
```

## Web Fetch API adapter

`createFetchCorsHandler(options)` returns a wrapper. The wrapper accepts a
fetch handler and returns a standards-style `Request` to `Response` function:

```js
import { createFetchCorsHandler } from 'corscage';

const withCors = createFetchCorsHandler({
  allowedOrigins: ['https://app.example.com'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['content-type']
});

export default {
  fetch: withCors(async (request) => {
    return new Response(JSON.stringify({ ok: true }), {
      headers: { 'content-type': 'application/json' }
    });
  })
};
```

The adapter handles valid preflights without invoking the application handler,
returns `403` for rejected preflights by default, copies application responses
without mutating immutable `Headers`, strips stale CORS headers on rejection,
and merges `Vary` tokens.

## Command line

```sh
corscage lint --config cors.json
corscage lint --config cors.json --json

corscage check \
  --config cors.json \
  --origin https://app.example.com \
  --method POST \
  --request-headers content-type,authorization \
  --preflight \
  --json
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | `check` allowed the request, or `lint` found no findings |
| `1` | `check` denied the request, or `lint` found one or more findings |
| `2` | usage error, unreadable or unsafe config path, invalid JSON, or invalid runtime configuration |

The config reader accepts only regular files, refuses symlinks and special
files, caps input at 65536 bytes, requires an object root, and rejects
prototype-pollution keys anywhere in the JSON object graph.

## Configuration reference

| Option | Default | Meaning |
| --- | --- | --- |
| `allowedOrigins` | `[]` | Exact origins, scoped subdomain wildcards, or `*` for audited public uncredentialed resources |
| `credentials` | `false` | Emit `Access-Control-Allow-Credentials` and enforce all credential prohibitions |
| `methods` | `['GET', 'HEAD', 'POST']` | Exact methods available to valid preflights |
| `allowedHeaders` | `[]` | Case-insensitive request-header allowlist |
| `exposeHeaders` | `[]` | Non-simple response headers exposed to browser JavaScript |
| `maxAge` | `600` | Preflight cache lifetime in seconds, maximum 86400 |
| `allowNullOrigin` | `false` | Allow the opaque `null` origin for uncredentialed responses only |
| `allowHttpLocalhost` | `false` | Permit localhost plaintext HTTP for wildcard or predicate authorization |
| `multiLevelSubdomain` | `false` | Permit nested labels below a subdomain wildcard |
| `allowPrivateNetwork` | `false` | Permit valid authorized preflights to request Private Network Access |
| `rejectDisallowedPreflight` | `true` | Return 403 for rejected preflights instead of calling downstream |
| `originPredicate` | `null` | Optional synchronous additional authorization predicate |
| `maxRequestHeaders` | `32` | Maximum requested preflight header count, hard ceiling 128 |
| `maxRequestHeadersBytes` | `2048` | Maximum preflight header-list bytes, hard ceiling 16384 |
| `allowForbiddenHeaders` | `false` | Dangerous explicit override for browser-forbidden request headers |

Unknown option keys are rejected so a typo cannot silently disable a defense.
Booleans, regular expressions, objects and other dynamic reflection forms are
not accepted inside `allowedOrigins`.

## Lint finding codes

`lintCorsPolicy(config)` returns structured findings:

```js
import { lintCorsPolicy } from 'corscage';

for (const finding of lintCorsPolicy(config)) {
  console.log(finding.severity, finding.code, finding.message);
}
```

`assertSafeCorsConfig(config)` throws `CorsCageError` with code
`ERR_CORSCAGE_UNSAFE_CONFIG` when any critical or high severity finding exists.

| Code | Typical severity | Meaning |
| --- | --- | --- |
| `CORS_WILDCARD_WITH_CREDENTIALS` | critical | Universal wildcard combined with credentials |
| `CORS_NULL_ORIGIN_ALLOWED` | medium or critical | Opaque null origin enabled, critically with credentials |
| `CORS_REFLECT_ALL_ORIGINS` | high or critical | Universal reflection or unaudited dynamic broadening risk |
| `CORS_INSECURE_HTTP_WITH_CREDENTIALS` | critical | Plaintext non-local HTTP combined with credentials |
| `CORS_INSECURE_HTTP_ORIGIN` | high | Plaintext non-local HTTP origin configured |
| `CORS_OVERBROAD_SUBDOMAIN_WILDCARD` | high | Wildcard base is a public suffix or too broad |
| `CORS_EXCESSIVE_MAX_AGE` | high | Preflight cache lifetime exceeds 86400 seconds |
| `CORS_INVALID_MAX_AGE` | high | maxAge is negative, fractional, non-finite or not a number |
| `CORS_PRIVATE_NETWORK_WITH_WILDCARD` | high | Private Network Access combined with wildcard authorization |
| `CORS_UNSAFE_EXPOSE_HEADER` | critical | Attempt to expose Set-Cookie or Set-Cookie2 |
| `CORS_UNSAFE_ALLOWED_HEADER` | high or critical | Browser-controlled, hop-by-hop or CORS control header allowed |
| `CORS_INVALID_ORIGIN_ENTRY` | high | Origin entry is malformed or not a string |
| `CORS_INVALID_HEADER_ENTRY` | high | Header entry is not a legal HTTP token |
| `CORS_INVALID_METHOD_ENTRY` | high | Method entry is malformed, wildcard, TRACE or CONNECT |
| `CORS_CONFIG_INVALID` | critical or high | Configuration root or structure is invalid |
| `CORS_UNKNOWN_OPTION` | medium | Unknown option key, usually a typo |
| `CORS_DUPLICATE_ORIGIN` | low | Duplicate allowlist entry |
| `CORS_NO_ORIGINS_CONFIGURED` | low | Intentional or accidental deny-all origin list |
| `CORS_REDUNDANT_ORIGIN_ENTRY` | low | Scoped entries are redundant beside the universal wildcard |

## Runtime evaluation shape

```js
const result = policy.evaluate(requestLike);
```

The frozen result is:

```ts
{
  allowed: boolean,
  isPreflight: boolean,
  statusCode: 204 | 403 | null,
  headers: Record<string, string>,
  vary: string[],
  reason: string,
  code: string,
  origin: string | null,
  removeHeaders: string[]
}
```

`statusCode` is `null` for actual requests because the application remains
responsible for the response. `removeHeaders` lists the CORS response headers
that adapters strip before applying policy decisions.

## Cache and `Vary` behavior

Every evaluation includes `Vary: Origin`. Valid preflights also vary by
`Access-Control-Request-Method`, `Access-Control-Request-Headers` and
`Access-Control-Request-Private-Network`. The adapters merge these tokens with
existing response values case-insensitively. Existing `Vary` entries are not
clobbered or duplicated, and an existing `*` remains `*`.

Rejected origins receive no `Access-Control-Allow-Origin`. Node and Fetch
adapters also remove stale `Access-Control-*` response headers before applying
the decision. The Node adapter guards the public response header mutation APIs
used downstream, preventing an accidental overwrite, append, bulk write or
header removal from reintroducing CORS permission or clobbering required `Vary`
tokens.

## Security invariants

1. Malformed input is never repaired into an authority decision.
2. `null` is never authorized by a predicate and never valid with credentials.
3. `*` is never valid with credentials.
4. Subdomain wildcards never match the apex, a sibling suffix, the wrong scheme
   or the wrong effective port.
5. Dynamic boolean reflection forms are rejected by construction.
6. Predicate errors and non-boolean predicate results fail closed.
7. Private Network Access is opt-in, still requires an authorized origin and
   can never be combined with the universal wildcard origin.
8. Forbidden response headers cannot be exposed.
9. Configuration typos are errors, not ignored settings.
10. The runtime has no dependency tree and no network access.

## Limitations

- The public suffix heuristic is conservative but not a complete replacement
  for the full Public Suffix List. Prefer exact origins for high-value systems.
- Node 18 or newer is required.
- `http` and `https` are the only supported schemes. Browser extension,
  `chrome-extension`, `file`, and nonstandard serialized origins are rejected.
- The middleware does not block actual requests from disallowed origins because
  CORS itself is not non-browser access control. Use authentication and
  authorization for enforcement.
- The library does not make wildcard use safe for data that is not public.
- Node response guards are not a sandbox for intentionally hostile application
  code. They defend against accidental downstream header mistakes through the
  public response APIs.
- TypeScript definitions are hand-authored and tested structurally, but the
  implementation itself is dependency-free JavaScript.

## Development

```sh
npm test
npm run check:cjs
npm run smoke
npm pack --dry-run
```

The CommonJS build is generated from `src/index.mjs` by
`scripts/build-cjs.mjs`. The test suite runs ESM and CommonJS parity checks,
CLI tests, real Node `http` integration tests, Fetch adapter tests, parser
bypass cases, cache behavior tests and linear-time fuzz checks.

## Responsible disclosure

See [SECURITY.md](SECURITY.md) before reporting a vulnerability. Do not open a
public issue for an unpatched security report.

# Contributing

Thanks for helping improve corscage. Security behavior changes need especially
careful review because permissive convenience features are often CORS
vulnerabilities in disguise.

## Ground rules

- Keep zero runtime dependencies and zero devDependencies.
- Support Node 18 or newer.
- Keep ESM as the source of truth in `src/index.mjs`.
- Regenerate CommonJS with `npm run build:cjs` and verify `npm run check:cjs`.
- Add tests for every behavior change, including bypass attempts.
- Do not add dynamic origin reflection, regular-expression origin matching or
  implicit plaintext HTTP support.
- Do not weaken the credentials, null-origin or wildcard invariants.

## Verification

Before opening a pull request, run:

```sh
npm test
npm run smoke
node scripts/cli-smoke.mjs
npm pack --dry-run
```

Tests must pass on Linux and Windows. The CI matrix covers Node 18, 20, 22 and
24 on both platforms.

## Style

- Use plain JavaScript and web standards APIs.
- Keep parsing deterministic and linear-time.
- Prefer explicit rejection over browser-dependent normalization.
- Keep public errors machine-readable through stable codes.
- Do not mutate caller-owned options, request objects or response objects.

## Security reports

Do not use the public issue tracker for unpatched vulnerabilities. Follow
[SECURITY.md](SECURITY.md).

import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { APIs, cjs, esm } from './helpers.mjs';

const require = createRequire(import.meta.url);

const expectedExports = [
  'CODE',
  'LINT_CODES',
  'CorsCageError',
  'parseOrigin',
  'normalizeOrigin',
  'matchOrigin',
  'mergeVary',
  'createCorsPolicy',
  'createNodeCorsMiddleware',
  'createFetchCorsHandler',
  'lintCorsPolicy',
  'assertSafeCorsConfig'
];

for (const [label, api] of APIs) {
  test(label + ' exposes the complete public API', () => {
    for (const name of expectedExports) {
      assert.equal(typeof api[name], name.startsWith('ERR_') ? 'string' : typeof cjs[name], name);
      assert.notEqual(api[name], undefined, name);
    }
  });

  test(label + ' default export points at the public API object', () => {
    assert.equal(typeof api.default, 'object');
    for (const name of expectedExports) assert.equal(api.default[name], api[name], name);
  });
}

test('package self-reference resolves the ESM export', async () => {
  const api = await import('corscage');
  assert.equal(api.normalizeOrigin('HTTPS://EXAMPLE.COM:443'), 'https://example.com');
  assert.equal(typeof api.createCorsPolicy, 'function');
});

test('package self-reference resolves the CommonJS export', () => {
  const api = require('corscage');
  assert.equal(api.normalizeOrigin('HTTPS://EXAMPLE.COM:443'), 'https://example.com');
  assert.equal(api.default, api);
});

const behaviorCases = [
  ['https://example.com', 'https://example.com'],
  ['HTTPS://EXAMPLE.COM:443', 'https://example.com'],
  ['https://example.com:8443', 'https://example.com:8443'],
  ['https://[::1]', 'https://[::1]'],
  ['https://example.com/', null],
  ['https://user@example.com', null],
  ['https://example.com:0', null],
  ['https://éxample.com', null]
];

for (const [input, expected] of behaviorCases) {
  test('ESM and CJS normalizeOrigin parity for ' + encodeURIComponent(input), () => {
    assert.equal(esm.normalizeOrigin(input), expected);
    assert.equal(cjs.normalizeOrigin(input), expected);
  });
}

const matchCases = [
  ['https://app.example.com', 'https://*.example.com', undefined, true],
  ['https://deep.app.example.com', 'https://*.example.com', undefined, false],
  ['https://deep.app.example.com', 'https://*.example.com', { multiLevelSubdomain: true }, true],
  ['https://example.com', 'https://*.example.com', undefined, false],
  ['https://app.com', 'https://*.com', undefined, false],
  ['https://example.com:443', 'https://example.com', undefined, true]
];

for (const [candidate, pattern, options, expected] of matchCases) {
  test('ESM and CJS matchOrigin parity for ' + candidate, () => {
    assert.equal(esm.matchOrigin(candidate, pattern, options), expected);
    assert.equal(cjs.matchOrigin(candidate, pattern, options), expected);
  });
}

for (const [label, api] of APIs) {
  test(label + ' policy evaluation behavior is identical', () => {
    const policy = api.createCorsPolicy({
      allowedOrigins: ['https://app.example.com'],
      credentials: true,
      methods: ['POST'],
      allowedHeaders: ['content-type']
    });
    const result = policy.evaluate({
      method: 'OPTIONS',
      headers: {
        origin: 'https://app.example.com',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type'
      }
    });
    assert.equal(result.allowed, true);
    assert.equal(result.statusCode, 204);
    assert.equal(result.headers['access-control-allow-origin'], 'https://app.example.com');
  });

  test(label + ' config validation errors carry CorsCageError shape', () => {
    assert.throws(() => api.createCorsPolicy({ allowedOrigins: ['*'], credentials: true }), (error) => {
      assert.equal(error.name, 'CorsCageError');
      assert.equal(error.code, api.CODE.INVALID_OPTIONS);
      assert.equal(typeof error.reason, 'string');
      return true;
    });
  });

  test(label + ' linter output is structured and frozen', () => {
    const findings = api.lintCorsPolicy({ allowedOrigins: ['*'], credentials: true });
    assert.ok(findings.length > 0);
    assert.equal(Object.isFrozen(findings), true);
    assert.equal(findings[0].code.length > 0, true);
  });
}

test('generated CJS and source ESM export exactly the same keys', () => {
  assert.deepEqual(Object.keys(esm).sort(), Object.keys(cjs).sort());
});

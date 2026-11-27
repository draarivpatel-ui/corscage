import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CODE,
  createCorsPolicy,
  matchOrigin
} from '../src/index.mjs';
import { actual, preflight, throwsInvalidOptions } from './helpers.mjs';

const exactPositiveCases = [
  ['https://example.com', 'https://example.com'],
  ['HTTPS://EXAMPLE.COM', 'https://example.com'],
  ['https://example.com:443', 'https://example.com'],
  ['https://example.com', 'https://example.com:443'],
  ['https://example.com:8443', 'https://example.com:8443'],
  ['http://localhost:3000', 'http://localhost:3000'],
  ['https://127.0.0.1', 'https://127.0.0.1'],
  ['https://[::1]', 'https://[0:0:0:0:0:0:0:1]'],
  ['https://[::ffff:c000:201]', 'https://[::ffff:192.0.2.1]'],
  ['https://xn--nxasmq6b.example.com', 'https://xn--nxasmq6b.example.com']
];

for (const [candidate, pattern] of exactPositiveCases) {
  test('matchOrigin exact positive ' + candidate + ' against ' + pattern, () => {
    assert.equal(matchOrigin(candidate, pattern), true);
  });
}

const exactNegativeCases = [
  ['https://example.com', 'http://example.com'],
  ['http://example.com', 'https://example.com'],
  ['https://example.com:444', 'https://example.com'],
  ['https://example.com', 'https://example.com:444'],
  ['https://example.com:8443', 'https://example.com:8444'],
  ['https://app.example.com', 'https://example.com'],
  ['https://example.com', 'https://app.example.com'],
  ['https://evil-example.com', 'https://example.com'],
  ['https://example.com.evil.test', 'https://example.com'],
  ['https://127.0.0.2', 'https://127.0.0.1'],
  ['https://[::2]', 'https://[::1]'],
  ['null', 'https://example.com'],
  ['https://example.com', 'null'],
  ['https://example.com/', 'https://example.com'],
  ['https://user@example.com', 'https://example.com'],
  ['https://example.com,https://evil.test', 'https://example.com']
];

for (const [candidate, pattern] of exactNegativeCases) {
  test('matchOrigin exact negative ' + JSON.stringify(candidate) + ' against ' + JSON.stringify(pattern), () => {
    assert.equal(matchOrigin(candidate, pattern), false);
  });
}

const wildcardPositiveCases = [
  ['https://app.example.com', 'https://*.example.com'],
  ['https://a.example.com', 'https://*.example.com'],
  ['https://tenant.example.com:8443', 'https://*.example.com:8443'],
  ['HTTPS://APP.EXAMPLE.COM', 'https://*.example.com'],
  ['https://app.example.com:443', 'https://*.example.com'],
  ['https://deep.app.example.com', 'https://*.example.com', { multiLevelSubdomain: true }],
  ['https://a.b.c.example.com', 'https://*.example.com', { multiLevelSubdomain: true }]
];

for (const [candidate, pattern, options] of wildcardPositiveCases) {
  test('matchOrigin wildcard positive ' + candidate, () => {
    assert.equal(matchOrigin(candidate, pattern, options), true);
  });
}

const wildcardNegativeCases = [
  ['https://example.com', 'https://*.example.com'],
  ['https://evil-example.com', 'https://*.example.com'],
  ['https://example.com.evil.test', 'https://*.example.com'],
  ['https://foo..example.com', 'https://*.example.com'],
  ['https://-bad.example.com', 'https://*.example.com'],
  ['https://bad-.example.com', 'https://*.example.com'],
  ['http://app.example.com', 'https://*.example.com'],
  ['https://app.example.com:8443', 'https://*.example.com'],
  ['https://app.example.com', 'https://*.example.com:8443'],
  ['https://deep.app.example.com', 'https://*.example.com'],
  ['https://app.other-example.com', 'https://*.example.com'],
  ['https://app.example.com.', 'https://*.example.com'],
  ['null', 'https://*.example.com'],
  ['https://app.example.com', 'https://*'],
  ['https://app.example.com', 'https://foo.*.example.com'],
  ['https://app.example.com', 'https://*example.com'],
  ['https://app.example.com', 'https://** .example.com'],
  ['https://app.example.com', /https:\/\/.*\.example\.com/],
  ['https://app.example.com', true],
  ['https://app.example.com', { pattern: 'https://*.example.com' }]
];

for (const [candidate, pattern] of wildcardNegativeCases) {
  test('matchOrigin wildcard negative ' + JSON.stringify(candidate) + ' against ' + String(pattern), () => {
    assert.equal(matchOrigin(candidate, pattern), false);
  });
}

const broadPatterns = [
  'https://*.com',
  'https://*.org',
  'https://*.io',
  'https://*.co.uk',
  'https://*.com.au',
  'https://*.co.jp',
  'https://*.github.io',
  'https://*.vercel.app',
  'https://*.netlify.app',
  'https://*.localhost',
  'https://*.com:8443'
];

for (const pattern of broadPatterns) {
  test('matchOrigin refuses overbroad wildcard pattern ' + pattern, () => {
    assert.equal(matchOrigin('https://host.' + pattern.slice('https://*.'.length), pattern), false);
  });

  test('createCorsPolicy rejects overbroad wildcard pattern ' + pattern, () => {
    throwsInvalidOptions(() => createCorsPolicy({ allowedOrigins: [pattern] }));
  });
}

test('matchOrigin rejects unknown options keys', () => {
  throwsInvalidOptions(() => matchOrigin('https://app.example.com', 'https://*.example.com', { unsafe: true }));
});

test('matchOrigin rejects non-object options', () => {
  throwsInvalidOptions(() => matchOrigin('https://app.example.com', 'https://*.example.com', true));
});


test('matchOrigin applies the plaintext HTTP scheme floor', () => {
  assert.equal(matchOrigin('http://example.com', 'http://example.com'), false);
  assert.equal(matchOrigin('http://anything.example', '*'), false);
  assert.equal(matchOrigin('http://app.example.com', 'http://*.example.com'), false);
  assert.equal(matchOrigin('http://app.example.localhost', 'http://*.example.localhost'), false);
  assert.equal(matchOrigin('http://localhost:3000', 'http://localhost:3000'), true);
  assert.equal(matchOrigin('https://example.com', 'https://example.com'), true);
});

const invalidOriginEntries = [
  true,
  false,
  null,
  undefined,
  1,
  {},
  [],
  /example/,
  '*.*',
  'https://*',
  'https://foo.*.example.com',
  'https://example.com/*',
  'https://example.com',
];

test('createCorsPolicy rejects boolean dynamic reflection', () => {
  const error = throwsInvalidOptions(() => createCorsPolicy({ allowedOrigins: true }));
  assert.equal(error.code, CODE.INVALID_OPTIONS);
});

for (const entry of invalidOriginEntries.slice(0, 12)) {
  test('createCorsPolicy rejects invalid origin entry type or shape ' + String(entry), () => {
    throwsInvalidOptions(() => createCorsPolicy({ allowedOrigins: [entry] }));
  });
}

test('createCorsPolicy accepts a valid exact origin control case', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['https://example.com'] });
  assert.equal(policy.isOriginAllowed('https://example.com'), true);
});

test('createCorsPolicy rejects wildcard star with credentials', () => {
  throwsInvalidOptions(() => createCorsPolicy({ allowedOrigins: ['*'], credentials: true }));
});

test('universal wildcard public policy allows strict https origins', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['*'] });
  const result = policy.evaluate(actual('https://anything.example'));
  assert.equal(result.allowed, true);
  assert.equal(result.headers['access-control-allow-origin'], '*');
});

test('universal wildcard public policy still denies non-local plaintext http', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['*'] });
  const result = policy.evaluate(actual('http://anything.example'));
  assert.equal(result.allowed, false);
  assert.equal(result.headers['access-control-allow-origin'], undefined);
});

test('universal wildcard does not implicitly allow null', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['*'] });
  const result = policy.evaluate(actual('null'));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_NULL_ORIGIN');
});

test('explicit null origin is allowed only without credentials when configured', () => {
  const policy = createCorsPolicy({ allowNullOrigin: true });
  const result = policy.evaluate(actual('null'));
  assert.equal(result.allowed, true);
  assert.equal(result.headers['access-control-allow-origin'], 'null');
  assert.equal(result.headers['access-control-allow-credentials'], undefined);
});

test('null origin with credentials is a hard configuration error', () => {
  throwsInvalidOptions(() => createCorsPolicy({ allowNullOrigin: true, credentials: true }));
});

test('exact localhost http entry is allowed as explicit development configuration', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['http://localhost:3000'] });
  assert.equal(policy.isOriginAllowed('http://localhost:3000'), true);
  assert.equal(policy.evaluate(actual('http://localhost:3000')).allowed, true);
});

test('non-local plaintext http entries are rejected', () => {
  throwsInvalidOptions(() => createCorsPolicy({ allowedOrigins: ['http://example.com'] }));
});

test('localhost http subdomain wildcard requires allowHttpLocalhost', () => {
  throwsInvalidOptions(() => createCorsPolicy({ allowedOrigins: ['http://*.example.localhost'] }));
});

test('localhost http subdomain wildcard works with explicit opt-in', () => {
  const policy = createCorsPolicy({
    allowedOrigins: ['http://*.example.localhost'],
    allowHttpLocalhost: true
  });
  assert.equal(policy.isOriginAllowed('http://app.example.localhost'), true);
});

test('predicate can authorize an unlisted valid https origin', () => {
  const policy = createCorsPolicy({
    originPredicate(origin) {
      return origin.host === 'dynamic.example.com';
    }
  });
  assert.equal(policy.isOriginAllowed('https://dynamic.example.com'), true);
  assert.equal(policy.evaluate(actual('https://dynamic.example.com')).allowed, true);
});

test('predicate receives a frozen canonical origin context', () => {
  let seen;
  const policy = createCorsPolicy({
    originPredicate(origin) {
      seen = origin;
      return true;
    }
  });
  assert.equal(policy.isOriginAllowed('HTTPS://EXAMPLE.COM:443'), true);
  assert.equal(seen.origin, 'https://example.com');
  assert.equal(seen.port, 443);
  assert.equal(Object.isFrozen(seen), true);
});

const predicateBadResults = [
  ['throwing predicate', () => { throw new Error('boom'); }],
  ['promise predicate', () => Promise.resolve(true)],
  ['string predicate', () => 'true'],
  ['number predicate', () => 1],
  ['undefined predicate', () => undefined],
  ['null predicate', () => null],
  ['object predicate', () => ({})]
];

for (const [label, predicate] of predicateBadResults) {
  test('predicate fail-closed behavior for ' + label, () => {
    const policy = createCorsPolicy({ originPredicate: predicate });
    const result = policy.evaluate(actual('https://dynamic.example.com'));
    assert.equal(result.allowed, false);
    assert.notEqual(result.code, 'CORS_ORIGIN_ALLOWED');
  });
}

test('async predicate functions are rejected at configuration time', () => {
  throwsInvalidOptions(() => createCorsPolicy({ originPredicate: async () => true }));
});

test('non-function predicate is rejected at configuration time', () => {
  throwsInvalidOptions(() => createCorsPolicy({ originPredicate: true }));
});

test('predicate is never called for malformed origins', () => {
  let calls = 0;
  const policy = createCorsPolicy({
    originPredicate() {
      calls += 1;
      return true;
    }
  });
  assert.equal(policy.evaluate(actual('https://example.com/')).allowed, false);
  assert.equal(calls, 0);
});

test('predicate is never called for null origins', () => {
  let calls = 0;
  const policy = createCorsPolicy({
    allowNullOrigin: false,
    originPredicate() {
      calls += 1;
      return true;
    }
  });
  assert.equal(policy.evaluate(actual('null')).allowed, false);
  assert.equal(calls, 0);
});

test('predicate cannot authorize non-local plaintext http', () => {
  const policy = createCorsPolicy({ originPredicate: () => true });
  assert.equal(policy.evaluate(actual('http://dynamic.example.com')).allowed, false);
});

test('predicate cannot authorize localhost plaintext http without opt-in', () => {
  const policy = createCorsPolicy({ originPredicate: () => true });
  assert.equal(policy.evaluate(actual('http://localhost:3000')).allowed, false);
});

test('predicate can authorize localhost plaintext http with opt-in', () => {
  const policy = createCorsPolicy({
    allowHttpLocalhost: true,
    originPredicate: () => true
  });
  assert.equal(policy.evaluate(actual('http://localhost:3000')).allowed, true);
});

test('static exact origin is checked before the predicate', () => {
  let calls = 0;
  const policy = createCorsPolicy({
    allowedOrigins: ['https://app.example.com'],
    originPredicate() {
      calls += 1;
      return false;
    }
  });
  assert.equal(policy.isOriginAllowed('https://app.example.com'), true);
  assert.equal(calls, 0);
});

test('policy immutability prevents caller mutation of configuration', () => {
  const origins = ['https://app.example.com'];
  const options = {
    allowedOrigins: origins,
    methods: ['GET'],
    allowedHeaders: ['x-test']
  };
  const policy = createCorsPolicy(options);
  origins.push('https://evil.example');
  options.methods.push('POST');
  options.allowedHeaders.push('x-evil');
  assert.equal(policy.isOriginAllowed('https://evil.example'), false);
  assert.equal(policy.config.methods.includes('POST'), false);
  assert.equal(policy.config.allowedHeaders.includes('x-evil'), false);
  assert.equal(Object.isFrozen(policy), true);
  assert.equal(Object.isFrozen(policy.config), true);
});

test('policy rejects unknown option keys as typo protection', () => {
  throwsInvalidOptions(() => createCorsPolicy({ allowedOrigins: ['https://example.com'], origin: true }));
});

test('policy rejects reserved prototype pollution keys', () => {
  const options = JSON.parse('{"__proto__":{"polluted":true},"allowedOrigins":["https://example.com"]}');
  throwsInvalidOptions(() => createCorsPolicy(options));
});

test('destructured policy match method does not depend on receiver binding', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['https://app.example.com'] });
  const match = policy.match;
  assert.equal(match('https://app.example.com'), true);
  assert.equal(match('https://evil.example.com'), false);
});

test('exact localhost http entry wins over universal wildcard regardless of entry order', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['*', 'http://localhost:3000'] });
  assert.equal(policy.isOriginAllowed('http://localhost:3000'), true);
});

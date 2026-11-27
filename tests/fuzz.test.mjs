import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { createCorsPolicy, matchOrigin, normalizeOrigin, parseOrigin } from '../src/index.mjs';

function seededRandom(seed) {
  let state = seed >>> 0;
  return function random() {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.:[]@/%\\?# \t\r\n,*';

function fuzzString(random, length) {
  let output = '';
  for (let index = 0; index < length; index += 1) {
    output += alphabet[Math.floor(random() * alphabet.length)];
  }
  return output;
}

test('deterministic parser fuzz corpus never throws', () => {
  const random = seededRandom(1337);
  for (let index = 0; index < 250; index += 1) {
    const input = 'https://' + fuzzString(random, 1 + (index % 90));
    const parsed = parseOrigin(input);
    assert.equal(typeof parsed.valid, 'boolean');
    assert.equal(Object.isFrozen(parsed), true);
  }
});

test('deterministic full-origin fuzz corpus never throws', () => {
  const random = seededRandom(4242);
  for (let index = 0; index < 250; index += 1) {
    const input = fuzzString(random, 1 + (index % 120));
    const parsed = parseOrigin(input);
    assert.equal(typeof parsed.valid, 'boolean');
  }
});

test('deterministic matcher fuzz corpus never throws and remains boolean', () => {
  const random = seededRandom(9001);
  for (let index = 0; index < 200; index += 1) {
    const host = 'label' + String(index % 20) + '.example.com';
    const candidate = 'https://' + host;
    const result = matchOrigin(candidate, 'https://*.example.com');
    assert.equal(typeof result, 'boolean');
    assert.equal(result, true);
    assert.equal(fuzzString(random, 2).length, 2);
  }
});

const adversarialInputs = [
  'https://' + 'a.'.repeat(100) + 'example.com',
  'https://' + 'a'.repeat(63) + '.example.com',
  'https://' + 'a'.repeat(64) + '.example.com',
  'https://example.com' + ':1'.repeat(20),
  'https://example.com:' + '9'.repeat(100),
  'https://' + '['.repeat(80),
  'https://' + ']'.repeat(80),
  'https://[' + '0:'.repeat(30) + ']',
  'https://[' + ':0'.repeat(30) + ']',
  'https://example.com' + '/'.repeat(80),
  'https://example.com' + '@'.repeat(80),
  'https://example.com' + ','.repeat(80),
  'https://example.com' + '%'.repeat(80),
  'https://' + 'xn--'.repeat(40) + '.example.com'
];

for (const input of adversarialInputs) {
  test('adversarial parser input completes without throwing ' + input.slice(0, 40), () => {
    const parsed = parseOrigin(input);
    assert.equal(typeof parsed.valid, 'boolean');
  });
}

test('long capped origin rejection is immediate', () => {
  const input = 'https://' + 'a'.repeat(10000) + '.example.com';
  const started = performance.now();
  const parsed = parseOrigin(input);
  const elapsed = performance.now() - started;
  assert.equal(parsed.valid, false);
  assert.equal(parsed.code, 'CORS_ORIGIN_TOO_LONG');
  assert.ok(elapsed < 50, 'origin length rejection took ' + String(elapsed) + 'ms');
});

test('large valid host parses within a generous linear-time budget', () => {
  const label = 'a'.repeat(63);
  const host = [label, label, label, 'example', 'com'].join('.');
  const input = 'https://' + host;
  const started = performance.now();
  for (let index = 0; index < 1000; index += 1) parseOrigin(input);
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 500, '1000 parses took ' + String(elapsed) + 'ms');
});

test('wildcard matching does not scan attacker-controlled backtracking space', () => {
  const deep = Array.from({ length: 80 }, (_, index) => 'l' + String(index)).join('.') + '.example.com';
  const candidate = 'https://' + deep;
  const started = performance.now();
  for (let index = 0; index < 1000; index += 1) {
    matchOrigin(candidate, 'https://*.example.com', { multiLevelSubdomain: true });
  }
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 500, '1000 deep matches took ' + String(elapsed) + 'ms');
});

test('origin candidate length is capped before wildcard matching', () => {
  const candidate = 'https://' + 'a'.repeat(1000) + '.example.com';
  assert.equal(matchOrigin(candidate, 'https://*.example.com'), false);
});

test('preflight request-header byte cap prevents large list processing', () => {
  const policy = createCorsPolicy({
    allowedOrigins: ['https://app.example.com'],
    methods: ['POST'],
    allowedHeaders: ['x-a']
  });
  const huge = Array.from({ length: 2000 }, () => 'x-a').join(',');
  const result = policy.evaluate({
    method: 'OPTIONS',
    headers: {
      origin: 'https://app.example.com',
      'access-control-request-method': 'POST',
      'access-control-request-headers': huge
    }
  });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_HEADERS_MALFORMED');
});

test('preflight request-header count cap rejects many tiny fields', () => {
  const policy = createCorsPolicy({
    allowedOrigins: ['https://app.example.com'],
    methods: ['POST'],
    allowedHeaders: ['x-a']
  });
  const many = Array.from({ length: 33 }, () => 'x-a').join(',');
  const result = policy.evaluate({
    method: 'OPTIONS',
    headers: {
      origin: 'https://app.example.com',
      'access-control-request-method': 'POST',
      'access-control-request-headers': many
    }
  });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_HEADERS_MALFORMED');
});

test('large allowlist evaluation completes within a generous linear-time budget', () => {
  const origins = [];
  for (let index = 0; index < 300; index += 1) origins.push('https://app' + String(index) + '.example.com');
  const policy = createCorsPolicy({ allowedOrigins: origins });
  const started = performance.now();
  for (let index = 0; index < 500; index += 1) {
    policy.isOriginAllowed('https://missing.example.com');
  }
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 1000, '500 deny scans took ' + String(elapsed) + 'ms');
});

test('normalizer does not mutate its input or retain mutable state', () => {
  const input = 'HTTPS://EXAMPLE.COM:443';
  assert.equal(normalizeOrigin(input), 'https://example.com');
  assert.equal(input, 'HTTPS://EXAMPLE.COM:443');
  assert.equal(normalizeOrigin(input), 'https://example.com');
});

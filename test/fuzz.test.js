import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { createCorsPolicy, matchOrigin, parseOrigin } from '../src/index.mjs';

const hostileUnit = fc.constantFrom(
  '', 'https://', 'http://', 'app', 'api', 'example', 'com', 'evil', '.', '..', ':', '443', '444',
  '/', '\\', '@', '%', ',', '*', '[', ']', ' ', '\t', '\r', '\n', 'xn--'
);
const hostileText = fc.string({ unit: hostileUnit, minLength: 1, maxLength: 18 });

test('fast-check malformed origins never bypass an exact allowlist', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['https://app.example.com'] });
  fc.assert(fc.property(hostileText, (input) => {
    const parsed = parseOrigin(input);
    const allowed = policy.isOriginAllowed(input);
    assert.equal(typeof parsed.valid, 'boolean');
    assert.equal(typeof allowed, 'boolean');
    if (!parsed.valid) {
      assert.equal(allowed, false, 'malformed origin was allowed');
      return;
    }
    if (allowed) {
      assert.equal(parsed.normalized, 'https://app.example.com');
    }
  }), { seed: 0xc02511, numRuns: 260 });
});

test('fast-check malformed candidates never match a subdomain wildcard', () => {
  fc.assert(fc.property(hostileText, (hostPart) => {
    const candidate = 'https://' + hostPart + '.example.com';
    const parsed = parseOrigin(candidate);
    const matched = matchOrigin(candidate, 'https://*.example.com');
    assert.equal(typeof matched, 'boolean');
    if (!parsed.valid) {
      assert.equal(matched, false, 'malformed wildcard candidate matched');
      return;
    }
    if (matched) {
      assert.equal(parsed.scheme, 'https');
      assert.equal(parsed.hostType, 'domain');
      assert.ok(parsed.host.endsWith('.example.com'));
      const prefix = parsed.host.slice(0, -'.example.com'.length);
      assert.equal(prefix.split('.').length, 1);
      assert.notEqual(prefix.length, 0);
    }
  }), { seed: 0xc02522, numRuns: 240 });
});

test('fast-check arbitrary candidate and wildcard pattern pairs return boolean without throwing', () => {
  fc.assert(fc.property(hostileText, hostileText, (candidate, pattern) => {
    const parsed = parseOrigin(candidate);
    const matched = matchOrigin(candidate, pattern);
    assert.equal(typeof matched, 'boolean');
    if (!parsed.valid) assert.equal(matched, false);
  }), { seed: 0xc02533, numRuns: 180 });
});

test('fast-check wildcard lookalike hosts stay outside the allowlist', () => {
  const affix = fc.string({ unit: 'grapheme-ascii', minLength: 0, maxLength: 12 });
  const policy = createCorsPolicy({ allowedOrigins: ['https://*.example.com'] });
  fc.assert(fc.property(affix, (text) => {
    for (const host of [
      'evil-example.com',
      'example.com.evil',
      'app.example.com.evil',
      'example.com' + text
    ]) {
      const input = 'https://' + host;
      const parsed = parseOrigin(input);
      if (!parsed.valid) {
        assert.equal(policy.isOriginAllowed(input), false);
      } else if (!parsed.host.endsWith('.example.com')) {
        assert.equal(policy.isOriginAllowed(input), false);
      }
    }
  }), { seed: 0xc02544, numRuns: 120 });
});

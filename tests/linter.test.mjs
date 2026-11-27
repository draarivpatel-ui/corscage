import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CODE,
  LINT_CODES,
  assertSafeCorsConfig,
  lintCorsPolicy
} from '../src/index.mjs';
import { codesOf, findingsFor } from './helpers.mjs';

test('lintCorsPolicy returns no findings for a strict credentialed config', () => {
  const findings = lintCorsPolicy({
    allowedOrigins: ['https://app.example.com'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['content-type', 'authorization'],
    exposeHeaders: ['x-request-id'],
    maxAge: 600
  });
  assert.deepEqual(findings, []);
});

test('lint findings are frozen and have stable structured fields', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['*'], credentials: true });
  assert.ok(findings.length > 0);
  assert.equal(Object.isFrozen(findings), true);
  for (const finding of findings) {
    assert.equal(Object.isFrozen(finding), true);
    assert.match(finding.code, /^CORS_[A-Z0-9_]+$/);
    assert.match(finding.severity, /^(critical|high|medium|low)$/);
    assert.ok(finding.message.length > 10);
    assert.ok(finding.remediation.length > 10);
    assert.ok(finding.path === null || typeof finding.path === 'string');
  }
});

test('lint rejects a non-object configuration root', () => {
  for (const input of [null, true, 1, 'x', []]) {
    const findings = lintCorsPolicy(input);
    assert.ok(codesOf(findings).includes(LINT_CODES.CONFIG_INVALID));
    assert.equal(findings[0].severity, 'critical');
  }
});

test('lint flags unknown option keys', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['https://app.example.com'], credential: true });
  const finding = findingsFor(findings, LINT_CODES.UNKNOWN_OPTION)[0];
  assert.equal(finding.severity, 'medium');
  assert.equal(finding.path, 'credential');
});

test('lint flags universal wildcard with credentials as critical', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['*'], credentials: true });
  const finding = findingsFor(findings, LINT_CODES.WILDCARD_WITH_CREDENTIALS)[0];
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.path, 'allowedOrigins[0]');
});

test('lint flags universal wildcard without credentials as high reflection risk', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['*'] });
  const finding = findingsFor(findings, LINT_CODES.REFLECT_ALL_ORIGINS)[0];
  assert.equal(finding.severity, 'high');
});

test('lint flags boolean reflection input', () => {
  const findings = lintCorsPolicy({ allowedOrigins: true });
  assert.ok(codesOf(findings).includes(LINT_CODES.REFLECT_ALL_ORIGINS));
  assert.ok(codesOf(findings).includes(LINT_CODES.INVALID_ORIGIN_ENTRY));
});

test('lint flags null origin with credentials as critical', () => {
  const findings = lintCorsPolicy({ allowNullOrigin: true, credentials: true, allowedOrigins: ['https://app.example.com'] });
  const finding = findingsFor(findings, LINT_CODES.NULL_ORIGIN_ALLOWED)[0];
  assert.equal(finding.severity, 'critical');
});

test('lint flags explicit null origin without credentials as medium', () => {
  const findings = lintCorsPolicy({ allowNullOrigin: true, allowedOrigins: ['https://app.example.com'] });
  const finding = findingsFor(findings, LINT_CODES.NULL_ORIGIN_ALLOWED)[0];
  assert.equal(finding.severity, 'medium');
});

test('lint flags non-local http with credentials as critical', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['http://api.example.com'], credentials: true });
  const finding = findingsFor(findings, LINT_CODES.INSECURE_HTTP_WITH_CREDENTIALS)[0];
  assert.equal(finding.severity, 'critical');
});

test('lint flags non-local http without credentials as high', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['http://api.example.com'] });
  const finding = findingsFor(findings, LINT_CODES.INSECURE_HTTP_ORIGIN)[0];
  assert.equal(finding.severity, 'high');
});

test('lint does not flag exact localhost http as non-local insecure http', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['http://localhost:3000'] });
  assert.equal(findingsFor(findings, LINT_CODES.INSECURE_HTTP_ORIGIN).length, 0);
});

const broadLinterPatterns = ['https://*.com', 'https://*.co.uk', 'https://*.github.io', 'https://*.localhost'];
for (const pattern of broadLinterPatterns) {
  test('lint flags overbroad wildcard ' + pattern, () => {
    const findings = lintCorsPolicy({ allowedOrigins: [pattern] });
    const finding = findingsFor(findings, LINT_CODES.OVERBROAD_SUBDOMAIN_WILDCARD)[0];
    assert.equal(finding.severity, 'high');
  });
}

test('lint flags excessive maxAge', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['https://app.example.com'], maxAge: 86401 });
  const finding = findingsFor(findings, LINT_CODES.EXCESSIVE_MAX_AGE)[0];
  assert.equal(finding.severity, 'high');
});

const invalidMaxAgeInputs = [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '600'];
for (const maxAge of invalidMaxAgeInputs) {
  test('lint flags invalid maxAge ' + String(maxAge), () => {
    const findings = lintCorsPolicy({ maxAge, allowedOrigins: ['https://app.example.com'] });
    assert.ok(codesOf(findings).includes(LINT_CODES.INVALID_MAX_AGE));
  });
}

test('lint flags private network access with subdomain wildcard', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['https://*.example.com'], allowPrivateNetwork: true });
  const finding = findingsFor(findings, LINT_CODES.PRIVATE_NETWORK_WITH_WILDCARD)[0];
  assert.equal(finding.severity, 'high');
});

test('lint flags private network access with universal wildcard', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['*'], allowPrivateNetwork: true });
  assert.ok(codesOf(findings).includes(LINT_CODES.PRIVATE_NETWORK_WITH_WILDCARD));
});

test('lint flags exposed Set-Cookie as critical', () => {
  const findings = lintCorsPolicy({ exposeHeaders: ['set-cookie'], allowedOrigins: ['https://app.example.com'] });
  const finding = findingsFor(findings, LINT_CODES.UNSAFE_EXPOSE_HEADER)[0];
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.path, 'exposeHeaders[0]');
});

test('lint flags hard forbidden allowed headers as critical', () => {
  const findings = lintCorsPolicy({ allowedHeaders: ['origin'], allowedOrigins: ['https://app.example.com'] });
  const finding = findingsFor(findings, LINT_CODES.UNSAFE_ALLOWED_HEADER)[0];
  assert.equal(finding.severity, 'critical');
});

const browserControlledHeaders = ['cookie', 'sec-fetch-site', 'proxy-authorization'];
for (const header of browserControlledHeaders) {
  test('lint flags browser-controlled allowed header ' + header, () => {
    const findings = lintCorsPolicy({ allowedHeaders: [header], allowedOrigins: ['https://app.example.com'] });
    const finding = findingsFor(findings, LINT_CODES.UNSAFE_ALLOWED_HEADER)[0];
    assert.equal(finding.severity, 'high');
  });
}

test('lint flags malformed origin entries', () => {
  for (const entry of [true, 1, {}, /x/, 'https://example.com/', 'https://user@example.com']) {
    const findings = lintCorsPolicy({ allowedOrigins: [entry] });
    assert.ok(codesOf(findings).includes(LINT_CODES.INVALID_ORIGIN_ENTRY), String(entry));
  }
});

test('lint flags malformed expose header entries', () => {
  const findings = lintCorsPolicy({ exposeHeaders: ['bad header'], allowedOrigins: ['https://app.example.com'] });
  assert.ok(codesOf(findings).includes(LINT_CODES.INVALID_HEADER_ENTRY));
});

test('lint flags malformed allowed header entries', () => {
  const findings = lintCorsPolicy({ allowedHeaders: ['bad header'], allowedOrigins: ['https://app.example.com'] });
  assert.ok(codesOf(findings).includes(LINT_CODES.INVALID_HEADER_ENTRY));
});

const invalidMethodEntries = ['TRACE', 'CONNECT', '*', 'bad method', ''];
for (const method of invalidMethodEntries) {
  test('lint flags invalid method entry ' + JSON.stringify(method), () => {
    const findings = lintCorsPolicy({ methods: [method], allowedOrigins: ['https://app.example.com'] });
    assert.ok(codesOf(findings).includes(LINT_CODES.INVALID_METHOD_ENTRY));
  });
}

test('lint flags duplicate origins as low severity', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['https://app.example.com', 'HTTPS://APP.EXAMPLE.COM:443'] });
  const finding = findingsFor(findings, LINT_CODES.DUPLICATE_ORIGIN)[0];
  assert.equal(finding.severity, 'low');
});

test('lint flags empty origin configuration as low severity deny-all', () => {
  const findings = lintCorsPolicy({});
  const finding = findingsFor(findings, LINT_CODES.NO_ORIGINS_CONFIGURED)[0];
  assert.equal(finding.severity, 'low');
});

test('lint flags redundant scoped entries beside universal wildcard', () => {
  const findings = lintCorsPolicy({ allowedOrigins: ['*', 'https://app.example.com'] });
  const finding = findingsFor(findings, LINT_CODES.REDUNDANT_ORIGIN_ENTRY)[0];
  assert.equal(finding.severity, 'low');
});

test('lint flags predicate-only configuration for reflection review', () => {
  const findings = lintCorsPolicy({ originPredicate: () => false });
  const finding = findingsFor(findings, LINT_CODES.REFLECT_ALL_ORIGINS)[0];
  assert.equal(finding.severity, 'medium');
});

test('lint flags credentialed predicate broadening as high', () => {
  const findings = lintCorsPolicy({
    allowedOrigins: ['https://app.example.com'],
    credentials: true,
    originPredicate: () => false
  });
  const finding = findingsFor(findings, LINT_CODES.REFLECT_ALL_ORIGINS)[0];
  assert.equal(finding.severity, 'high');
});

test('lint accepts an uncredentialed predicate beside static origins without reflection finding', () => {
  const findings = lintCorsPolicy({
    allowedOrigins: ['https://app.example.com'],
    originPredicate: () => false
  });
  assert.equal(findingsFor(findings, LINT_CODES.REFLECT_ALL_ORIGINS).length, 0);
});

test('assertSafeCorsConfig passes a low-severity-only deny-all config', () => {
  assert.equal(assertSafeCorsConfig({}), true);
});

test('assertSafeCorsConfig passes a strict exact-origin config', () => {
  assert.equal(assertSafeCorsConfig({ allowedOrigins: ['https://app.example.com'], credentials: true }), true);
});

test('assertSafeCorsConfig throws with findings for high severity configurations', () => {
  let error;
  assert.throws(() => assertSafeCorsConfig({ allowedOrigins: ['*'] }), (caught) => {
    error = caught;
    return true;
  });
  assert.equal(error.name, 'CorsCageError');
  assert.equal(error.code, CODE.UNSAFE_CONFIG);
  assert.ok(Array.isArray(error.findings));
  assert.ok(error.findings.length > 0);
  assert.equal(error.findings[0].severity, 'high');
});

test('assertSafeCorsConfig throws for critical credential misconfiguration', () => {
  assert.throws(() => assertSafeCorsConfig({ allowedOrigins: ['*'], credentials: true }), /ERR_CORSCAGE_UNSAFE_CONFIG/);
});

test('lint detects reserved prototype pollution keys', () => {
  const config = JSON.parse('{"__proto__":{"x":1},"allowedOrigins":["https://app.example.com"]}');
  const findings = lintCorsPolicy(config);
  assert.ok(codesOf(findings).includes(LINT_CODES.CONFIG_INVALID));
});

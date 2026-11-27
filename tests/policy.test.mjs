import test from 'node:test';
import assert from 'node:assert/strict';
import { createCorsPolicy, mergeVary } from '../src/index.mjs';
import { actual, preflight, request, throwsInvalidOptions } from './helpers.mjs';

function basePolicy(extra = {}) {
  return createCorsPolicy(Object.assign({
    allowedOrigins: ['https://app.example.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT'],
    allowedHeaders: ['content-type', 'authorization', 'x-request-id'],
    exposeHeaders: ['x-response-id'],
    maxAge: 600
  }, extra));
}

test('default policy is deny-all and uses secure defaults', () => {
  const policy = createCorsPolicy();
  assert.equal(policy.evaluate(actual('https://app.example.com')).allowed, false);
  assert.deepEqual(policy.config.allowedOrigins, []);
  assert.deepEqual(policy.config.methods, ['GET', 'HEAD', 'POST']);
  assert.equal(policy.config.credentials, false);
  assert.equal(policy.config.maxAge, 600);
  assert.equal(policy.config.allowNullOrigin, false);
  assert.equal(policy.config.allowPrivateNetwork, false);
  assert.equal(policy.config.rejectDisallowedPreflight, true);
});

test('allowed actual credentialed request receives exact origin and credentials headers', () => {
  const result = basePolicy().evaluate(actual('https://app.example.com'));
  assert.equal(result.allowed, true);
  assert.equal(result.isPreflight, false);
  assert.equal(result.statusCode, null);
  assert.equal(result.headers['access-control-allow-origin'], 'https://app.example.com');
  assert.equal(result.headers['access-control-allow-credentials'], 'true');
  assert.equal(result.headers['access-control-expose-headers'], 'x-response-id');
  assert.deepEqual(result.vary, ['Origin']);
});

test('allowed actual uncredentialed request omits credentials header', () => {
  const policy = createCorsPolicy({ allowedOrigins: ['https://app.example.com'] });
  const result = policy.evaluate(actual('https://app.example.com'));
  assert.equal(result.allowed, true);
  assert.equal(result.headers['access-control-allow-credentials'], undefined);
});

test('rejected actual request has no CORS headers and no terminal status', () => {
  const result = basePolicy().evaluate(actual('https://evil.example.com'));
  assert.equal(result.allowed, false);
  assert.equal(result.statusCode, null);
  assert.deepEqual(result.headers, {});
  assert.deepEqual(result.vary, ['Origin']);
  assert.equal(result.code, 'CORS_ORIGIN_NOT_ALLOWED');
});

test('request without Origin is not a CORS request', () => {
  const result = basePolicy().evaluate(request('GET', {}));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_NO_ORIGIN');
  assert.equal(result.isPreflight, false);
  assert.equal(result.statusCode, null);
});

test('plain OPTIONS with Origin but no request-method is an actual request', () => {
  const result = basePolicy().evaluate(request('OPTIONS', { origin: 'https://app.example.com' }));
  assert.equal(result.allowed, true);
  assert.equal(result.isPreflight, false);
  assert.equal(result.statusCode, null);
});

test('OPTIONS with request-method but no Origin is not a preflight', () => {
  const result = basePolicy().evaluate(request('OPTIONS', { 'access-control-request-method': 'POST' }));
  assert.equal(result.allowed, false);
  assert.equal(result.isPreflight, false);
  assert.equal(result.code, 'CORS_NO_ORIGIN');
});

test('lowercase options method is not treated as the CORS OPTIONS method', () => {
  const result = basePolicy().evaluate(request('options', {
    origin: 'https://app.example.com',
    'access-control-request-method': 'POST'
  }));
  assert.equal(result.isPreflight, false);
});

const malformedOriginInputs = [
  'https://app.example.com/',
  'https://app.example.com,https://evil.example',
  ' https://app.example.com',
  'https://app.example.com ',
  'https://user@app.example.com',
  'https://app.example.com?x=1',
  'https://app.example.com#x',
  'https://éxample.com',
  'https://app.example.com:0',
  'https://app.example.com:65536'
];

for (const origin of malformedOriginInputs) {
  test('malformed preflight origin is rejected without CORS headers ' + encodeURIComponent(origin), () => {
    const result = basePolicy().evaluate(preflight(origin, 'POST'));
    assert.equal(result.allowed, false);
    assert.equal(result.isPreflight, true);
    assert.equal(result.statusCode, 403);
    assert.equal(result.headers['access-control-allow-origin'], undefined);
  });
}

test('repeated Origin header array is rejected', () => {
  const result = basePolicy().evaluate(request('GET', { origin: ['https://app.example.com', 'https://evil.example'] }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_ORIGIN_MALFORMED');
});

test('duplicate mixed-case Origin fields are rejected', () => {
  const result = basePolicy().evaluate(request('GET', { Origin: 'https://app.example.com', origin: 'https://app.example.com' }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_ORIGIN_MALFORMED');
});

test('mixed-case custom header object keys are read case-insensitively', () => {
  const result = basePolicy().evaluate(request('GET', { OrIgIn: 'https://app.example.com' }));
  assert.equal(result.allowed, true);
});

test('valid preflight receives least-privilege response headers', () => {
  const result = basePolicy().evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-headers': 'Content-Type, X-Request-Id'
  }));
  assert.equal(result.allowed, true);
  assert.equal(result.isPreflight, true);
  assert.equal(result.statusCode, 204);
  assert.equal(result.headers['access-control-allow-origin'], 'https://app.example.com');
  assert.equal(result.headers['access-control-allow-credentials'], 'true');
  assert.equal(result.headers['access-control-allow-methods'], 'POST');
  assert.equal(result.headers['access-control-allow-headers'], 'content-type, x-request-id');
  assert.equal(result.headers['access-control-max-age'], '600');
  assert.equal(result.headers['access-control-expose-headers'], undefined);
  assert.deepEqual(result.vary, [
    'Origin',
    'Access-Control-Request-Method',
    'Access-Control-Request-Headers',
    'Access-Control-Request-Private-Network'
  ]);
});

test('valid preflight without request headers omits allow-headers', () => {
  const result = basePolicy().evaluate(preflight('https://app.example.com', 'GET'));
  assert.equal(result.allowed, true);
  assert.equal(result.headers['access-control-allow-headers'], undefined);
});

test('exposed headers appear only on actual responses', () => {
  const policy = basePolicy();
  assert.equal(policy.evaluate(actual('https://app.example.com')).headers['access-control-expose-headers'], 'x-response-id');
  assert.equal(policy.evaluate(preflight('https://app.example.com', 'GET')).headers['access-control-expose-headers'], undefined);
});

const malformedMethods = [
  '',
  'POST,GET',
  'POST GET',
  'POST\nGET',
  'POST\rGET',
  'P@ST',
  'TRACE',
  'trace',
  'CONNECT',
  'connect',
  '*',
  'P'.repeat(65)
];

for (const method of malformedMethods) {
  test('preflight rejects malformed or dangerous requested method ' + JSON.stringify(method), () => {
    const result = basePolicy().evaluate(preflight('https://app.example.com', method));
    assert.equal(result.allowed, false);
    assert.equal(result.statusCode, 403);
    assert.equal(result.headers['access-control-allow-methods'], undefined);
  });
}

test('preflight rejects repeated request-method header array', () => {
  const result = basePolicy().evaluate(request('OPTIONS', {
    origin: 'https://app.example.com',
    'access-control-request-method': ['POST', 'GET']
  }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_PREFLIGHT_METHOD_MALFORMED');
});

test('preflight rejects valid token method outside policy allowlist', () => {
  const result = basePolicy().evaluate(preflight('https://app.example.com', 'DELETE'));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_METHOD_NOT_ALLOWED');
});

test('method matching is exact and case-sensitive', () => {
  const result = basePolicy().evaluate(preflight('https://app.example.com', 'post'));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_METHOD_NOT_ALLOWED');
});

const validMethodConfigCases = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'QUERY', 'X-CUSTOM'];
for (const method of validMethodConfigCases) {
  test('custom safe method can be configured and used ' + method, () => {
    const policy = createCorsPolicy({ allowedOrigins: ['https://app.example.com'], methods: [method] });
    const result = policy.evaluate(preflight('https://app.example.com', method));
    assert.equal(result.allowed, true);
    assert.equal(result.headers['access-control-allow-methods'], method);
  });
}

const invalidConfigMethods = ['TRACE', 'CONNECT', '*', 'BAD METHOD', 'BAD\nMETHOD', '', 'P'.repeat(65)];
for (const method of invalidConfigMethods) {
  test('method config rejects unsafe method ' + JSON.stringify(method), () => {
    throwsInvalidOptions(() => createCorsPolicy({ methods: [method] }));
  });
}

test('empty methods array is rejected', () => {
  throwsInvalidOptions(() => createCorsPolicy({ methods: [] }));
});

const malformedHeaderLists = [
  '',
  ',',
  'content-type,',
  ',content-type',
  'content-type,,x-test',
  'content type',
  'content-type x-test',
  'content-type\nx-test',
  'content-type\rx-test',
  'content-type\tx-test',
  '\u00a0content-type',
  'content-type\u00a0',
  'content-type,\u2003x-request-id',
  'content-type@',
  '*',
  'content-type,*'
];

for (const list of malformedHeaderLists) {
  test('preflight rejects malformed request header list ' + JSON.stringify(list), () => {
    const result = basePolicy().evaluate(preflight('https://app.example.com', 'POST', {
      'access-control-request-headers': list
    }));
    assert.equal(result.allowed, false);
    assert.equal(result.statusCode, 403);
    assert.equal(result.headers['access-control-allow-headers'], undefined);
  });
}

test('preflight rejects repeated request-headers field array', () => {
  const result = basePolicy().evaluate(request('OPTIONS', {
    origin: 'https://app.example.com',
    'access-control-request-method': 'POST',
    'access-control-request-headers': ['content-type', 'x-request-id']
  }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_HEADERS_MALFORMED');
});

test('preflight header matching is case-insensitive and deduplicates output', () => {
  const result = basePolicy().evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-headers': 'CONTENT-TYPE,content-type,Authorization'
  }));
  assert.equal(result.allowed, true);
  assert.equal(result.headers['access-control-allow-headers'], 'content-type, authorization');
});

test('preflight rejects a requested header outside the allowlist', () => {
  const result = basePolicy().evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-headers': 'content-type,x-evil'
  }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_HEADERS_NOT_ALLOWED');
});

test('preflight enforces configured header count cap', () => {
  const policy = basePolicy({ maxRequestHeaders: 2 });
  const result = policy.evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-headers': 'content-type,authorization,x-request-id'
  }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_HEADERS_MALFORMED');
});

test('preflight header count boundary allows exact cap', () => {
  const policy = basePolicy({ maxRequestHeaders: 2 });
  const result = policy.evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-headers': 'content-type,authorization'
  }));
  assert.equal(result.allowed, true);
});

test('preflight enforces configured header byte cap', () => {
  const policy = basePolicy({ maxRequestHeadersBytes: 128 });
  const result = policy.evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-headers': 'content-type,' + 'x'.repeat(120)
  }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_HEADERS_MALFORMED');
});


test('preflight rejects oversized non-ASCII header lists without copying them into output', () => {
  const policy = basePolicy({ maxRequestHeadersBytes: 128 });
  const result = policy.evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-headers': '💥'.repeat(500)
  }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_HEADERS_MALFORMED');
  assert.match(result.reason, /control or non-ASCII/);
});

test('duplicate requested headers do not bypass count cap', () => {
  const policy = basePolicy({ maxRequestHeaders: 2 });
  const result = policy.evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-headers': 'content-type,content-type,authorization'
  }));
  assert.equal(result.allowed, false);
});

const hardForbiddenHeaders = [
  'origin', 'host', 'connection', 'content-length', 'transfer-encoding',
  'upgrade', 'keep-alive', 'te', 'trailer', 'via',
  'access-control-request-method', 'access-control-request-headers',
  'access-control-request-private-network'
];
for (const header of hardForbiddenHeaders) {
  test('hard forbidden request header cannot be configured even with override ' + header, () => {
    throwsInvalidOptions(() => createCorsPolicy({ allowedHeaders: [header], allowForbiddenHeaders: true }));
  });
}

const browserForbiddenHeaders = ['cookie', 'cookie2', 'accept-charset', 'accept-encoding', 'date', 'dnt', 'expect', 'referer', 'sec-fetch-site', 'proxy-authorization'];
for (const header of browserForbiddenHeaders) {
  test('browser forbidden request header requires explicit override ' + header, () => {
    throwsInvalidOptions(() => createCorsPolicy({ allowedHeaders: [header] }));
  });
}

for (const header of browserForbiddenHeaders) {
  test('browser forbidden request header is configurable only with explicit override ' + header, () => {
    const policy = createCorsPolicy({
      allowedOrigins: ['https://app.example.com'],
      methods: ['POST'],
      allowedHeaders: [header],
      allowForbiddenHeaders: true
    });
    const result = policy.evaluate(preflight('https://app.example.com', 'POST', {
      'access-control-request-headers': header
    }));
    assert.equal(result.allowed, true);
  });
}

const invalidExposeHeaders = ['set-cookie', 'Set-Cookie', 'set-cookie2', '*', 'bad header', 'x\ny', '', 'x'.repeat(129)];
for (const header of invalidExposeHeaders) {
  test('exposeHeaders rejects dangerous or malformed header ' + JSON.stringify(header), () => {
    throwsInvalidOptions(() => createCorsPolicy({ exposeHeaders: [header] }));
  });
}

test('safe exposeHeaders are lower-cased and deduplicated', () => {
  const policy = createCorsPolicy({ exposeHeaders: ['X-One', 'x-one', 'X-Two'] });
  assert.deepEqual(policy.config.exposeHeaders, ['x-one', 'x-two']);
});

const invalidMaxAges = [-1, -100, 0.5, 1.2, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 86401, 1000000, '600'];
for (const maxAge of invalidMaxAges) {
  test('maxAge rejects invalid value ' + String(maxAge), () => {
    throwsInvalidOptions(() => createCorsPolicy({ maxAge }));
  });
}

for (const maxAge of [0, 1, 599, 600, 3600, 86400]) {
  test('maxAge accepts valid boundary value ' + String(maxAge), () => {
    const policy = createCorsPolicy({ allowedOrigins: ['https://app.example.com'], maxAge });
    const result = policy.evaluate(preflight('https://app.example.com', 'GET'));
    assert.equal(result.headers['access-control-max-age'], String(maxAge));
  });
}

test('private network request is denied by default', () => {
  const result = basePolicy().evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-private-network': 'true'
  }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'CORS_PRIVATE_NETWORK_DENIED');
  assert.equal(result.headers['access-control-allow-private-network'], undefined);
});

test('private network request is emitted only with explicit opt-in', () => {
  const policy = basePolicy({ allowPrivateNetwork: true });
  const result = policy.evaluate(preflight('https://app.example.com', 'POST', {
    'access-control-request-private-network': 'true'
  }));
  assert.equal(result.allowed, true);
  assert.equal(result.headers['access-control-allow-private-network'], 'true');
});


test('private network access cannot be configured with the universal wildcard', () => {
  const error = throwsInvalidOptions(() => createCorsPolicy({
    allowedOrigins: ['*'],
    methods: ['GET'],
    allowPrivateNetwork: true
  }));
  assert.match(error.reason, /Private Network Access/);
});

test('private network access rejects mixed exact and universal wildcard policies', () => {
  throwsInvalidOptions(() => createCorsPolicy({
    allowedOrigins: ['https://app.example.com', '*'],
    methods: ['GET'],
    allowPrivateNetwork: true
  }));
});

test('private network access remains available for an exact origin policy', () => {
  const policy = createCorsPolicy({
    allowedOrigins: ['https://internal.example.com'],
    methods: ['GET'],
    allowPrivateNetwork: true
  });
  const result = policy.evaluate(preflight('https://internal.example.com', 'GET', {
    'access-control-request-private-network': 'true'
  }));
  assert.equal(result.allowed, true);
  assert.equal(result.headers['access-control-allow-private-network'], 'true');
});

const malformedPnaValues = ['false', 'TRUE ', ' true', 'true,true', 'yes', '1', ''];
for (const value of malformedPnaValues) {
  test('private network request rejects malformed value ' + JSON.stringify(value), () => {
    const policy = basePolicy({ allowPrivateNetwork: true });
    const result = policy.evaluate(preflight('https://app.example.com', 'POST', {
      'access-control-request-private-network': value
    }));
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'CORS_PRIVATE_NETWORK_MALFORMED');
  });
}

test('private network request is not emitted for unauthorized origins', () => {
  const policy = basePolicy({ allowPrivateNetwork: true });
  const result = policy.evaluate(preflight('https://evil.example.com', 'POST', {
    'access-control-request-private-network': 'true'
  }));
  assert.equal(result.allowed, false);
  assert.equal(result.headers['access-control-allow-private-network'], undefined);
});

test('mergeVary merges case-insensitively without duplicates', () => {
  assert.equal(mergeVary('origin, Accept-Encoding', ['Origin', 'access-control-request-method']), 'origin, Accept-Encoding, access-control-request-method');
});

test('mergeVary preserves an existing star', () => {
  assert.equal(mergeVary('Origin, *', ['Accept']), '*');
});

test('mergeVary supports arrays and comma-joined strings', () => {
  assert.equal(mergeVary(['Origin', 'Accept-Encoding, Accept'], ['origin', 'X-Test']), 'Origin, Accept-Encoding, Accept, X-Test');
});

test('mergeVary drops invalid tokens rather than emitting header injection', () => {
  assert.equal(mergeVary('Origin, bad\rtoken', ['Access-Control-Request-Method']), 'Origin, Access-Control-Request-Method');
});

test('evaluation results are frozen', () => {
  const result = basePolicy().evaluate(actual('https://app.example.com'));
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.headers), true);
  assert.equal(Object.isFrozen(result.vary), true);
  assert.throws(() => {
    result.allowed = false;
  }, TypeError);
});

test('evaluate rejects non-object input', () => {
  assert.throws(() => basePolicy().evaluate(null), /ERR_CORSCAGE_INVALID_INPUT/);
});

const invalidCaps = [
  ['maxRequestHeaders', 0],
  ['maxRequestHeaders', 129],
  ['maxRequestHeaders', 1.5],
  ['maxRequestHeadersBytes', 127],
  ['maxRequestHeadersBytes', 16385],
  ['maxRequestHeadersBytes', Number.NaN]
];
for (const [key, value] of invalidCaps) {
  test('preflight cap config rejects ' + key + ' value ' + String(value), () => {
    throwsInvalidOptions(() => createCorsPolicy({ [key]: value }));
  });
}

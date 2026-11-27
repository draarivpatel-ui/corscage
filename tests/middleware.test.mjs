import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createNodeCorsMiddleware } from '../src/index.mjs';
import { mockResponse } from './helpers.mjs';

function options(extra = {}) {
  return Object.assign({
    allowedOrigins: ['https://app.example.com'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['content-type', 'authorization'],
    exposeHeaders: ['x-response-id']
  }, extra);
}

function runMiddleware(middleware, req, res) {
  let nextCalls = 0;
  middleware(req, res, () => {
    nextCalls += 1;
  });
  return nextCalls;
}

function actualReq(origin = 'https://app.example.com', method = 'GET') {
  return { method, headers: { origin } };
}

function preflightReq(origin = 'https://app.example.com', method = 'POST', extra = {}) {
  return {
    method: 'OPTIONS',
    headers: Object.assign({
      origin,
      'access-control-request-method': method,
      'access-control-request-headers': 'content-type'
    }, extra)
  };
}

test('middleware applies allowed actual response headers and calls next', () => {
  const res = mockResponse();
  const nextCalls = runMiddleware(createNodeCorsMiddleware(options()), actualReq(), res);
  assert.equal(nextCalls, 1);
  assert.equal(res.ended, false);
  assert.equal(res.headers['access-control-allow-origin'], 'https://app.example.com');
  assert.equal(res.headers['access-control-allow-credentials'], 'true');
  assert.equal(res.headers['access-control-expose-headers'], 'x-response-id');
  assert.equal(res.headers.vary, 'Origin');
});

test('middleware omits CORS headers for disallowed actual origin and calls next', () => {
  const res = mockResponse();
  const nextCalls = runMiddleware(createNodeCorsMiddleware(options()), actualReq('https://evil.example'), res);
  assert.equal(nextCalls, 1);
  assert.equal(res.headers['access-control-allow-origin'], undefined);
  assert.equal(res.headers.vary, 'Origin');
});

test('middleware strips stale CORS headers for disallowed actual origin', () => {
  const res = mockResponse();
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  const nextCalls = runMiddleware(createNodeCorsMiddleware(options()), actualReq('https://evil.example'), res);
  assert.equal(nextCalls, 1);
  assert.equal(res.headers['access-control-allow-origin'], undefined);
  assert.equal(res.headers['access-control-allow-credentials'], undefined);
});

test('middleware strips stale wildcard before replacing it with exact allowed origin', () => {
  const res = mockResponse();
  res.setHeader('Access-Control-Allow-Origin', '*');
  runMiddleware(createNodeCorsMiddleware(options()), actualReq(), res);
  assert.equal(res.headers['access-control-allow-origin'], 'https://app.example.com');
});

test('middleware handles no-Origin request as non-CORS and calls next', () => {
  const res = mockResponse();
  const nextCalls = runMiddleware(createNodeCorsMiddleware(options()), { method: 'GET', headers: {} }, res);
  assert.equal(nextCalls, 1);
  assert.equal(res.headers['access-control-allow-origin'], undefined);
  assert.equal(res.headers.vary, 'Origin');
});

test('middleware merges existing Vary header case-insensitively', () => {
  const res = mockResponse();
  res.setHeader('Vary', 'accept-encoding, origin');
  runMiddleware(createNodeCorsMiddleware(options()), preflightReq(), res);
  assert.equal(res.headers.vary, 'accept-encoding, origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network');
});

test('middleware preserves existing Vary star', () => {
  const res = mockResponse();
  res.setHeader('Vary', '*');
  runMiddleware(createNodeCorsMiddleware(options()), preflightReq(), res);
  assert.equal(res.headers.vary, '*');
});

test('middleware supports array-valued existing Vary header', () => {
  const res = mockResponse();
  res.headers.vary = ['Origin', 'Accept-Encoding'];
  runMiddleware(createNodeCorsMiddleware(options()), actualReq(), res);
  assert.equal(res.headers.vary, 'Origin, Accept-Encoding');
});

test('middleware ends authorized preflight with 204 and does not call next', () => {
  const res = mockResponse();
  const nextCalls = runMiddleware(createNodeCorsMiddleware(options()), preflightReq(), res);
  assert.equal(nextCalls, 0);
  assert.equal(res.statusCode, 204);
  assert.equal(res.ended, true);
  assert.equal(res.headers['access-control-allow-origin'], 'https://app.example.com');
  assert.equal(res.headers['access-control-allow-methods'], 'POST');
  assert.equal(res.headers['access-control-allow-headers'], 'content-type');
});

test('middleware ends rejected preflight with 403 and does not call next', () => {
  const res = mockResponse();
  const nextCalls = runMiddleware(createNodeCorsMiddleware(options()), preflightReq('https://evil.example'), res);
  assert.equal(nextCalls, 0);
  assert.equal(res.statusCode, 403);
  assert.equal(res.ended, true);
  assert.equal(res.headers['access-control-allow-origin'], undefined);
});

test('middleware can pass rejected preflight downstream when explicitly configured', () => {
  const res = mockResponse();
  const middleware = createNodeCorsMiddleware(options({ rejectDisallowedPreflight: false }));
  const nextCalls = runMiddleware(middleware, preflightReq('https://evil.example'), res);
  assert.equal(nextCalls, 1);
  assert.equal(res.ended, false);
  assert.equal(res.headers['access-control-allow-origin'], undefined);
});

test('middleware still ends authorized preflight when rejection passthrough is configured', () => {
  const res = mockResponse();
  const middleware = createNodeCorsMiddleware(options({ rejectDisallowedPreflight: false }));
  const nextCalls = runMiddleware(middleware, preflightReq(), res);
  assert.equal(nextCalls, 0);
  assert.equal(res.statusCode, 204);
});

test('plain OPTIONS without request-method passes downstream as actual request', () => {
  const res = mockResponse();
  const req = { method: 'OPTIONS', headers: { origin: 'https://app.example.com' } };
  const nextCalls = runMiddleware(createNodeCorsMiddleware(options()), req, res);
  assert.equal(nextCalls, 1);
  assert.equal(res.ended, false);
  assert.equal(res.headers['access-control-allow-origin'], 'https://app.example.com');
});

test('middleware rejects non-function next argument', () => {
  assert.throws(() => createNodeCorsMiddleware(options())(actualReq(), mockResponse(), true), /next must be a function/);
});

test('middleware requires response setHeader support', () => {
  assert.throws(() => createNodeCorsMiddleware(options())(actualReq(), {}, () => {}), /setHeader/);
});

test('middleware exposes its frozen policy non-enumerably', () => {
  const middleware = createNodeCorsMiddleware(options());
  assert.equal(typeof middleware.policy, 'object');
  assert.equal(Object.keys(middleware).includes('policy'), false);
  assert.equal(Object.isFrozen(middleware.policy), true);
  assert.equal(Object.isFrozen(middleware), true);
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function requestRaw(port, method, headers) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: '/resource',
      method,
      headers
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        statusCode: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8')
      }));
    });
    req.once('error', reject);
    req.end();
  });
}

async function withServer(middleware, fn) {
  const server = http.createServer((req, res) => {
    middleware(req, res, () => {
      res.setHeader('content-type', 'text/plain');
      res.end('application');
    });
  });
  const port = await listen(server);
  try {
    await fn(port);
  } finally {
    await close(server);
  }
}

test('real Node http server returns exact credentialed CORS headers', async () => {
  await withServer(createNodeCorsMiddleware(options()), async (port) => {
    const response = await requestRaw(port, 'GET', { origin: 'https://app.example.com' });
    assert.equal(response.statusCode, 200);
    assert.equal(response.body, 'application');
    assert.equal(response.headers['access-control-allow-origin'], 'https://app.example.com');
    assert.equal(response.headers['access-control-allow-credentials'], 'true');
    assert.equal(response.headers.vary, 'Origin');
  });
});

test('real Node http server omits CORS headers for rejected actual origin', async () => {
  await withServer(createNodeCorsMiddleware(options()), async (port) => {
    const response = await requestRaw(port, 'GET', { origin: 'https://evil.example' });
    assert.equal(response.statusCode, 200);
    assert.equal(response.body, 'application');
    assert.equal(response.headers['access-control-allow-origin'], undefined);
    assert.equal(response.headers.vary, 'Origin');
  });
});

test('real Node http server answers allowed preflight with 204 and empty body', async () => {
  await withServer(createNodeCorsMiddleware(options()), async (port) => {
    const response = await requestRaw(port, 'OPTIONS', {
      origin: 'https://app.example.com',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type'
    });
    assert.equal(response.statusCode, 204);
    assert.equal(response.body, '');
    assert.equal(response.headers['access-control-allow-origin'], 'https://app.example.com');
    assert.equal(response.headers['access-control-allow-methods'], 'POST');
    assert.match(response.headers.vary, /Access-Control-Request-Method/);
  });
});

test('real Node http server answers rejected preflight with 403 and empty body', async () => {
  await withServer(createNodeCorsMiddleware(options()), async (port) => {
    const response = await requestRaw(port, 'OPTIONS', {
      origin: 'https://evil.example',
      'access-control-request-method': 'POST'
    });
    assert.equal(response.statusCode, 403);
    assert.equal(response.body, '');
    assert.equal(response.headers['access-control-allow-origin'], undefined);
  });
});

test('real Node http server rejects comma-joined origin smuggling', async () => {
  await withServer(createNodeCorsMiddleware(options()), async (port) => {
    const response = await requestRaw(port, 'GET', { origin: 'https://app.example.com,https://evil.example' });
    assert.equal(response.statusCode, 200);
    assert.equal(response.headers['access-control-allow-origin'], undefined);
  });
});

test('real Node http server preserves downstream Vary token', async () => {
  const server = http.createServer((req, res) => {
    res.setHeader('Vary', 'Accept-Encoding');
    createNodeCorsMiddleware(options())(req, res, () => {
      res.end('application');
    });
  });
  const port = await listen(server);
  try {
    const response = await requestRaw(port, 'GET', { origin: 'https://app.example.com' });
    assert.equal(response.headers.vary, 'Accept-Encoding, Origin');
  } finally {
    await close(server);
  }
});

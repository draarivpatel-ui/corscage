import test from 'node:test';
import assert from 'node:assert/strict';
import { createFetchCorsHandler } from '../src/index.mjs';

function options(extra = {}) {
  return Object.assign({
    allowedOrigins: ['https://app.example.com'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['content-type', 'authorization'],
    exposeHeaders: ['x-response-id']
  }, extra);
}

function actualRequest(origin = 'https://app.example.com', method = 'GET') {
  return new Request('https://api.example.test/resource', {
    method,
    headers: { origin }
  });
}

function preflightRequest(origin = 'https://app.example.com', method = 'POST', extra = {}) {
  const headers = new Headers({
    origin,
    'access-control-request-method': method,
    'access-control-request-headers': 'content-type'
  });
  for (const [name, value] of Object.entries(extra)) headers.set(name, value);
  return new Request('https://api.example.test/resource', { method: 'OPTIONS', headers });
}

function okResponse() {
  return new Response('body', {
    status: 201,
    statusText: 'Created Custom',
    headers: {
      'content-type': 'text/plain',
      'x-custom': 'preserved'
    }
  });
}

test('fetch adapter handles authorized preflight without invoking the handler', async () => {
  let calls = 0;
  const handler = createFetchCorsHandler(options())(async () => {
    calls += 1;
    return okResponse();
  });
  const response = await handler(preflightRequest());
  assert.equal(calls, 0);
  assert.equal(response.status, 204);
  assert.equal(await response.text(), '');
  assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.example.com');
  assert.equal(response.headers.get('access-control-allow-methods'), 'POST');
  assert.equal(response.headers.get('access-control-allow-headers'), 'content-type');
  assert.match(response.headers.get('vary'), /Access-Control-Request-Method/);
});

test('fetch adapter rejects unauthorized preflight without invoking the handler', async () => {
  let calls = 0;
  const handler = createFetchCorsHandler(options())(async () => {
    calls += 1;
    return okResponse();
  });
  const response = await handler(preflightRequest('https://evil.example'));
  assert.equal(calls, 0);
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.match(response.headers.get('vary'), /Origin/);
});

test('fetch adapter wraps actual response with exact credentialed CORS headers', async () => {
  const handler = createFetchCorsHandler(options())(async () => okResponse());
  const response = await handler(actualRequest());
  assert.equal(response.status, 201);
  assert.equal(response.statusText, 'Created Custom');
  assert.equal(await response.text(), 'body');
  assert.equal(response.headers.get('x-custom'), 'preserved');
  assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.example.com');
  assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
  assert.equal(response.headers.get('access-control-expose-headers'), 'x-response-id');
});

test('fetch adapter does not mutate the original immutable response headers', async () => {
  const original = okResponse();
  const before = original.headers.get('access-control-allow-origin');
  const handler = createFetchCorsHandler(options())(async () => original);
  const response = await handler(actualRequest());
  assert.equal(original.headers.get('access-control-allow-origin'), before);
  assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.example.com');
});

test('fetch adapter strips stale permissive CORS headers for rejected actual origin', async () => {
  const handler = createFetchCorsHandler(options())(async () => new Response('body', {
    headers: {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true'
    }
  }));
  const response = await handler(actualRequest('https://evil.example'));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal(response.headers.get('access-control-allow-credentials'), null);
});

test('fetch adapter replaces stale wildcard with exact allowed origin', async () => {
  const handler = createFetchCorsHandler(options())(async () => new Response('body', {
    headers: { 'access-control-allow-origin': '*' }
  }));
  const response = await handler(actualRequest());
  assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.example.com');
});

test('fetch adapter strips CORS headers for no-Origin responses', async () => {
  const handler = createFetchCorsHandler(options())(async () => new Response('body', {
    headers: { 'access-control-allow-origin': '*' }
  }));
  const response = await handler(new Request('https://api.example.test/resource'));
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal(response.headers.get('vary'), 'Origin');
});

test('fetch adapter merges existing Vary values case-insensitively', async () => {
  const handler = createFetchCorsHandler(options())(async () => new Response('body', {
    headers: { vary: 'accept-encoding, ORIGIN' }
  }));
  const response = await handler(actualRequest());
  assert.equal(response.headers.get('vary'), 'accept-encoding, ORIGIN');
});

test('fetch adapter preserves existing Vary star', async () => {
  const handler = createFetchCorsHandler(options())(async () => new Response('body', {
    headers: { vary: '*' }
  }));
  const response = await handler(actualRequest());
  assert.equal(response.headers.get('vary'), '*');
});

test('fetch adapter can pass a rejected preflight downstream only by explicit configuration', async () => {
  let calls = 0;
  const handler = createFetchCorsHandler(options({ rejectDisallowedPreflight: false }))(async () => {
    calls += 1;
    return new Response('handled', { headers: { 'access-control-allow-origin': '*' } });
  });
  const response = await handler(preflightRequest('https://evil.example'));
  assert.equal(calls, 1);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'handled');
  assert.equal(response.headers.get('access-control-allow-origin'), null);
});

test('fetch adapter direct form wraps a handler supplied as second argument', async () => {
  const handler = createFetchCorsHandler(options(), async () => okResponse());
  const response = await handler(actualRequest());
  assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.example.com');
});

test('fetch adapter passes additional handler arguments through', async () => {
  const handler = createFetchCorsHandler(options())(async (request, env, context) => {
    assert.equal(env.name, 'env');
    assert.equal(context.id, 42);
    return okResponse();
  });
  await handler(actualRequest(), { name: 'env' }, { id: 42 });
});

test('fetch adapter propagates handler exceptions without inventing CORS headers', async () => {
  const failure = new Error('handler failed');
  const handler = createFetchCorsHandler(options())(async () => {
    throw failure;
  });
  await assert.rejects(() => handler(actualRequest()), (error) => error === failure);
});

test('fetch adapter rejects a handler that does not return Response', async () => {
  const handler = createFetchCorsHandler(options())(async () => ({ not: 'response' }));
  await assert.rejects(() => handler(actualRequest()), /must return a Response/);
});

test('fetch adapter rejects non-function handlers', () => {
  assert.throws(() => createFetchCorsHandler(options())(true), /requires a handler function/);
});

test('fetch adapter recognizes Headers objects case-insensitively', async () => {
  const request = new Request('https://api.example.test/resource', {
    headers: { OrIgIn: 'https://app.example.com' }
  });
  const handler = createFetchCorsHandler(options())(async () => okResponse());
  const response = await handler(request);
  assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.example.com');
});

test('fetch adapter blocks null origin by default', async () => {
  const handler = createFetchCorsHandler(options())(async () => okResponse());
  const response = await handler(actualRequest('null'));
  assert.equal(response.headers.get('access-control-allow-origin'), null);
});

test('fetch adapter emits PNA only for authorized opted-in preflight', async () => {
  const handler = createFetchCorsHandler(options({ allowPrivateNetwork: true }))(async () => okResponse());
  const response = await handler(preflightRequest('https://app.example.com', 'POST', {
    'access-control-request-private-network': 'true'
  }));
  assert.equal(response.status, 204);
  assert.equal(response.headers.get('access-control-allow-private-network'), 'true');
});

test('fetch adapter copies streaming response bodies', async () => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('stream-body'));
      controller.close();
    }
  });
  const handler = createFetchCorsHandler(options())(async () => new Response(stream));
  const response = await handler(actualRequest());
  assert.equal(await response.text(), 'stream-body');
});

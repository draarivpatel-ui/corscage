import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

export const cjs = require('../cjs/index.cjs');
export const esm = await import('../src/index.mjs');
export const APIs = [
  ['esm', esm],
  ['cjs', cjs]
];

export function throwsCode(fn, code, message) {
  let error;
  const label = message || 'expected CorsCageError ' + code;
  assert.throws(fn, (caught) => {
    error = caught;
    return true;
  }, label);
  assert.equal(error.name, 'CorsCageError', label);
  assert.equal(error.code, code, label);
  assert.ok(typeof error.reason === 'string' && error.reason.length > 0, label);
  assert.ok('input' in error, label);
  return error;
}

export function throwsInvalidOptions(fn, message) {
  return throwsCode(fn, cjs.CODE.INVALID_OPTIONS, message);
}

export function request(method, headers) {
  return { method, headers };
}

export function actual(origin, method = 'GET', extraHeaders = {}) {
  return request(method, Object.assign({ origin }, extraHeaders));
}

export function preflight(origin, method = 'POST', extraHeaders = {}) {
  return request('OPTIONS', Object.assign({
    origin,
    'access-control-request-method': method
  }, extraHeaders));
}

export function mockResponse() {
  return {
    headers: Object.create(null),
    statusCode: 200,
    ended: false,
    endCount: 0,
    setHeader(name, value) {
      this.headers[String(name).toLowerCase()] = String(value);
    },
    getHeader(name) {
      return this.headers[String(name).toLowerCase()];
    },
    removeHeader(name) {
      delete this.headers[String(name).toLowerCase()];
    },
    end() {
      this.ended = true;
      this.endCount += 1;
    }
  };
}

export function codesOf(findings) {
  return findings.map((finding) => finding.code);
}

export function findingsFor(findings, code) {
  return findings.filter((finding) => finding.code === code);
}

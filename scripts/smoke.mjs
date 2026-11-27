import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as esm from '../src/index.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');

assert.equal(esm.normalizeOrigin('HTTPS://EXAMPLE.COM:443'), 'https://example.com');
assert.equal(cjs.normalizeOrigin('HTTPS://EXAMPLE.COM:443'), 'https://example.com');
assert.equal(typeof esm.createCorsPolicy, 'function');
assert.equal(typeof cjs.createCorsPolicy, 'function');
assert.equal(cjs.default, cjs);
process.stdout.write('corscage ESM and CJS smoke checks passed\n');

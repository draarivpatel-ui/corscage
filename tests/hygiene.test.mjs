import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { cjs } from './helpers.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_ENTRIES = new Set(['.git', 'node_modules', '.DS_Store']);

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (SKIP_ENTRIES.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(full));
    else if (entry.isFile() && !entry.name.endsWith('.tgz')) output.push(full);
  }
  return output.sort();
}

async function textFiles() {
  return walk(root);
}

test('repository text files contain no em dash or en dash characters', async () => {
  const emDash = String.fromCharCode(0x2014);
  const enDash = String.fromCharCode(0x2013);
  for (const file of await textFiles()) {
    const text = await readFile(file, 'utf8');
    assert.equal(text.includes(emDash), false, file + ' contains an em dash');
    assert.equal(text.includes(enDash), false, file + ' contains an en dash');
  }
});

test('repository text files use LF line endings only', async () => {
  for (const file of await textFiles()) {
    const text = await readFile(file, 'utf8');
    assert.equal(text.includes('\r'), false, file + ' contains carriage return');
  }
});

test('repository text files contain no local paths or private account data', async () => {
  const banned = [
    new RegExp('/' + 'Users' + '/'),
    new RegExp('Hub' + '/' + 'personal'),
    new RegExp('Contest' + ' ' + 'Submissions'),
    new RegExp('@' + 'gmail'),
    new RegExp('pro' + 'ro' + 'blox', 'i'),
    new RegExp('aa' + 'riv' + 'patel', 'i'),
    new RegExp('t3' + '-code', 'i')
  ];
  for (const file of await textFiles()) {
    const text = (await readFile(file, 'utf8'))
      .replaceAll('287273626+draarivpatel-ui@users.noreply.github.com', '')
      .replaceAll('draarivpatel-ui', '');
    for (const pattern of banned) {
      assert.equal(pattern.test(text), false, file + ' contains prohibited local or private data');
    }
  }
});

test('repository files contain no vendor-shaped secret placeholders', async () => {
  const patterns = [
    new RegExp('ts' + 'key-'),
    new RegExp('s' + 'k-[A-Za-z0-9]'),
    new RegExp('gh' + 'p_[A-Za-z0-9]'),
    new RegExp('github' + '_pat_[A-Za-z0-9]'),
    new RegExp('AK' + 'IA[0-9A-Z]'),
    new RegExp('x' + 'ox[baprs]-'),
    new RegExp('nv' + 'api-'),
    new RegExp('AI' + 'za[0-9A-Za-z_-]')
  ];
  for (const file of await textFiles()) {
    const text = await readFile(file, 'utf8');
    for (const pattern of patterns) {
      assert.equal(pattern.test(text), false, file + ' contains secret-shaped content');
    }
  }
});

test('package metadata has the required name version license and dependency shape', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'corscage');
  assert.equal(pkg.version, '1.0.0');
  assert.equal(pkg.license, 'MIT');
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
  assert.equal(pkg.engines.node, '>=18.0.0');
  assert.equal(pkg.sideEffects, false);
});

test('package repository metadata points at the public repository', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.repository.type, 'git');
  assert.equal(pkg.repository.url, 'git+https://github.com/draarivpatel-ui/corscage.git');
  assert.equal(pkg.homepage, 'https://github.com/draarivpatel-ui/corscage#readme');
  assert.equal(pkg.bugs.url, 'https://github.com/draarivpatel-ui/corscage/issues');
});

test('package module exports provide ESM CJS and TypeScript entries', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.main, './cjs/index.cjs');
  assert.equal(pkg.module, './src/index.mjs');
  assert.equal(pkg.types, './types/index.d.ts');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.exports['.'].require, './cjs/index.cjs');
});

test('package bin entry has no leading relative prefix', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.bin, { corscage: 'bin/corscage.mjs' });
  assert.equal(pkg.bin.corscage.startsWith('./'), false);
});

test('package test script uses the required explicit test glob', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts.test, 'node scripts/run-tests.mjs');
});

test('package published file list is intentional and includes runtime docs types and CLI', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.files, [
    'src',
    'cjs',
    'types',
    'bin',
    'docs',
    'README.md',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'LICENSE'
  ]);
});

test('gitattributes enforces LF line endings for source and documentation types', async () => {
  const text = await readFile(path.join(root, '.gitattributes'), 'utf8');
  assert.match(text, /\* text=auto eol=lf/);
  for (const extension of ['mjs', 'cjs', 'js', 'ts', 'json', 'md', 'yml']) {
    assert.ok(text.includes('*.' + extension + ' text eol=lf'), extension);
  }
});

test('CI covers Node 18 20 22 and 24 on ubuntu 24.04 and Windows', async () => {
  const ci = await readFile(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.ok(ci.includes('ubuntu-24.04'));
  assert.ok(ci.includes('windows-latest'));
  assert.ok(ci.includes('node: [18, 20, 22, 24]'));
  assert.ok(ci.includes('npm test'));
  assert.ok(ci.includes('npm run check:cjs'));
  assert.ok(ci.includes('node scripts/cli-smoke.mjs'));
  assert.ok(ci.includes('npm run smoke'));
  assert.ok(ci.includes('npm pack --dry-run'));
});

test('README documents threat model limitations and honest publication status', async () => {
  const readme = await readFile(path.join(root, 'README.md'), 'utf8');
  assert.match(readme, /Threat model/i);
  assert.match(readme, /Limitations/i);
  assert.match(readme, /not claimed to be published yet/i);
  assert.match(readme, /718 deterministic tests/i);
  assert.match(readme, /not an\s+authentication system/i);
});

test('README includes Node Express Fetch CLI and finding code documentation', async () => {
  const readme = await readFile(path.join(root, 'README.md'), 'utf8');
  for (const fragment of [
    'createNodeCorsMiddleware',
    'createFetchCorsHandler',
    'corscage lint --config',
    'CORS_WILDCARD_WITH_CREDENTIALS',
    'CORS_PRIVATE_NETWORK_WITH_WILDCARD',
    'app.use('
  ]) {
    assert.ok(readme.includes(fragment), fragment);
  }
});

test('security documentation includes reporting guidance supported versions and scope', async () => {
  const security = await readFile(path.join(root, 'SECURITY.md'), 'utf8');
  assert.match(security, /Reporting a vulnerability/i);
  assert.match(security, /Supported versions/i);
  assert.match(security, /In scope/i);
  assert.match(security, /Out of scope/i);
});

test('good first issues file contains exactly ten numbered starter specifications', async () => {
  const text = await readFile(path.join(root, 'docs', 'GOOD_FIRST_ISSUES.md'), 'utf8');
  const count = (text.match(/^## \d+\./gm) || []).length;
  assert.equal(count, 10);
});

test('license is MIT and does not contain private personal data', async () => {
  const license = await readFile(path.join(root, 'LICENSE'), 'utf8');
  assert.match(license, /MIT License/);
  assert.match(license, /Permission is hereby granted/);
  assert.match(license, /corscage contributors/);
});

test('generated CommonJS file carries the generator marker and default export bridge', async () => {
  const text = await readFile(path.join(root, 'cjs', 'index.cjs'), 'utf8');
  assert.match(text, /Generated by scripts\/build-cjs\.mjs/);
  assert.match(text, /module\.exports\.default = module\.exports/);
});

test('runtime source does not use eval or the Function constructor', async () => {
  for (const file of ['src/index.mjs', 'cjs/index.cjs', 'bin/corscage.mjs']) {
    const text = await readFile(path.join(root, file), 'utf8');
    assert.equal(/\beval\s*\(/.test(text), false, file);
    assert.equal(/\bnew\s+Function\s*\(/.test(text), false, file);
  }
});

test('runtime error codes are frozen unique and machine-readable', () => {
  assert.equal(Object.isFrozen(cjs.CODE), true);
  const values = Object.values(cjs.CODE);
  assert.equal(new Set(values).size, values.length);
  for (const value of values) assert.match(value, /^ERR_CORSCAGE_[A-Z0-9_]+$/);
});

test('lint codes are frozen unique and machine-readable', () => {
  assert.equal(Object.isFrozen(cjs.LINT_CODES), true);
  const values = Object.values(cjs.LINT_CODES);
  assert.equal(new Set(values).size, values.length);
  for (const value of values) assert.match(value, /^CORS_[A-Z0-9_]+$/);
});

test('TypeScript definitions include every public API', async () => {
  const types = await readFile(path.join(root, 'types', 'index.d.ts'), 'utf8');
  for (const fragment of [
    'parseOrigin',
    'normalizeOrigin',
    'matchOrigin',
    'mergeVary',
    'createCorsPolicy',
    'createNodeCorsMiddleware',
    'createFetchCorsHandler',
    'lintCorsPolicy',
    'assertSafeCorsConfig',
    'CorsPolicyOptions',
    'CorsEvaluation'
  ]) {
    assert.ok(types.includes(fragment), fragment);
  }
});

test('no dependency directory is present in the source tree', async () => {
  await assert.rejects(stat(path.join(root, 'node_modules')), /ENOENT/);
});

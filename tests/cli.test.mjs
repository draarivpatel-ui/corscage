import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'corscage.mjs');
const scratch = mkdtempSync(path.join(tmpdir(), 'corscage-test-'));
let configCounter = 0;

process.on('exit', () => {
  rmSync(scratch, { recursive: true, force: true });
});

function writeConfig(value, name) {
  configCounter += 1;
  const file = path.join(scratch, name || 'config-' + String(configCounter) + '.json');
  writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value), 'utf8');
  return file;
}

function goodConfig() {
  return writeConfig({
    allowedOrigins: ['https://app.example.com'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['content-type', 'authorization'],
    maxAge: 600
  });
}

function runCli(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
}

test('CLI help exits zero and documents both commands', () => {
  const result = runCli(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /corscage check/);
  assert.match(result.stdout, /corscage lint/);
  assert.match(result.stdout, /Exit codes/);
});

test('CLI unknown command exits 2', () => {
  const result = runCli(['wat']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown command/);
});

test('CLI lint clean config exits zero with human output', () => {
  const result = runCli(['lint', '--config', goodConfig()]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /clean/);
});

test('CLI lint clean config exits zero with JSON output', () => {
  const result = runCli(['lint', '--config', goodConfig(), '--json']);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.findings, []);
});

test('CLI lint findings exit 1 with structured JSON', () => {
  const file = writeConfig({ allowedOrigins: ['*'], credentials: true });
  const result = runCli(['lint', '--config', file, '--json']);
  assert.equal(result.status, 1);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.ok, false);
  assert.ok(parsed.findings.some((finding) => finding.code === 'CORS_WILDCARD_WITH_CREDENTIALS'));
  assert.equal(parsed.counts.critical > 0, true);
});

test('CLI lint human output includes severity, code and remediation', () => {
  const file = writeConfig({ allowedOrigins: ['http://api.example.com'] });
  const result = runCli(['lint', '--config', file]);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /\[high\] CORS_INSECURE_HTTP_ORIGIN/);
  assert.match(result.stdout, /Fix:/);
});

test('CLI lint missing config flag exits 2', () => {
  const result = runCli(['lint']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires --config/);
});

test('CLI nonexistent config exits 2', () => {
  const result = runCli(['lint', '--config', path.join(scratch, 'missing.json')]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /does not exist/);
});

test('CLI directory config path exits 2', () => {
  const result = runCli(['lint', '--config', scratch]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /regular file/);
});

test('CLI FIFO config path is refused on platforms with FIFO support', () => {
  if (process.platform === 'win32') {
    assert.equal(process.platform, 'win32');
    return;
  }
  const fifo = path.join(scratch, 'config.fifo');
  const made = spawnSync('mkfifo', [fifo], { encoding: 'utf8' });
  assert.equal(made.status, 0, made.stderr);
  const result = runCli(['lint', '--config', fifo]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /regular file/);
});

test('CLI symlink config path is refused', () => {
  const target = goodConfig();
  const link = path.join(scratch, 'linked-config.json');
  let linked = false;
  try {
    symlinkSync(target, link);
    linked = true;
  } catch {
    linked = false;
  }
  if (!linked) {
    assert.equal(process.platform, 'win32');
    return;
  }
  const result = runCli(['lint', '--config', link]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /symlink|regular file/);
});

test('CLI oversized config exits 2', () => {
  const file = path.join(scratch, 'oversized.json');
  writeFileSync(file, '{"padding":"' + 'x'.repeat(70000) + '"}', 'utf8');
  const result = runCli(['lint', '--config', file]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /65536 byte cap/);
});


test('CLI accepts a regular config exactly at the byte cap', () => {
  const base = JSON.stringify({ allowedOrigins: ['https://app.example.com'] });
  const padding = ' '.repeat(65536 - Buffer.byteLength(base, 'utf8'));
  const file = writeConfig(base + padding, 'exact-cap.json');
  assert.equal(statSync(file).size, 65536);
  const result = runCli(['lint', '--config', file]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /clean/);
});

test('CLI invalid JSON exits 2', () => {
  const file = writeConfig('{not json', 'invalid-json.json');
  const result = runCli(['lint', '--config', file]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /not valid JSON/);
});

test('CLI non-object JSON root exits 2', () => {
  for (const [name, value] of [['array.json', '[]'], ['null.json', 'null'], ['string.json', '"x"']]) {
    const file = writeConfig(value, name);
    const result = runCli(['lint', '--config', file]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /root must be a JSON object/);
  }
});

test('CLI reserved prototype pollution keys exit 2', () => {
  const file = writeConfig('{"__proto__":{"polluted":true},"allowedOrigins":[]}', 'proto-config.json');
  const result = runCli(['lint', '--config', file]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /reserved object key/);
});

test('CLI check allowed actual origin exits zero with JSON', () => {
  const result = runCli(['check', '--config', goodConfig(), '--origin', 'https://app.example.com', '--json']);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.result.headers['access-control-allow-origin'], 'https://app.example.com');
});

test('CLI check denied actual origin exits 1 with JSON', () => {
  const result = runCli(['check', '--config', goodConfig(), '--origin', 'https://evil.example', '--json']);
  assert.equal(result.status, 1);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.ok, false);
  assert.equal(parsed.result.headers['access-control-allow-origin'], undefined);
});

test('CLI check malformed origin exits 1', () => {
  const result = runCli(['check', '--config', goodConfig(), '--origin', 'https://app.example.com/']);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /allowed: no/);
});

test('CLI check authorized preflight exits zero and emits expected headers', () => {
  const result = runCli([
    'check', '--config', goodConfig(), '--origin', 'https://app.example.com',
    '--method', 'POST', '--request-headers', 'content-type', '--preflight', '--json'
  ]);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.result.statusCode, 204);
  assert.equal(parsed.result.headers['access-control-allow-methods'], 'POST');
  assert.equal(parsed.result.headers['access-control-allow-headers'], 'content-type');
});

test('CLI check rejected preflight exits 1 with status 403', () => {
  const result = runCli([
    'check', '--config', goodConfig(), '--origin', 'https://evil.example',
    '--method', 'POST', '--preflight', '--json'
  ]);
  assert.equal(result.status, 1);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.result.statusCode, 403);
});

test('CLI check private network request is denied by default policy', () => {
  const result = runCli([
    'check', '--config', goodConfig(), '--origin', 'https://app.example.com',
    '--method', 'POST', '--preflight', '--private-network', '--json'
  ]);
  assert.equal(result.status, 1);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.result.code, 'CORS_PRIVATE_NETWORK_DENIED');
});

test('CLI check private network opt-in exits zero', () => {
  const file = writeConfig({
    allowedOrigins: ['https://app.example.com'],
    methods: ['POST'],
    allowPrivateNetwork: true
  });
  const result = runCli([
    'check', '--config', file, '--origin', 'https://app.example.com',
    '--method', 'POST', '--preflight', '--private-network', '--json'
  ]);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.result.headers['access-control-allow-private-network'], 'true');
});

test('CLI request headers without preflight are a usage error', () => {
  const result = runCli(['check', '--config', goodConfig(), '--origin', 'https://app.example.com', '--request-headers', 'content-type']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /require --preflight/);
});

test('CLI check missing origin exits 2', () => {
  const result = runCli(['check', '--config', goodConfig()]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires --origin/);
});

test('CLI check missing config exits 2', () => {
  const result = runCli(['check', '--origin', 'https://app.example.com']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires --config/);
});

test('CLI unknown flag exits 2', () => {
  const result = runCli(['lint', '--config', goodConfig(), '--wat']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown flag/);
});

test('CLI duplicate flag exits 2', () => {
  const file = goodConfig();
  const result = runCli(['lint', '--config', file, '--config', file]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /duplicate flag/);
});

test('CLI missing flag value exits 2', () => {
  const result = runCli(['lint', '--config']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /missing value/);
});

test('CLI positional argument exits 2', () => {
  const result = runCli(['lint', goodConfig()]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /positional argument/);
});

test('CLI invalid runtime config exits 2 rather than 1', () => {
  const file = writeConfig({ allowedOrigins: ['*'], credentials: true });
  const result = runCli(['check', '--config', file, '--origin', 'https://app.example.com']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /wildcard/);
});

test('CLI JSON usage errors produce JSON on stdout', () => {
  const result = runCli(['lint', '--json']);
  assert.equal(result.status, 2);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /requires --config/);
});

test('CLI executable file has a node shebang and executable mode', () => {
  assert.equal(readFileSync(cli, 'utf8').startsWith('#!/usr/bin/env node\n'), true);
  if (process.platform !== 'win32') {
    assert.notEqual(statSync(cli).mode & 0o111, 0);
  }
});

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scratch = mkdtempSync(path.join(tmpdir(), 'corscage-ci-'));
try {
  const configPath = path.join(scratch, 'cors.json');
  writeFileSync(configPath, JSON.stringify({
    allowedOrigins: ['https://app.example.com'],
    methods: ['GET', 'POST'],
    allowedHeaders: ['content-type']
  }), 'utf8');
  const cli = path.join(root, 'bin', 'corscage.mjs');
  const check = spawnSync(process.execPath, [
    cli,
    'check',
    '--config', configPath,
    '--origin', 'https://app.example.com',
    '--method', 'POST',
    '--request-headers', 'content-type',
    '--preflight',
    '--json'
  ], { encoding: 'utf8' });
  assert.equal(check.status, 0, check.stderr || check.stdout);
  const parsed = JSON.parse(check.stdout);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.result.statusCode, 204);
  const lint = spawnSync(process.execPath, [cli, 'lint', '--config', configPath, '--json'], { encoding: 'utf8' });
  assert.equal(lint.status, 0, lint.stderr || lint.stdout);
  assert.equal(JSON.parse(lint.stdout).ok, true);
  process.stdout.write('corscage CLI smoke checks passed\n');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

#!/usr/bin/env node

import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import process from 'node:process';
import {
  CorsCageError,
  createCorsPolicy,
  lintCorsPolicy
} from '../src/index.mjs';

const MAX_CONFIG_BYTES = 65536;
const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function printUsage(stream) {
  stream.write([
    'corscage - strict CORS policy checks',
    '',
    'Usage:',
    '  corscage check --config <file.json> --origin <origin> [--method <method>] [--request-headers <h1,h2>] [--preflight] [--private-network] [--json]',
    '  corscage lint --config <file.json> [--json]',
    '',
    'Exit codes:',
    '  0  check allowed, or lint found no findings',
    '  1  check denied, or lint found one or more findings',
    '  2  usage, input or configuration error',
    ''
  ].join('\n'));
}

function cliError(message, json) {
  if (json) {
    process.stdout.write(JSON.stringify({ ok: false, error: message }, null, 2) + '\n');
  } else {
    process.stderr.write('corscage: ' + message + '\n');
  }
  process.exitCode = 2;
}

function parseArgs(args, booleanFlags, valueFlags) {
  const output = Object.create(null);
  for (const flag of booleanFlags) output[flag] = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith('--')) return { error: 'unexpected positional argument ' + arg };
    const name = arg.slice(2);
    if (booleanFlags.includes(name)) {
      if (output[name] === true) return { error: 'duplicate flag --' + name };
      output[name] = true;
      continue;
    }
    if (!valueFlags.includes(name)) return { error: 'unknown flag --' + name };
    if (index + 1 >= args.length) return { error: 'missing value for --' + name };
    const value = args[index + 1];
    if (value.startsWith('--')) return { error: 'missing value for --' + name };
    if (output[name] !== undefined) return { error: 'duplicate flag --' + name };
    output[name] = value;
    index += 1;
  }
  return { flags: output };
}

function findReservedKey(value, path) {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = findReservedKey(value[index], path + '[' + String(index) + ']');
      if (found !== null) return found;
    }
    return null;
  }
  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      const childPath = path === '' ? key : path + '.' + key;
      if (RESERVED_KEYS.has(key)) return childPath;
      const found = findReservedKey(value[key], childPath);
      if (found !== null) return found;
    }
  }
  return null;
}

async function readConfig(path) {
  let stat;
  try {
    stat = await lstat(path);
  } catch {
    throw new Error('configuration file does not exist or is not readable');
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('configuration path must be a regular file, not a symlink or special file');
  }
  if (stat.size > MAX_CONFIG_BYTES) {
    throw new Error('configuration file exceeds the 65536 byte cap');
  }
  const nofollowFlag = process.platform !== 'win32' && typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | nofollowFlag);
  } catch (error) {
    if (error && error.code === 'ELOOP') {
      throw new Error('configuration path must be a regular file, not a symlink or special file');
    }
    throw new Error('configuration file does not exist or is not readable');
  }
  let text;
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile()) {
      throw new Error('configuration path must be a regular file, not a symlink or special file');
    }
    if (openedStat.size > MAX_CONFIG_BYTES) {
      throw new Error('configuration file exceeds the 65536 byte cap');
    }
    const buffer = Buffer.alloc(MAX_CONFIG_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const result = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    if (offset > MAX_CONFIG_BYTES) {
      throw new Error('configuration file exceeds the 65536 byte cap');
    }
    const closingStat = await handle.stat();
    if (!closingStat.isFile() || closingStat.size !== openedStat.size || offset !== openedStat.size) {
      throw new Error('configuration file changed while being read');
    }
    text = buffer.toString('utf8', 0, offset);
  } finally {
    await handle.close().catch(() => {});
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('configuration file is not valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('configuration root must be a JSON object');
  }
  const reserved = findReservedKey(parsed, '');
  if (reserved !== null) {
    throw new Error('configuration contains a reserved object key at ' + reserved);
  }
  return parsed;
}

function countSeverities(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
  }
  return counts;
}

async function runLint(args) {
  const parsed = parseArgs(args, ['json'], ['config']);
  if (parsed.error) return cliError(parsed.error, args.includes('--json'));
  const flags = parsed.flags;
  if (flags.config === undefined) return cliError('lint requires --config <file.json>', flags.json);
  let config;
  try {
    config = await readConfig(flags.config);
  } catch (error) {
    return cliError(error.message, flags.json);
  }
  const findings = lintCorsPolicy(config);
  const counts = countSeverities(findings);
  const clean = findings.length === 0;
  if (flags.json) {
    process.stdout.write(JSON.stringify({ ok: clean, counts, findings }, null, 2) + '\n');
  } else if (clean) {
    process.stdout.write('corscage lint: clean\n');
  } else {
    for (const finding of findings) {
      const where = finding.path === null ? 'configuration' : finding.path;
      process.stdout.write('[' + finding.severity + '] ' + finding.code + ' at ' + where + '\n');
      process.stdout.write('  ' + finding.message + '\n');
      process.stdout.write('  Fix: ' + finding.remediation + '\n');
    }
    process.stdout.write('corscage lint: ' + String(findings.length) + ' finding(s)\n');
  }
  process.exitCode = clean ? 0 : 1;
}

async function runCheck(args) {
  const parsed = parseArgs(
    args,
    ['json', 'preflight', 'private-network'],
    ['config', 'origin', 'method', 'request-headers']
  );
  if (parsed.error) return cliError(parsed.error, args.includes('--json'));
  const flags = parsed.flags;
  if (flags.config === undefined) return cliError('check requires --config <file.json>', flags.json);
  if (flags.origin === undefined) return cliError('check requires --origin <origin>', flags.json);
  let config;
  try {
    config = await readConfig(flags.config);
  } catch (error) {
    return cliError(error.message, flags.json);
  }
  let policy;
  try {
    policy = createCorsPolicy(config);
  } catch (error) {
    if (error instanceof CorsCageError) return cliError(error.reason, flags.json);
    throw error;
  }
  const method = flags.method === undefined ? 'GET' : flags.method;
  const headers = { origin: flags.origin };
  let request;
  if (flags.preflight) {
    headers['access-control-request-method'] = method;
    if (flags['request-headers'] !== undefined) {
      headers['access-control-request-headers'] = flags['request-headers'];
    }
    if (flags['private-network']) {
      headers['access-control-request-private-network'] = 'true';
    }
    request = { method: 'OPTIONS', headers };
  } else {
    if (flags['request-headers'] !== undefined || flags['private-network']) {
      return cliError('--request-headers and --private-network require --preflight', flags.json);
    }
    request = { method, headers };
  }
  const result = policy.evaluate(request);
  if (flags.json) {
    process.stdout.write(JSON.stringify({ ok: result.allowed, result }, null, 2) + '\n');
  } else {
    process.stdout.write('allowed: ' + (result.allowed ? 'yes' : 'no') + '\n');
    process.stdout.write('code: ' + result.code + '\n');
    process.stdout.write('reason: ' + result.reason + '\n');
    if (result.statusCode !== null) process.stdout.write('status: ' + String(result.statusCode) + '\n');
    if (result.vary.length > 0) process.stdout.write('vary: ' + result.vary.join(', ') + '\n');
    for (const name of Object.keys(result.headers)) {
      process.stdout.write(name + ': ' + result.headers[name] + '\n');
    }
  }
  process.exitCode = result.allowed ? 0 : 1;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    printUsage(process.stdout);
    return;
  }
  const command = args[0];
  if (command === 'lint') {
    await runLint(args.slice(1));
    return;
  }
  if (command === 'check') {
    await runCheck(args.slice(1));
    return;
  }
  cliError('unknown command ' + command, args.includes('--json'));
}

main().catch((error) => {
  process.stderr.write('corscage: unexpected failure: ' + error.message + '\n');
  process.exitCode = 2;
});

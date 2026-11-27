/*
 * corscage core.
 *
 * Pure Web Standards JavaScript with no static imports and no runtime
 * dependencies. The CommonJS build in cjs/index.cjs is generated from this
 * file by scripts/build-cjs.mjs so both module formats have identical
 * behavior.
 */

export const CODE = Object.freeze({
  INVALID_INPUT: 'ERR_CORSCAGE_INVALID_INPUT',
  INVALID_OPTIONS: 'ERR_CORSCAGE_INVALID_OPTIONS',
  UNSAFE_CONFIG: 'ERR_CORSCAGE_UNSAFE_CONFIG'
});

export const LINT_CODES = Object.freeze({
  CONFIG_INVALID: 'CORS_CONFIG_INVALID',
  UNKNOWN_OPTION: 'CORS_UNKNOWN_OPTION',
  WILDCARD_WITH_CREDENTIALS: 'CORS_WILDCARD_WITH_CREDENTIALS',
  NULL_ORIGIN_ALLOWED: 'CORS_NULL_ORIGIN_ALLOWED',
  REFLECT_ALL_ORIGINS: 'CORS_REFLECT_ALL_ORIGINS',
  INSECURE_HTTP_WITH_CREDENTIALS: 'CORS_INSECURE_HTTP_WITH_CREDENTIALS',
  INSECURE_HTTP_ORIGIN: 'CORS_INSECURE_HTTP_ORIGIN',
  OVERBROAD_SUBDOMAIN_WILDCARD: 'CORS_OVERBROAD_SUBDOMAIN_WILDCARD',
  EXCESSIVE_MAX_AGE: 'CORS_EXCESSIVE_MAX_AGE',
  INVALID_MAX_AGE: 'CORS_INVALID_MAX_AGE',
  PRIVATE_NETWORK_WITH_WILDCARD: 'CORS_PRIVATE_NETWORK_WITH_WILDCARD',
  UNSAFE_EXPOSE_HEADER: 'CORS_UNSAFE_EXPOSE_HEADER',
  UNSAFE_ALLOWED_HEADER: 'CORS_UNSAFE_ALLOWED_HEADER',
  INVALID_ORIGIN_ENTRY: 'CORS_INVALID_ORIGIN_ENTRY',
  INVALID_HEADER_ENTRY: 'CORS_INVALID_HEADER_ENTRY',
  INVALID_METHOD_ENTRY: 'CORS_INVALID_METHOD_ENTRY',
  DUPLICATE_ORIGIN: 'CORS_DUPLICATE_ORIGIN',
  NO_ORIGINS_CONFIGURED: 'CORS_NO_ORIGINS_CONFIGURED',
  REDUNDANT_ORIGIN_ENTRY: 'CORS_REDUNDANT_ORIGIN_ENTRY'
});

export class CorsCageError extends Error {
  constructor(code, reason, input, findings, cause) {
    super(code + ': ' + reason);
    this.name = 'CorsCageError';
    this.code = code;
    this.reason = reason;
    this.input = input;
    if (findings !== undefined) this.findings = findings;
    if (cause !== undefined) this.cause = cause;
  }

  toJSON() {
    const output = {
      name: this.name,
      code: this.code,
      reason: this.reason,
      input: this.input
    };
    if (this.findings !== undefined) output.findings = this.findings;
    return output;
  }
}

function throwError(code, reason, input, findings, cause) {
  throw new CorsCageError(code, reason, input, findings, cause);
}

function configError(reason, input) {
  throwError(CODE.INVALID_OPTIONS, reason, input);
}

const MAX_ORIGIN_LENGTH = 320;
const MAX_METHOD_LENGTH = 64;
const MAX_HEADER_NAME_LENGTH = 128;
const DEFAULT_METHODS = Object.freeze(['GET', 'HEAD', 'POST']);
const DEFAULT_MAX_AGE = 600;
const MAX_MAX_AGE = 86400;
const DEFAULT_MAX_REQUEST_HEADERS = 32;
const DEFAULT_MAX_REQUEST_HEADERS_BYTES = 2048;
const MAX_REQUEST_HEADERS_LIMIT = 128;
const MAX_REQUEST_HEADER_BYTES_LIMIT = 16384;
const TOKEN_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const VISIBLE_ASCII_RE = /^[\x21-\x7e]+$/;
const SCHEME_AUTHORITY_RE = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/(.*)$/;
const DOMAIN_LABEL_RE = /^[a-z0-9-]+$/;
const NUMERIC_HOST_RE = /^[0-9.]+$/;
const HEX_GROUP_RE = /^[0-9a-fA-F]{1,4}$/;
const DEFAULT_PORTS = Object.freeze({ http: 80, https: 443 });
const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const DANGEROUS_METHODS = new Set(['TRACE', 'CONNECT']);
const HARD_FORBIDDEN_REQUEST_HEADERS = new Set([
  'access-control-request-headers',
  'access-control-request-method',
  'access-control-request-private-network',
  'connection',
  'content-length',
  'host',
  'keep-alive',
  'origin',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'via'
]);
const BROWSER_FORBIDDEN_REQUEST_HEADERS = new Set([
  'accept-charset',
  'accept-encoding',
  'cookie',
  'cookie2',
  'date',
  'dnt',
  'expect',
  'referer'
]);
const FORBIDDEN_EXPOSE_HEADERS = new Set(['set-cookie', 'set-cookie2']);
const CORS_RESPONSE_HEADERS = Object.freeze([
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'access-control-allow-methods',
  'access-control-allow-headers',
  'access-control-expose-headers',
  'access-control-max-age',
  'access-control-allow-private-network'
]);
const KNOWN_OPTION_KEYS = new Set([
  'allowedOrigins',
  'credentials',
  'methods',
  'allowedHeaders',
  'exposeHeaders',
  'maxAge',
  'allowNullOrigin',
  'allowHttpLocalhost',
  'multiLevelSubdomain',
  'allowPrivateNetwork',
  'rejectDisallowedPreflight',
  'originPredicate',
  'maxRequestHeaders',
  'maxRequestHeadersBytes',
  'allowForbiddenHeaders'
]);
const BOOLEAN_OPTION_KEYS = Object.freeze([
  'credentials',
  'allowNullOrigin',
  'allowHttpLocalhost',
  'multiLevelSubdomain',
  'allowPrivateNetwork',
  'rejectDisallowedPreflight',
  'allowForbiddenHeaders'
]);
const PUBLIC_SUFFIX_AGGREGATORS = new Set([
  'ac', 'co', 'com', 'edu', 'go', 'gob', 'gov', 'mil', 'ne', 'net',
  'or', 'org', 'sch'
]);
const KNOWN_PUBLIC_SUFFIXES = new Set([
  'ac.uk', 'co.uk', 'gov.uk', 'ltd.uk', 'me.uk', 'net.uk', 'nhs.uk',
  'org.uk', 'plc.uk', 'police.uk', 'sch.uk',
  'com.au', 'edu.au', 'gov.au', 'net.au', 'org.au',
  'co.jp', 'ac.jp', 'go.jp', 'ne.jp', 'or.jp',
  'com.cn', 'edu.cn', 'gov.cn', 'net.cn', 'org.cn',
  'com.br', 'net.br', 'org.br',
  'com.mx', 'org.mx', 'gob.mx',
  'co.nz', 'org.nz', 'net.nz', 'ac.nz', 'govt.nz',
  'co.in', 'firm.in', 'net.in', 'org.in', 'gen.in', 'ind.in',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg',
  'com.hk', 'net.hk', 'org.hk', 'gov.hk',
  'co.kr', 'ne.kr', 'or.kr', 'go.kr',
  'com.tw', 'org.tw', 'net.tw',
  'com.tr', 'org.tr', 'net.tr',
  'github.io', 'gitlab.io', 'pages.dev', 'vercel.app', 'netlify.app',
  'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 'workers.dev',
  'web.app', 'firebaseapp.com', 'appspot.com', 'amazonaws.com'
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isAsyncFunction(value) {
  return typeof value === 'function' &&
    value.constructor &&
    value.constructor.name === 'AsyncFunction';
}

function freezeObject(value) {
  return Object.freeze(value);
}

function invalidOrigin(code, reason) {
  return freezeObject({
    valid: false,
    isNull: false,
    normalized: null,
    scheme: null,
    host: null,
    port: null,
    explicitPort: null,
    isDefaultPort: false,
    hostType: null,
    isLocalhost: false,
    code,
    reason
  });
}

function nullOrigin() {
  return freezeObject({
    valid: true,
    isNull: true,
    normalized: 'null',
    scheme: null,
    host: null,
    port: null,
    explicitPort: null,
    isDefaultPort: false,
    hostType: null,
    isLocalhost: false,
    code: 'CORS_ORIGIN_NULL',
    reason: 'the origin is the opaque value null'
  });
}

function validOrigin(parts) {
  return freezeObject({
    valid: true,
    isNull: false,
    normalized: parts.normalized,
    scheme: parts.scheme,
    host: parts.host,
    port: parts.port,
    explicitPort: parts.explicitPort,
    isDefaultPort: parts.isDefaultPort,
    hostType: parts.hostType,
    isLocalhost: parts.isLocalhost,
    code: 'CORS_ORIGIN_VALID',
    reason: 'the origin is syntactically valid'
  });
}

function splitSchemeAuthority(input) {
  const match = SCHEME_AUTHORITY_RE.exec(input);
  if (!match) return null;
  return { scheme: match[1].toLowerCase(), authority: match[2] };
}

function parsePortText(text) {
  if (text === undefined) {
    return { valid: true, explicit: false, port: null, reason: null };
  }
  if (text.length === 0) {
    return { valid: false, explicit: true, port: null, reason: 'the port is empty' };
  }
  if (!/^\d+$/.test(text)) {
    return { valid: false, explicit: true, port: null, reason: 'the port contains non-digits' };
  }
  if (text.length > 1 && text.charAt(0) === '0') {
    return { valid: false, explicit: true, port: null, reason: 'the port has a leading zero' };
  }
  if (text.length > 5) {
    return { valid: false, explicit: true, port: null, reason: 'the port is too long' };
  }
  const port = Number(text);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    return { valid: false, explicit: true, port: null, reason: 'the port is outside 1 through 65535' };
  }
  return { valid: true, explicit: true, port, reason: null };
}


function ipv4NumberLenient(text) {
  if (text.length === 0) return null;
  if (text.startsWith('0x') || text.startsWith('0X')) {
    const rest = text.slice(2);
    if (rest.length === 0) return 0;
    if (!/^[0-9a-fA-F]+$/.test(rest)) return null;
    return parseInt(rest, 16);
  }
  if (text.length > 1 && text.startsWith('0')) {
    if (!/^[0-7]+$/.test(text)) return null;
    return parseInt(text, 8);
  }
  if (!/^\d+$/.test(text)) return null;
  return Number(text);
}

function parseIPv4Parts(text) {
  const pieces = text.split('.');
  if (pieces.length !== 4) return null;
  const output = [];
  for (const piece of pieces) {
    if (!/^\d{1,3}$/.test(piece)) return null;
    if (piece.length > 1 && piece.charAt(0) === '0') return null;
    const value = Number(piece);
    if (value > 255) return null;
    output.push(value);
  }
  return output;
}

function parseIPv6Side(text, state) {
  if (text === '') return [];
  const rawParts = text.split(':');
  const output = [];
  for (let index = 0; index < rawParts.length; index += 1) {
    const part = rawParts[index];
    if (part === '') return null;
    if (part.includes('.')) {
      if (index !== rawParts.length - 1 || state.ipv4Used) return null;
      const ipv4 = parseIPv4Parts(part);
      if (ipv4 === null) return null;
      state.ipv4Used = true;
      output.push((ipv4[0] << 8) + ipv4[1]);
      output.push((ipv4[2] << 8) + ipv4[3]);
    } else {
      if (!HEX_GROUP_RE.test(part)) return null;
      output.push(parseInt(part, 16));
    }
  }
  return output;
}

function parseIPv6(text) {
  if (text.length === 0 || text.length > 45) return null;
  if (!/^[0-9a-fA-F:.]+$/.test(text)) return null;
  const compression = text.split('::');
  if (compression.length > 2) return null;
  const state = { ipv4Used: false };
  if (compression.length === 1) {
    const groups = parseIPv6Side(text, state);
    if (groups === null || groups.length !== 8) return null;
    return groups;
  }
  const left = parseIPv6Side(compression[0], state);
  const right = parseIPv6Side(compression[1], state);
  if (left === null || right === null) return null;
  const present = left.length + right.length;
  if (present >= 8) return null;
  const zeros = [];
  for (let index = 0; index < 8 - present; index += 1) zeros.push(0);
  return left.concat(zeros, right);
}

function serializeIPv6(groups) {
  let bestStart = -1;
  let bestLength = 0;
  let currentStart = -1;
  let currentLength = 0;
  for (let index = 0; index < 8; index += 1) {
    if (groups[index] === 0) {
      if (currentStart === -1) currentStart = index;
      currentLength += 1;
    } else {
      if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
      }
      currentStart = -1;
      currentLength = 0;
    }
  }
  if (currentLength > bestLength) {
    bestStart = currentStart;
    bestLength = currentLength;
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestLength < 2) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLength).join(':');
  if (left === '' && right === '') return '::';
  if (left === '') return '::' + right;
  if (right === '') return left + '::';
  return left + '::' + right;
}

function normalizeDomainOrIPv4(host) {
  if (host.length === 0) return { valid: false, reason: 'the host is empty' };
  if (host.length > 253) return { valid: false, reason: 'the host is too long' };
  const lower = host.toLowerCase();
  if (lower.endsWith('.')) {
    return { valid: false, reason: 'a trailing root dot is not accepted' };
  }
  const labels = lower.split('.');
  for (const label of labels) {
    if (label.length === 0) return { valid: false, reason: 'the host contains an empty label' };
    if (label.length > 63) return { valid: false, reason: 'a host label is too long' };
    if (!DOMAIN_LABEL_RE.test(label)) return { valid: false, reason: 'a host label contains a prohibited character' };
    if (label.startsWith('-') || label.endsWith('-')) {
      return { valid: false, reason: 'a host label starts or ends with a hyphen' };
    }
  }
  const finalLabel = labels[labels.length - 1];
  const browserWouldParseIPv4 = NUMERIC_HOST_RE.test(lower) || ipv4NumberLenient(finalLabel) !== null;
  if (browserWouldParseIPv4) {
    const ipv4 = parseIPv4Parts(lower);
    if (ipv4 === null) return { valid: false, reason: 'the IPv4 literal is malformed or obfuscated' };
    return {
      valid: true,
      host: ipv4.join('.'),
      hostType: 'ipv4',
      labels
    };
  }
  return {
    valid: true,
    host: lower,
    hostType: 'domain',
    labels
  };
}

function parseAuthority(authority) {
  if (authority.length === 0) return { valid: false, reason: 'the host is empty' };
  if (authority.includes('@')) return { valid: false, reason: 'userinfo is prohibited in an origin' };
  if (authority.includes('%')) return { valid: false, reason: 'percent encoding is prohibited in an origin' };
  if (authority.includes('/') || authority.includes('\\') || authority.includes('?') || authority.includes('#')) {
    return { valid: false, reason: 'an origin must not contain a path, query, fragment or backslash' };
  }

  let hostText;
  let portText;
  if (authority.startsWith('[')) {
    const closing = authority.indexOf(']');
    if (closing === -1) return { valid: false, reason: 'the IPv6 literal is missing a closing bracket' };
    hostText = authority.slice(1, closing);
    const remainder = authority.slice(closing + 1);
    if (remainder === '') {
      portText = undefined;
    } else if (remainder.startsWith(':')) {
      portText = remainder.slice(1);
    } else {
      return { valid: false, reason: 'unexpected text after the IPv6 literal' };
    }
    const groups = parseIPv6(hostText);
    if (groups === null) return { valid: false, reason: 'the IPv6 literal is malformed' };
    const serialized = '[' + serializeIPv6(groups) + ']';
    const port = parsePortText(portText);
    if (!port.valid) return { valid: false, reason: port.reason };
    return {
      valid: true,
      host: serialized,
      hostType: 'ipv6',
      labels: [],
      port
    };
  }

  if (authority.includes('[') || authority.includes(']')) {
    return { valid: false, reason: 'IPv6 literals must be bracketed' };
  }
  const colonCount = authority.split(':').length - 1;
  if (colonCount > 1) return { valid: false, reason: 'an IPv6 literal must be bracketed' };
  if (colonCount === 1) {
    const index = authority.lastIndexOf(':');
    hostText = authority.slice(0, index);
    portText = authority.slice(index + 1);
  } else {
    hostText = authority;
    portText = undefined;
  }
  const host = normalizeDomainOrIPv4(hostText);
  if (!host.valid) return host;
  const port = parsePortText(portText);
  if (!port.valid) return { valid: false, reason: port.reason };
  return {
    valid: true,
    host: host.host,
    hostType: host.hostType,
    labels: host.labels,
    port
  };
}

function isLocalHostPart(host, hostType) {
  if (hostType === 'ipv4') return host.startsWith('127.');
  if (hostType === 'ipv6') return host === '[::1]';
  return host === 'localhost' || host.endsWith('.localhost');
}

export function parseOrigin(input) {
  if (typeof input !== 'string') {
    return invalidOrigin('CORS_ORIGIN_TYPE', 'the origin must be a string');
  }
  if (input.length === 0) {
    return invalidOrigin('CORS_ORIGIN_EMPTY', 'the origin is empty');
  }
  if (input.length > MAX_ORIGIN_LENGTH) {
    return invalidOrigin('CORS_ORIGIN_TOO_LONG', 'the origin exceeds the strict length cap');
  }
  if (input !== input.trim()) {
    return invalidOrigin('CORS_ORIGIN_WHITESPACE', 'the origin has leading or trailing whitespace');
  }
  if (!VISIBLE_ASCII_RE.test(input)) {
    return invalidOrigin('CORS_ORIGIN_NON_ASCII', 'the origin contains whitespace, control or non-ASCII characters');
  }
  if (input === 'null') return nullOrigin();
  if (input.includes(',')) {
    return invalidOrigin('CORS_ORIGIN_MULTIPLE', 'multiple comma-separated origins are prohibited');
  }
  const split = splitSchemeAuthority(input);
  if (split === null) {
    return invalidOrigin('CORS_ORIGIN_MALFORMED', 'the origin must use scheme://host form');
  }
  if (split.scheme !== 'http' && split.scheme !== 'https') {
    return invalidOrigin('CORS_ORIGIN_SCHEME', 'only http and https origins are supported');
  }
  if (split.authority.length === 0) {
    return invalidOrigin('CORS_ORIGIN_HOST_EMPTY', 'the origin host is empty');
  }
  if (split.authority !== split.authority.trim() || split.authority.includes(' ')) {
    return invalidOrigin('CORS_ORIGIN_WHITESPACE', 'the origin contains whitespace');
  }
  const authority = parseAuthority(split.authority);
  if (!authority.valid) {
    return invalidOrigin('CORS_ORIGIN_MALFORMED', authority.reason);
  }
  const defaultPort = DEFAULT_PORTS[split.scheme];
  const explicitPort = authority.port.explicit ? authority.port.port : null;
  const effectivePort = explicitPort === null ? defaultPort : explicitPort;
  const isDefaultPort = effectivePort === defaultPort;
  const serializedPort = explicitPort !== null && !isDefaultPort ? ':' + String(explicitPort) : '';
  return validOrigin({
    normalized: split.scheme + '://' + authority.host + serializedPort,
    scheme: split.scheme,
    host: authority.host,
    port: effectivePort,
    explicitPort,
    isDefaultPort,
    hostType: authority.hostType,
    isLocalhost: isLocalHostPart(authority.host, authority.hostType)
  });
}

export function normalizeOrigin(input) {
  const parsed = parseOrigin(input);
  return parsed.valid ? parsed.normalized : null;
}

function invalidPattern(reason) {
  return { valid: false, reason };
}

function parseOriginPattern(input) {
  if (typeof input !== 'string' || input.length === 0) {
    return invalidPattern('an origin entry must be a non-empty string');
  }
  if (input === '*') {
    return { valid: true, type: 'any', key: '*' };
  }
  if (input === 'null') {
    return invalidPattern('the null origin is controlled only by allowNullOrigin');
  }
  const wildcardCount = input.split('*').length - 1;
  if (wildcardCount === 0) {
    const exact = parseOrigin(input);
    if (!exact.valid || exact.isNull) return invalidPattern(exact.reason || 'the exact origin is malformed');
    return { valid: true, type: 'exact', key: exact.normalized, origin: exact };
  }
  if (wildcardCount !== 1) return invalidPattern('only one subdomain wildcard marker is permitted');
  const split = splitSchemeAuthority(input);
  if (split === null) return invalidPattern('a wildcard origin must use scheme://host form');
  if (split.scheme !== 'http' && split.scheme !== 'https') {
    return invalidPattern('only http and https wildcard origins are supported');
  }
  if (!split.authority.startsWith('*.')) {
    return invalidPattern('the wildcard must replace the complete leftmost host label');
  }
  if (split.authority.indexOf('*', 2) !== -1) {
    return invalidPattern('the wildcard may only appear as the leftmost host label');
  }
  const baseAuthority = split.authority.slice(2);
  if (baseAuthority.length === 0) return invalidPattern('the wildcard base host is empty');
  const authority = parseAuthority(baseAuthority);
  if (!authority.valid) return invalidPattern(authority.reason);
  if (authority.hostType !== 'domain') return invalidPattern('wildcards are valid only before domain names');
  const defaultPort = DEFAULT_PORTS[split.scheme];
  const explicitPort = authority.port.explicit ? authority.port.port : null;
  const effectivePort = explicitPort === null ? defaultPort : explicitPort;
  const serializedPort = explicitPort !== null && effectivePort !== defaultPort ? ':' + String(explicitPort) : '';
  const baseOrigin = split.scheme + '://' + authority.host + serializedPort;
  return {
    valid: true,
    type: 'subdomain',
    key: split.scheme + '://*.' + authority.host + serializedPort,
    scheme: split.scheme,
    host: authority.host,
    port: effectivePort,
    explicitPort,
    isDefaultPort: effectivePort === defaultPort,
    baseOrigin,
    isLocalhost: isLocalHostPart(authority.host, 'domain')
  };
}

function isOverbroadWildcardBase(host) {
  const labels = host.split('.');
  if (labels.length < 2) return true;
  const joined = labels.join('.');
  if (KNOWN_PUBLIC_SUFFIXES.has(joined)) return true;
  const finalLabel = labels[labels.length - 1];
  const previousLabel = labels[labels.length - 2];
  if (finalLabel.length === 2 && PUBLIC_SUFFIX_AGGREGATORS.has(previousLabel)) return true;
  if (host === 'localhost') return true;
  return false;
}

function matchesParsedPattern(parsed, pattern, multiLevelSubdomain) {
  if (!parsed.valid || parsed.isNull) return false;
  if (pattern.type === 'any') return true;
  if (pattern.type === 'exact') return parsed.normalized === pattern.key;
  if (parsed.scheme !== pattern.scheme || parsed.port !== pattern.port) return false;
  if (parsed.hostType !== 'domain') return false;
  const suffix = '.' + pattern.host;
  if (!parsed.host.endsWith(suffix)) return false;
  const prefix = parsed.host.slice(0, parsed.host.length - suffix.length);
  if (prefix.length === 0) return false;
  const labels = prefix.split('.');
  if (!multiLevelSubdomain && labels.length !== 1) return false;
  for (const label of labels) {
    if (label.length === 0) return false;
  }
  return true;
}

export function matchOrigin(candidate, pattern, options) {
  if (options !== undefined && !isPlainObject(options)) {
    configError('matchOrigin options must be a plain object', options);
  }
  const multiLevelSubdomain = options && options.multiLevelSubdomain === true;
  if (options !== undefined) {
    for (const key of Object.keys(options)) {
      if (key !== 'multiLevelSubdomain') configError('unknown matchOrigin option ' + key, options);
    }
  }
  const parsed = parseOrigin(candidate);
  const compiled = parseOriginPattern(pattern);
  if (!compiled.valid) return false;
  if (compiled.type === 'subdomain' && isOverbroadWildcardBase(compiled.host)) return false;
  if (parsed.scheme === 'http' && (!parsed.isLocalhost || compiled.type !== 'exact')) return false;
  return matchesParsedPattern(parsed, compiled, multiLevelSubdomain);
}

function isHttpSchemeUseAllowed(config, parsed, pattern) {
  if (parsed.scheme === 'https') return true;
  if (parsed.scheme !== 'http') return false;
  if (!parsed.isLocalhost) return false;
  if (config.allowHttpLocalhost) return true;
  return Boolean(pattern && pattern.type === 'exact' && pattern.origin.scheme === 'http' && pattern.origin.isLocalhost);
}

function arrayOption(value, label) {
  if (value === undefined) return [];
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) configError(label + ' must be a string or an array of strings', value);
  return value.slice();
}

function booleanOption(config, key, value, fallback) {
  if (value === undefined) {
    config[key] = fallback;
    return;
  }
  if (typeof value !== 'boolean') configError(key + ' must be a boolean', value);
  config[key] = value;
}

function assertNoReservedKeys(object, label) {
  for (const key of Object.keys(object)) {
    if (RESERVED_KEYS.has(key)) configError(label + ' contains a reserved object key', key);
  }
}

function validateMethod(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_METHOD_LENGTH || !TOKEN_RE.test(value)) {
    return null;
  }
  if (value === '*') return null;
  if (DANGEROUS_METHODS.has(value.toUpperCase())) return null;
  return value;
}

function normalizeMethods(input) {
  const values = input === undefined ? DEFAULT_METHODS.slice() : arrayOption(input, 'methods');
  const output = [];
  const seen = new Set();
  for (const value of values) {
    const method = validateMethod(value);
    if (method === null) configError('methods entries must be safe RFC 9110 method tokens and must not be TRACE or CONNECT', value);
    if (!seen.has(method)) {
      seen.add(method);
      output.push(method);
    }
  }
  if (output.length === 0) configError('methods must contain at least one method', input);
  return Object.freeze(output);
}

function validateHeaderName(value) {
  if (typeof value !== 'string') return null;
  if (value.length === 0 || value.length > MAX_HEADER_NAME_LENGTH) return null;
  const lower = value.toLowerCase();
  if (!TOKEN_RE.test(lower)) return null;
  return lower;
}

function isPrefixedForbiddenHeader(lower) {
  return lower.startsWith('sec-') || lower.startsWith('proxy-');
}

function headerIsHardForbidden(lower) {
  return HARD_FORBIDDEN_REQUEST_HEADERS.has(lower);
}

function headerIsBrowserForbidden(lower) {
  return BROWSER_FORBIDDEN_REQUEST_HEADERS.has(lower) || isPrefixedForbiddenHeader(lower);
}

function normalizeAllowedHeaders(input, allowForbiddenHeaders) {
  const values = arrayOption(input, 'allowedHeaders');
  const output = [];
  const seen = new Set();
  for (const value of values) {
    const lower = validateHeaderName(value);
    if (lower === null || lower === '*') configError('allowedHeaders entries must be legal HTTP header names', value);
    if (headerIsHardForbidden(lower)) {
      configError('allowedHeaders cannot include protocol, hop-by-hop or CORS control headers', value);
    }
    if (headerIsBrowserForbidden(lower) && !allowForbiddenHeaders) {
      configError('allowedHeaders cannot include browser-forbidden headers without allowForbiddenHeaders', value);
    }
    if (!seen.has(lower)) {
      seen.add(lower);
      output.push(lower);
    }
  }
  return Object.freeze(output);
}

function normalizeExposeHeaders(input) {
  const values = arrayOption(input, 'exposeHeaders');
  const output = [];
  const seen = new Set();
  for (const value of values) {
    const lower = validateHeaderName(value);
    if (lower === null || lower === '*') configError('exposeHeaders entries must be legal HTTP header names', value);
    if (FORBIDDEN_EXPOSE_HEADERS.has(lower)) {
      configError('exposeHeaders cannot expose Set-Cookie response headers', value);
    }
    if (!seen.has(lower)) {
      seen.add(lower);
      output.push(lower);
    }
  }
  return Object.freeze(output);
}

function normalizePositiveInteger(value, key, fallback, minimum, maximum) {
  if (value === undefined) return fallback;
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    configError(key + ' must be a safe integer within its supported range', value);
  }
  return value;
}

function originPatternSortKey(pattern) {
  return pattern.type + '|' + pattern.key;
}

function normalizeOriginEntries(input, config) {
  const values = arrayOption(input, 'allowedOrigins');
  const output = [];
  const seen = new Set();
  for (const value of values) {
    if (typeof value !== 'string') {
      configError('allowedOrigins entries must be strings; booleans, regular expressions and objects are prohibited', value);
    }
    const pattern = parseOriginPattern(value);
    if (!pattern.valid) configError('invalid allowedOrigins entry: ' + pattern.reason, value);
    if (pattern.type === 'any' && config.credentials) {
      configError('the wildcard * origin can never be combined with credentials', value);
    }
    if (pattern.type === 'subdomain' && isOverbroadWildcardBase(pattern.host)) {
      configError('the subdomain wildcard base is a public suffix or otherwise overbroad', value);
    }
    const patternScheme = pattern.type === 'exact' ? pattern.origin.scheme : pattern.scheme;
    if (pattern.type !== 'any' && patternScheme === 'http') {
      const probe = pattern.type === 'exact' ? pattern.origin : {
        scheme: pattern.scheme,
        isLocalhost: pattern.isLocalhost
      };
      if (!probe.isLocalhost) {
        configError('insecure http origins are rejected except explicit localhost development origins', value);
      }
      if (pattern.type === 'subdomain' && !config.allowHttpLocalhost) {
        configError('http localhost subdomain wildcards require allowHttpLocalhost', value);
      }
    }
    if (!seen.has(originPatternSortKey(pattern))) {
      seen.add(originPatternSortKey(pattern));
      output.push(Object.freeze(pattern));
    }
  }
  return Object.freeze(output);
}

function normalizeConfig(options) {
  if (options === undefined) options = {};
  if (!isPlainObject(options)) configError('options must be a plain object', options);
  assertNoReservedKeys(options, 'options');
  for (const key of Object.keys(options)) {
    if (!KNOWN_OPTION_KEYS.has(key)) configError('unknown option ' + key, options);
  }

  const config = Object.create(null);
  booleanOption(config, 'credentials', options.credentials, false);
  booleanOption(config, 'allowNullOrigin', options.allowNullOrigin, false);
  booleanOption(config, 'allowHttpLocalhost', options.allowHttpLocalhost, false);
  booleanOption(config, 'multiLevelSubdomain', options.multiLevelSubdomain, false);
  booleanOption(config, 'allowPrivateNetwork', options.allowPrivateNetwork, false);
  booleanOption(config, 'rejectDisallowedPreflight', options.rejectDisallowedPreflight, true);
  booleanOption(config, 'allowForbiddenHeaders', options.allowForbiddenHeaders, false);

  if (config.allowNullOrigin && config.credentials) {
    configError('the null origin can never be allowed when credentials are enabled', options.allowNullOrigin);
  }
  config.maxAge = normalizePositiveInteger(options.maxAge, 'maxAge', DEFAULT_MAX_AGE, 0, MAX_MAX_AGE);
  config.maxRequestHeaders = normalizePositiveInteger(
    options.maxRequestHeaders,
    'maxRequestHeaders',
    DEFAULT_MAX_REQUEST_HEADERS,
    1,
    MAX_REQUEST_HEADERS_LIMIT
  );
  config.maxRequestHeadersBytes = normalizePositiveInteger(
    options.maxRequestHeadersBytes,
    'maxRequestHeadersBytes',
    DEFAULT_MAX_REQUEST_HEADERS_BYTES,
    128,
    MAX_REQUEST_HEADER_BYTES_LIMIT
  );
  config.methods = normalizeMethods(options.methods);
  config.allowedHeaders = normalizeAllowedHeaders(options.allowedHeaders, config.allowForbiddenHeaders);
  config.exposeHeaders = normalizeExposeHeaders(options.exposeHeaders);
  config.originPredicate = null;
  if (options.originPredicate !== undefined) {
    if (typeof options.originPredicate !== 'function') {
      configError('originPredicate must be a synchronous function', options.originPredicate);
    }
    if (isAsyncFunction(options.originPredicate)) {
      configError('originPredicate must be synchronous, not async', options.originPredicate);
    }
    config.originPredicate = options.originPredicate;
  }
  config.allowedOrigins = normalizeOriginEntries(options.allowedOrigins, config);
  if (config.allowPrivateNetwork && config.allowedOrigins.some((pattern) => pattern.type === 'any')) {
    configError('Private Network Access can never be combined with the universal wildcard origin', options.allowedOrigins);
  }
  return Object.freeze(config);
}

function publicConfig(config) {
  return Object.freeze({
    allowedOrigins: config.allowedOrigins.map((pattern) => pattern.key).sort(),
    credentials: config.credentials,
    methods: config.methods.slice(),
    allowedHeaders: config.allowedHeaders.slice(),
    exposeHeaders: config.exposeHeaders.slice(),
    maxAge: config.maxAge,
    allowNullOrigin: config.allowNullOrigin,
    allowHttpLocalhost: config.allowHttpLocalhost,
    multiLevelSubdomain: config.multiLevelSubdomain,
    allowPrivateNetwork: config.allowPrivateNetwork,
    rejectDisallowedPreflight: config.rejectDisallowedPreflight,
    maxRequestHeaders: config.maxRequestHeaders,
    maxRequestHeadersBytes: config.maxRequestHeadersBytes,
    allowForbiddenHeaders: config.allowForbiddenHeaders,
    hasOriginPredicate: config.originPredicate !== null
  });
}

function requestHeadersObject(requestLike) {
  if (!isPlainObject(requestLike) && (requestLike === null || typeof requestLike !== 'object')) {
    return null;
  }
  return requestLike.headers || null;
}

function rawHeader(requestLike, name) {
  const headers = requestHeadersObject(requestLike);
  if (headers === null || headers === undefined) return undefined;
  const lowerName = name.toLowerCase();
  if (typeof headers.get === 'function') {
    const value = headers.get(lowerName);
    return value === null ? undefined : value;
  }
  if (!isPlainObject(headers) && typeof headers !== 'object') return undefined;
  let found;
  let count = 0;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lowerName) {
      found = headers[key];
      count += 1;
    }
  }
  if (count > 1) return [found, found];
  return found;
}

function headerState(raw) {
  if (raw === undefined || raw === null) {
    return { present: false, valid: false, multiple: false, value: null };
  }
  if (Array.isArray(raw)) {
    if (raw.length !== 1 || typeof raw[0] !== 'string') {
      return { present: true, valid: false, multiple: true, value: null };
    }
    return { present: true, valid: true, multiple: false, value: raw[0] };
  }
  if (typeof raw !== 'string') {
    return { present: true, valid: false, multiple: false, value: null };
  }
  return { present: true, valid: true, multiple: false, value: raw };
}

function evaluationResult(fields) {
  return Object.freeze({
    allowed: fields.allowed,
    isPreflight: fields.isPreflight,
    statusCode: fields.statusCode,
    headers: Object.freeze(Object.assign({}, fields.headers)),
    vary: Object.freeze(fields.vary.slice()),
    reason: fields.reason,
    code: fields.code,
    origin: fields.origin === undefined ? null : fields.origin,
    removeHeaders: Object.freeze(CORS_RESPONSE_HEADERS.slice())
  });
}

function baseVary(isPreflight) {
  const output = ['Origin'];
  if (isPreflight) {
    output.push('Access-Control-Request-Method');
    output.push('Access-Control-Request-Headers');
    output.push('Access-Control-Request-Private-Network');
  }
  return output;
}

function denyResult(isPreflight, code, reason, origin) {
  return evaluationResult({
    allowed: false,
    isPreflight,
    statusCode: isPreflight ? 403 : null,
    headers: {},
    vary: baseVary(isPreflight),
    reason,
    code,
    origin
  });
}

function parseRequestMethod(requestLike) {
  if (requestLike && typeof requestLike.method === 'string' && requestLike.method.length > 0) {
    return requestLike.method;
  }
  return 'GET';
}

function authorizeParsedOrigin(config, parsed) {
  if (parsed.isNull) {
    if (!config.allowNullOrigin) {
      return { allowed: false, code: 'CORS_NULL_ORIGIN', reason: 'the null origin is blocked by default', wildcard: false };
    }
    if (config.credentials) {
      return { allowed: false, code: 'CORS_NULL_ORIGIN_WITH_CREDENTIALS', reason: 'the null origin can never use credentials', wildcard: false };
    }
    return { allowed: true, code: 'CORS_ORIGIN_ALLOWED', reason: 'the explicitly configured null origin is allowed', wildcard: false };
  }

  let matched = null;
  let universalMatch = null;
  for (const pattern of config.allowedOrigins) {
    if (!matchesParsedPattern(parsed, pattern, config.multiLevelSubdomain)) continue;
    if (pattern.type === 'any') {
      if (universalMatch === null) universalMatch = pattern;
    } else {
      matched = pattern;
      break;
    }
  }
  if (matched === null) matched = universalMatch;
  if (matched !== null) {
    if (!isHttpSchemeUseAllowed(config, parsed, matched)) {
      return { allowed: false, code: 'CORS_INSECURE_HTTP_ORIGIN', reason: 'insecure http is limited to explicit localhost development use', wildcard: false };
    }
    return {
      allowed: true,
      code: 'CORS_ORIGIN_ALLOWED',
      reason: 'the origin matches the configured allowlist',
      wildcard: matched.type === 'any'
    };
  }

  if (config.originPredicate !== null) {
    const schemeAllowed = parsed.scheme === 'https' || (parsed.scheme === 'http' && parsed.isLocalhost && config.allowHttpLocalhost);
    if (schemeAllowed) {
      let decision;
      try {
        decision = config.originPredicate(Object.freeze({
          origin: parsed.normalized,
          scheme: parsed.scheme,
          host: parsed.host,
          port: parsed.port,
          hostType: parsed.hostType,
          isLocalhost: parsed.isLocalhost
        }));
      } catch {
        decision = false;
      }
      if (decision === true) {
        return { allowed: true, code: 'CORS_ORIGIN_ALLOWED', reason: 'the synchronous origin predicate authorized the origin', wildcard: false };
      }
      if (decision !== false) {
        return { allowed: false, code: 'CORS_PREDICATE_INVALID_RESULT', reason: 'the origin predicate did not return a boolean false or true', wildcard: false };
      }
    }
  }

  return { allowed: false, code: 'CORS_ORIGIN_NOT_ALLOWED', reason: 'the origin does not match the configured allowlist', wildcard: false };
}

function parseRequestedHeaders(rawState, config) {
  if (!rawState.present) {
    return { valid: true, headers: [], reason: null };
  }
  if (!rawState.valid) {
    return { valid: false, headers: null, reason: 'Access-Control-Request-Headers must be a single string header value' };
  }
  const raw = rawState.value;
  if (!/^[\x20-\x7e]*$/.test(raw)) {
    return { valid: false, headers: null, reason: 'Access-Control-Request-Headers contains control or non-ASCII characters' };
  }
  if (raw.length > config.maxRequestHeadersBytes) {
    return { valid: false, headers: null, reason: 'Access-Control-Request-Headers exceeds the configured byte cap' };
  }
  const pieces = raw.split(',');
  if (pieces.length > config.maxRequestHeaders) {
    return { valid: false, headers: null, reason: 'Access-Control-Request-Headers exceeds the configured count cap' };
  }
  const output = [];
  const seen = new Set();
  for (const piece of pieces) {
    const trimmed = piece.trim();
    if (trimmed.length === 0) {
      return { valid: false, headers: null, reason: 'Access-Control-Request-Headers contains an empty header name' };
    }
    const lower = validateHeaderName(trimmed);
    if (lower === null || lower === '*') {
      return { valid: false, headers: null, reason: 'Access-Control-Request-Headers contains a prohibited header token' };
    }
    if (!seen.has(lower)) {
      seen.add(lower);
      output.push(lower);
    }
  }
  if (output.length > config.maxRequestHeaders) {
    return { valid: false, headers: null, reason: 'Access-Control-Request-Headers exceeds the configured count cap' };
  }
  return { valid: true, headers: output, reason: null };
}

function validatePreflight(config, requestLike) {
  const methodState = headerState(rawHeader(requestLike, 'access-control-request-method'));
  if (!methodState.present || !methodState.valid) {
    return { valid: false, code: 'CORS_PREFLIGHT_METHOD_MALFORMED', reason: 'the preflight method header is missing, repeated or not a string' };
  }
  const requestedMethod = methodState.value;
  if (
    requestedMethod.length === 0 ||
    requestedMethod.length > MAX_METHOD_LENGTH ||
    !TOKEN_RE.test(requestedMethod) ||
    requestedMethod.includes(',') ||
    DANGEROUS_METHODS.has(requestedMethod.toUpperCase())
  ) {
    return { valid: false, code: 'CORS_PREFLIGHT_METHOD_MALFORMED', reason: 'the requested method is not a single safe RFC 9110 token' };
  }
  if (!config.methods.includes(requestedMethod)) {
    return { valid: false, code: 'CORS_METHOD_NOT_ALLOWED', reason: 'the requested method is not in the policy allowlist' };
  }

  const requestedHeaders = parseRequestedHeaders(headerState(rawHeader(requestLike, 'access-control-request-headers')), config);
  if (!requestedHeaders.valid) {
    return { valid: false, code: 'CORS_HEADERS_MALFORMED', reason: requestedHeaders.reason };
  }
  for (const header of requestedHeaders.headers) {
    if (!config.allowedHeaders.includes(header)) {
      return { valid: false, code: 'CORS_HEADERS_NOT_ALLOWED', reason: 'a requested header is not in the policy allowlist: ' + header };
    }
  }

  const privateNetworkState = headerState(rawHeader(requestLike, 'access-control-request-private-network'));
  let privateNetworkRequested = false;
  if (privateNetworkState.present) {
    if (!privateNetworkState.valid || privateNetworkState.value !== 'true' || privateNetworkState.value.includes(',')) {
      return { valid: false, code: 'CORS_PRIVATE_NETWORK_MALFORMED', reason: 'the private network request header must be the single value true' };
    }
    privateNetworkRequested = true;
    if (!config.allowPrivateNetwork) {
      return { valid: false, code: 'CORS_PRIVATE_NETWORK_DENIED', reason: 'private network access is denied by default' };
    }
  }
  return {
    valid: true,
    method: requestedMethod,
    headers: requestedHeaders.headers,
    privateNetworkRequested
  };
}

function corsResponseHeaders(config, parsed, authorization, preflight) {
  const headers = Object.create(null);
  headers['access-control-allow-origin'] = authorization.wildcard ? '*' : parsed.normalized;
  if (config.credentials) headers['access-control-allow-credentials'] = 'true';
  if (preflight === null) {
    if (config.exposeHeaders.length > 0) {
      headers['access-control-expose-headers'] = config.exposeHeaders.join(', ');
    }
    return headers;
  }
  headers['access-control-allow-methods'] = preflight.method;
  if (preflight.headers.length > 0) {
    headers['access-control-allow-headers'] = preflight.headers.join(', ');
  }
  headers['access-control-max-age'] = String(config.maxAge);
  if (preflight.privateNetworkRequested) {
    headers['access-control-allow-private-network'] = 'true';
  }
  return headers;
}

function evaluateWithConfig(config, requestLike) {
  if (requestLike === null || typeof requestLike !== 'object') {
    throwError(CODE.INVALID_INPUT, 'evaluate requires a request-like object', requestLike);
  }
  const method = parseRequestMethod(requestLike);
  const originState = headerState(rawHeader(requestLike, 'origin'));
  const acrmState = headerState(rawHeader(requestLike, 'access-control-request-method'));
  const isPreflight = method === 'OPTIONS' && originState.present && acrmState.present;

  if (!originState.present) {
    return evaluationResult({
      allowed: false,
      isPreflight: false,
      statusCode: null,
      headers: {},
      vary: baseVary(false),
      reason: 'the request has no Origin header and is not a CORS request',
      code: 'CORS_NO_ORIGIN',
      origin: null
    });
  }
  if (!originState.valid) {
    return denyResult(isPreflight, 'CORS_ORIGIN_MALFORMED', 'the Origin header is repeated or not a string', null);
  }

  const parsed = parseOrigin(originState.value);
  if (!parsed.valid) {
    return denyResult(isPreflight, parsed.code, parsed.reason, null);
  }
  const authorization = authorizeParsedOrigin(config, parsed);
  if (!authorization.allowed) {
    return denyResult(isPreflight, authorization.code, authorization.reason, parsed.normalized);
  }

  if (!isPreflight) {
    return evaluationResult({
      allowed: true,
      isPreflight: false,
      statusCode: null,
      headers: corsResponseHeaders(config, parsed, authorization, null),
      vary: baseVary(false),
      reason: authorization.reason,
      code: authorization.code,
      origin: parsed.normalized
    });
  }

  const preflight = validatePreflight(config, requestLike);
  if (!preflight.valid) {
    return denyResult(true, preflight.code, preflight.reason, parsed.normalized);
  }
  return evaluationResult({
    allowed: true,
    isPreflight: true,
    statusCode: 204,
    headers: corsResponseHeaders(config, parsed, authorization, preflight),
    vary: baseVary(true),
    reason: 'the preflight request is authorized',
    code: 'CORS_PREFLIGHT_ALLOWED',
    origin: parsed.normalized
  });
}

export function createCorsPolicy(options) {
  const config = normalizeConfig(options);
  const exposedConfig = publicConfig(config);
  function isAllowed(origin) {
    const parsed = parseOrigin(origin);
    if (!parsed.valid) return false;
    return authorizeParsedOrigin(config, parsed).allowed;
  }
  const policy = {
    config: exposedConfig,
    evaluate(requestLike) {
      return evaluateWithConfig(config, requestLike);
    },
    isOriginAllowed(origin) {
      return isAllowed(origin);
    },
    match(origin) {
      return isAllowed(origin);
    }
  };
  Object.freeze(policy.config);
  Object.freeze(policy.config.allowedOrigins);
  Object.freeze(policy.config.methods);
  Object.freeze(policy.config.allowedHeaders);
  Object.freeze(policy.config.exposeHeaders);
  return Object.freeze(policy);
}

export function mergeVary(existing, tokens) {
  const values = [];
  const seen = new Set();
  let hasStar = false;
  function addRaw(raw) {
    if (raw === undefined || raw === null) return;
    const list = Array.isArray(raw) ? raw : [raw];
    for (const item of list) {
      if (typeof item !== 'string') continue;
      for (const piece of item.split(',')) {
        const token = piece.trim();
        if (token === '*') {
          hasStar = true;
          continue;
        }
        if (!TOKEN_RE.test(token)) continue;
        const key = token.toLowerCase();
        if (!seen.has(key)) {
          seen.add(key);
          values.push(token);
        }
      }
    }
  }
  addRaw(existing);
  addRaw(tokens);
  if (hasStar) return '*';
  return values.join(', ');
}

function nodeGetHeader(res, name) {
  if (res && typeof res.getHeader === 'function') return res.getHeader(name);
  if (res && isPlainObject(res.headers)) {
    for (const key of Object.keys(res.headers)) {
      if (key.toLowerCase() === name.toLowerCase()) return res.headers[key];
    }
  }
  return undefined;
}

function nodeSetHeader(res, name, value) {
  if (res && typeof res.setHeader === 'function') {
    res.setHeader(name, value);
    return;
  }
  throwError(CODE.INVALID_INPUT, 'the response object does not implement setHeader', name);
}

function nodeRemoveHeader(res, name) {
  if (res && typeof res.removeHeader === 'function') {
    res.removeHeader(name);
    return;
  }
  if (res && isPlainObject(res.headers)) {
    for (const key of Object.keys(res.headers)) {
      if (key.toLowerCase() === name.toLowerCase()) delete res.headers[key];
    }
  }
}

function stripNodeCorsHeaders(res) {
  for (const name of CORS_RESPONSE_HEADERS) nodeRemoveHeader(res, name);
}

function applyNodeVary(res, vary) {
  const merged = mergeVary(nodeGetHeader(res, 'vary'), vary);
  if (merged.length > 0) nodeSetHeader(res, 'Vary', merged);
}

function applyNodeHeaders(res, headers) {
  for (const key of Object.keys(headers)) nodeSetHeader(res, key, headers[key]);
}

function assertNodeResponseShape(res) {
  if (res === null || typeof res !== 'object') {
    throwError(CODE.INVALID_INPUT, 'the response must be a response-like object', res);
  }
  if (res.headersSent === true) {
    throwError(CODE.INVALID_INPUT, 'the response headers have already been sent', res);
  }
  if (typeof res.setHeader !== 'function') {
    throwError(CODE.INVALID_INPUT, 'the response object does not implement setHeader', res);
  }
  if (typeof res.getHeader !== 'function') {
    throwError(CODE.INVALID_INPUT, 'the response object does not implement getHeader', res);
  }
  if (typeof res.removeHeader !== 'function') {
    throwError(CODE.INVALID_INPUT, 'the response object does not implement removeHeader', res);
  }
}

function installNodeResponseGuard(res, result) {
  const originalSetHeader = res.setHeader;
  const originalRemoveHeader = typeof res.removeHeader === 'function' ? res.removeHeader : null;
  const originalAppendHeader = typeof res.appendHeader === 'function' ? res.appendHeader : null;
  const originalSetHeaders = typeof res.setHeaders === 'function' ? res.setHeaders : null;

  function removeDirect(name) {
    if (originalRemoveHeader !== null) return originalRemoveHeader.call(res, name);
    if (isPlainObject(res.headers)) {
      for (const key of Object.keys(res.headers)) {
        if (key.toLowerCase() === String(name).toLowerCase()) delete res.headers[key];
      }
    }
    return undefined;
  }

  function setProtectedCorsHeader(name) {
    const lower = name.toLowerCase();
    const value = result.allowed ? result.headers[lower] : undefined;
    if (value === undefined) {
      removeDirect(name);
      return res;
    }
    originalSetHeader.call(res, name, value);
    return res;
  }

  function protectedVaryValue(candidate) {
    const mergedWithExisting = mergeVary(nodeGetHeader(res, 'vary'), candidate);
    return mergeVary(mergedWithExisting, result.vary);
  }

  function setProtectedVary(candidate) {
    const merged = protectedVaryValue(candidate);
    if (merged.length > 0) originalSetHeader.call(res, 'Vary', merged);
    else removeDirect('Vary');
    return res;
  }

  function enforceStoredPolicyHeaders() {
    for (const name of CORS_RESPONSE_HEADERS) {
      const value = result.allowed ? result.headers[name] : undefined;
      if (value === undefined) removeDirect(name);
      else originalSetHeader.call(res, name, value);
    }
    setProtectedVary(undefined);
  }

  function guardedSetHeader(name, value) {
    if (typeof name === 'string') {
      const lower = name.toLowerCase();
      if (CORS_RESPONSE_HEADERS.includes(lower)) return setProtectedCorsHeader(name);
      if (lower === 'vary') return setProtectedVary(value);
    }
    return originalSetHeader.call(res, name, value);
  }

  function guardedRemoveHeader(name) {
    if (typeof name !== 'string') return removeDirect(name);
    const lower = name.toLowerCase();
    if (CORS_RESPONSE_HEADERS.includes(lower)) {
      const output = removeDirect(name);
      const value = result.allowed ? result.headers[lower] : undefined;
      if (value !== undefined) originalSetHeader.call(res, name, value);
      return output;
    }
    if (lower === 'vary') {
      const existing = nodeGetHeader(res, 'vary');
      const output = removeDirect(name);
      const merged = mergeVary(existing, result.vary);
      if (merged.length > 0) originalSetHeader.call(res, 'Vary', merged);
      return output;
    }
    return removeDirect(name);
  }

  function guardedAppendHeader(name, value) {
    if (typeof name === 'string') {
      const lower = name.toLowerCase();
      if (CORS_RESPONSE_HEADERS.includes(lower)) return setProtectedCorsHeader(name);
      if (lower === 'vary') return setProtectedVary(value);
    }
    return originalAppendHeader.call(res, name, value);
  }

  function guardedSetHeaders(headers) {
    const output = originalSetHeaders.call(res, headers);
    enforceStoredPolicyHeaders();
    return output;
  }

  function defineGuardedMethod(name, implementation) {
    Object.defineProperty(res, name, {
      value: implementation,
      writable: true,
      configurable: true,
      enumerable: false
    });
  }

  defineGuardedMethod('setHeader', guardedSetHeader);
  defineGuardedMethod('removeHeader', guardedRemoveHeader);
  if (originalAppendHeader !== null) defineGuardedMethod('appendHeader', guardedAppendHeader);
  if (originalSetHeaders !== null) defineGuardedMethod('setHeaders', guardedSetHeaders);
}

export function createNodeCorsMiddleware(options) {
  const config = normalizeConfig(options);
  const policy = createCorsPolicy(options);
  const middleware = function corscageMiddleware(req, res, next) {
    if (next === undefined) next = function noop() {};
    if (typeof next !== 'function') {
      throwError(CODE.INVALID_INPUT, 'next must be a function', next);
    }
    assertNodeResponseShape(res);
    const result = evaluateWithConfig(config, req);
    stripNodeCorsHeaders(res);
    applyNodeVary(res, result.vary);
    if (result.isPreflight) {
      if (result.allowed) {
        applyNodeHeaders(res, result.headers);
        res.statusCode = result.statusCode;
        if (typeof res.end !== 'function') {
          throwError(CODE.INVALID_INPUT, 'the response object does not implement end for a terminal preflight', res);
        }
        res.end();
        return;
      }
      if (config.rejectDisallowedPreflight) {
        res.statusCode = result.statusCode;
        if (typeof res.end !== 'function') {
          throwError(CODE.INVALID_INPUT, 'the response object does not implement end for a terminal preflight', res);
        }
        res.end();
        return;
      }
      installNodeResponseGuard(res, result);
      next();
      return;
    }
    if (result.allowed) applyNodeHeaders(res, result.headers);
    installNodeResponseGuard(res, result);
    next();
  };
  Object.defineProperty(middleware, 'policy', {
    value: policy,
    enumerable: false
  });
  return Object.freeze(middleware);
}

function copyResponseWithHeaders(response, headers) {
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function responseHeadersWithPolicy(response, result) {
  const headers = new Headers(response.headers);
  for (const name of CORS_RESPONSE_HEADERS) headers.delete(name);
  if (result.allowed) {
    for (const key of Object.keys(result.headers)) headers.set(key, result.headers[key]);
  }
  const mergedVary = mergeVary(headers.get('vary'), result.vary);
  if (mergedVary.length > 0) headers.set('vary', mergedVary);
  return headers;
}

export function createFetchCorsHandler(options, handler) {
  const config = normalizeConfig(options);
  const wrap = function wrapFetchHandler(fn) {
    if (typeof fn !== 'function') {
      throwError(CODE.INVALID_INPUT, 'createFetchCorsHandler requires a handler function', fn);
    }
    return async function corscageFetchHandler(request, ...args) {
      const result = evaluateWithConfig(config, request);
      if (result.isPreflight && result.allowed) {
        const headers = new Headers(result.headers);
        headers.set('vary', mergeVary(null, result.vary));
        return new Response(null, { status: result.statusCode, headers });
      }
      if (result.isPreflight && !result.allowed && config.rejectDisallowedPreflight) {
        const headers = new Headers();
        headers.set('vary', mergeVary(null, result.vary));
        return new Response(null, { status: result.statusCode, headers });
      }
      const response = await fn(request, ...args);
      if (!(response instanceof Response)) {
        throwError(CODE.INVALID_INPUT, 'the fetch handler must return a Response', response);
      }
      const headers = responseHeadersWithPolicy(response, result);
      return copyResponseWithHeaders(response, headers);
    };
  };
  return handler === undefined ? wrap : wrap(handler);
}

function addFinding(findings, code, severity, message, remediation, path) {
  findings.push(Object.freeze({
    code,
    severity,
    message,
    remediation,
    path: path || null
  }));
}

function lintBoundedIntegerOption(findings, options, key, minimum, maximum) {
  const value = options[key];
  if (value === undefined) return;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    addFinding(
      findings,
      LINT_CODES.CONFIG_INVALID,
      'high',
      'Option ' + key + ' must be a safe integer from ' + String(minimum) + ' through ' + String(maximum) + '.',
      'Use an integer inside the enforced preflight denial-of-service range.',
      key
    );
  }
}

function lintOriginEntry(findings, entry, index, credentials) {
  const path = 'allowedOrigins[' + String(index) + ']';
  if (typeof entry !== 'string') {
    addFinding(
      findings,
      LINT_CODES.INVALID_ORIGIN_ENTRY,
      'high',
      'Origin entries must be strings. Booleans, regular expressions and objects are prohibited.',
      'Use exact serialized origins or strictly scoped subdomain wildcard strings.',
      path
    );
    return null;
  }
  if (entry === '*') {
    if (credentials) {
      addFinding(
        findings,
        LINT_CODES.WILDCARD_WITH_CREDENTIALS,
        'critical',
        'The universal wildcard origin is combined with credentialed CORS.',
        'Remove the wildcard or disable credentials. Credentialed responses must echo only exact authorized origins.',
        path
      );
    } else {
      addFinding(
        findings,
        LINT_CODES.REFLECT_ALL_ORIGINS,
        'high',
        'The universal wildcard authorizes every syntactically valid secure origin for uncredentialed responses.',
        'Use the wildcard only for intentionally public resources.',
        path
      );
    }
    return { type: 'any' };
  }
  const parsed = parseOriginPattern(entry);
  if (!parsed.valid) {
    addFinding(
      findings,
      LINT_CODES.INVALID_ORIGIN_ENTRY,
      'high',
      'The origin entry is malformed: ' + parsed.reason,
      'Use a canonical serialized origin such as https://app.example.com.',
      path
    );
    return null;
  }
  if (parsed.type === 'subdomain' && isOverbroadWildcardBase(parsed.host)) {
    addFinding(
      findings,
      LINT_CODES.OVERBROAD_SUBDOMAIN_WILDCARD,
      'high',
      'The subdomain wildcard base is a public suffix or otherwise overbroad.',
      'Scope the wildcard below a registrable domain that you control, such as https://*.example.com.',
      path
    );
  }
  const scheme = parsed.type === 'exact' ? parsed.origin.scheme : parsed.scheme;
  const local = parsed.type === 'exact' ? parsed.origin.isLocalhost : parsed.isLocalhost;
  if (scheme === 'http' && !local) {
    addFinding(
      findings,
      credentials ? LINT_CODES.INSECURE_HTTP_WITH_CREDENTIALS : LINT_CODES.INSECURE_HTTP_ORIGIN,
      credentials ? 'critical' : 'high',
      credentials ? 'Insecure http origins are combined with credentialed CORS.' : 'An insecure non-localhost http origin is configured.',
      'Use https in production. Plain http is limited to explicit localhost development origins.',
      path
    );
  }
  return parsed;
}

export function lintCorsPolicy(options) {
  const findings = [];
  if (!isPlainObject(options)) {
    addFinding(
      findings,
      LINT_CODES.CONFIG_INVALID,
      'critical',
      'The policy configuration must be a plain object.',
      'Pass a plain configuration object to createCorsPolicy.',
      null
    );
    return Object.freeze(findings);
  }
  for (const key of Object.keys(options)) {
    if (!KNOWN_OPTION_KEYS.has(key)) {
      addFinding(
        findings,
        LINT_CODES.UNKNOWN_OPTION,
        'medium',
        'Unknown option ' + key + ' will be rejected by the runtime validator.',
        'Remove the unknown option or check for a typo.',
        key
      );
    }
    if (RESERVED_KEYS.has(key)) {
      addFinding(
        findings,
        LINT_CODES.CONFIG_INVALID,
        'critical',
        'The configuration contains a reserved object key.',
        'Remove prototype pollution keys from the configuration.',
        key
      );
    }
  }
  for (const key of BOOLEAN_OPTION_KEYS) {
    if (options[key] !== undefined && typeof options[key] !== 'boolean') {
      addFinding(
        findings,
        LINT_CODES.CONFIG_INVALID,
        'high',
        'Option ' + key + ' must be a boolean.',
        'Use exactly true or false. Truthy strings and numbers are rejected by the runtime validator.',
        key
      );
    }
  }
  lintBoundedIntegerOption(findings, options, 'maxRequestHeaders', 1, MAX_REQUEST_HEADERS_LIMIT);
  lintBoundedIntegerOption(findings, options, 'maxRequestHeadersBytes', 128, MAX_REQUEST_HEADER_BYTES_LIMIT);
  const credentials = options.credentials === true;
  const rawOrigins = options.allowedOrigins;
  const entries = rawOrigins === undefined ? [] : (typeof rawOrigins === 'string' ? [rawOrigins] : (Array.isArray(rawOrigins) ? rawOrigins : [rawOrigins]));
  const seen = new Set();
  let hasWildcardSubdomain = false;
  let hasAnyWildcard = false;
  let validEntryCount = 0;
  for (let index = 0; index < entries.length; index += 1) {
    const parsed = lintOriginEntry(findings, entries[index], index, credentials);
    if (parsed !== null) {
      validEntryCount += 1;
      if (parsed.type === 'subdomain') hasWildcardSubdomain = true;
      if (parsed.type === 'any') hasAnyWildcard = true;
      const key = parsed.type === 'any' ? '*' : parsed.key;
      if (seen.has(key)) {
        addFinding(
          findings,
          LINT_CODES.DUPLICATE_ORIGIN,
          'low',
          'The origin entry is duplicated.',
          'Remove duplicate allowlist entries.',
          'allowedOrigins[' + String(index) + ']'
        );
      }
      seen.add(key);
    }
  }
  if (entries.length === 0 && options.originPredicate === undefined) {
    addFinding(
      findings,
      LINT_CODES.NO_ORIGINS_CONFIGURED,
      'low',
      'No origins are configured, so the policy intentionally denies every CORS origin.',
      'Add explicit origins or keep this deny-all policy if that is intended.',
      'allowedOrigins'
    );
  }
  if (hasAnyWildcard && validEntryCount > 1) {
    addFinding(
      findings,
      LINT_CODES.REDUNDANT_ORIGIN_ENTRY,
      'low',
      'Exact or subdomain entries are redundant when the universal wildcard is present.',
      'Choose either the audited universal wildcard or a scoped allowlist.',
      'allowedOrigins'
    );
  }
  if (rawOrigins === true || options.origin === true) {
    addFinding(
      findings,
      LINT_CODES.REFLECT_ALL_ORIGINS,
      'critical',
      'Boolean reflection of all origins is prohibited by construction.',
      'Never reflect arbitrary Origin headers. Use exact origins or an audited synchronous predicate.',
      'allowedOrigins'
    );
  }
  if (options.allowNullOrigin === true) {
    addFinding(
      findings,
      LINT_CODES.NULL_ORIGIN_ALLOWED,
      credentials ? 'critical' : 'medium',
      credentials ? 'The null origin is enabled together with credentials.' : 'The opaque null origin is explicitly enabled.',
      'Keep allowNullOrigin false unless a sandboxed browser context absolutely requires it. It is never valid with credentials.',
      'allowNullOrigin'
    );
  }
  if (options.originPredicate !== undefined) {
    if (typeof options.originPredicate !== 'function') {
      addFinding(
        findings,
        LINT_CODES.CONFIG_INVALID,
        'high',
        'originPredicate is present but is not a function.',
        'Use a synchronous predicate that returns a boolean.',
        'originPredicate'
      );
    } else if (isAsyncFunction(options.originPredicate)) {
      addFinding(
        findings,
        LINT_CODES.CONFIG_INVALID,
        'high',
        'originPredicate must be synchronous, not async.',
        'Use a synchronous function that returns exactly true or false.',
        'originPredicate'
      );
    } else if (entries.length === 0 || credentials) {
      addFinding(
        findings,
        LINT_CODES.REFLECT_ALL_ORIGINS,
        credentials ? 'high' : 'medium',
        'A dynamic predicate can broaden the allowlist and must be manually audited against reflection.',
        'Prefer exact static origins. If a predicate is necessary, require an exact host, scheme and port and never return true unconditionally.',
        'originPredicate'
      );
    }
  }
  if (options.maxAge !== undefined) {
    if (typeof options.maxAge !== 'number' || !Number.isSafeInteger(options.maxAge) || options.maxAge < 0) {
      addFinding(
        findings,
        LINT_CODES.INVALID_MAX_AGE,
        'high',
        'maxAge must be a nonnegative safe integer.',
        'Use an integer number of seconds from 0 through 86400.',
        'maxAge'
      );
    } else if (options.maxAge > MAX_MAX_AGE) {
      addFinding(
        findings,
        LINT_CODES.EXCESSIVE_MAX_AGE,
        'high',
        'maxAge exceeds the hard 86400 second cap.',
        'Lower maxAge. Long-lived preflight caches preserve mistakes and increase incident response time.',
        'maxAge'
      );
    }
  }
  if (options.allowPrivateNetwork === true && (hasWildcardSubdomain || hasAnyWildcard)) {
    addFinding(
      findings,
      LINT_CODES.PRIVATE_NETWORK_WITH_WILDCARD,
      'high',
      'Private Network Access is enabled together with a wildcard origin.',
      'Use exact origins for Private Network Access. A wildcard makes local-network reachability depend on broad DNS control.',
      'allowPrivateNetwork'
    );
  }
  const exposeEntries = options.exposeHeaders === undefined ? [] : (typeof options.exposeHeaders === 'string' ? [options.exposeHeaders] : (Array.isArray(options.exposeHeaders) ? options.exposeHeaders : [options.exposeHeaders]));
  for (let index = 0; index < exposeEntries.length; index += 1) {
    const value = exposeEntries[index];
    const lower = validateHeaderName(value);
    if (lower === null || lower === '*') {
      addFinding(
        findings,
        LINT_CODES.INVALID_HEADER_ENTRY,
        'high',
        'An exposeHeaders entry is not a legal explicit HTTP header name.',
        'Use exact RFC 9110 field names. Wildcard exposure is prohibited.',
        'exposeHeaders[' + String(index) + ']'
      );
    } else if (FORBIDDEN_EXPOSE_HEADERS.has(lower)) {
      addFinding(
        findings,
        LINT_CODES.UNSAFE_EXPOSE_HEADER,
        'critical',
        'Set-Cookie must never be exposed to browser JavaScript.',
        'Remove Set-Cookie and Set-Cookie2 from exposeHeaders.',
        'exposeHeaders[' + String(index) + ']'
      );
    }
  }
  const allowedEntries = options.allowedHeaders === undefined ? [] : (typeof options.allowedHeaders === 'string' ? [options.allowedHeaders] : (Array.isArray(options.allowedHeaders) ? options.allowedHeaders : [options.allowedHeaders]));
  for (let index = 0; index < allowedEntries.length; index += 1) {
    const value = allowedEntries[index];
    const lower = validateHeaderName(value);
    if (lower === null || lower === '*') {
      addFinding(
        findings,
        LINT_CODES.INVALID_HEADER_ENTRY,
        'high',
        'An allowedHeaders entry is not a legal explicit HTTP header name.',
        'Use exact RFC 9110 field names. Wildcard request headers are prohibited.',
        'allowedHeaders[' + String(index) + ']'
      );
    } else if (headerIsHardForbidden(lower) || headerIsBrowserForbidden(lower)) {
      addFinding(
        findings,
        LINT_CODES.UNSAFE_ALLOWED_HEADER,
        headerIsHardForbidden(lower) ? 'critical' : 'high',
        'A forbidden or browser-controlled request header appears in allowedHeaders.',
        'Remove protocol, hop-by-hop, Cookie, sec-* and proxy-* headers from the allowlist.',
        'allowedHeaders[' + String(index) + ']'
      );
    }
  }
  const methodEntries = options.methods === undefined ? [] : (typeof options.methods === 'string' ? [options.methods] : (Array.isArray(options.methods) ? options.methods : [options.methods]));
  if (options.methods !== undefined && methodEntries.length === 0) {
    addFinding(
      findings,
      LINT_CODES.INVALID_METHOD_ENTRY,
      'high',
      'The methods array is empty, so the runtime validator rejects it.',
      'Configure at least one safe method or omit methods to use the secure defaults.',
      'methods'
    );
  }
  for (let index = 0; index < methodEntries.length; index += 1) {
    if (validateMethod(methodEntries[index]) === null) {
      addFinding(
        findings,
        LINT_CODES.INVALID_METHOD_ENTRY,
        'high',
        'A methods entry is not a safe RFC 9110 token or is a dangerous method.',
        'Remove TRACE, CONNECT, wildcard and malformed method tokens.',
        'methods[' + String(index) + ']'
      );
    }
  }
  return Object.freeze(findings);
}

export function assertSafeCorsConfig(options) {
  const findings = lintCorsPolicy(options);
  const blocking = findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high');
  if (blocking.length > 0) {
    throwError(
      CODE.UNSAFE_CONFIG,
      'the CORS configuration has critical or high severity findings',
      options,
      Object.freeze(blocking.slice())
    );
  }
  return true;
}

const corscage = {
  CODE,
  LINT_CODES,
  CorsCageError,
  parseOrigin,
  normalizeOrigin,
  matchOrigin,
  mergeVary,
  createCorsPolicy,
  createNodeCorsMiddleware,
  createFetchCorsHandler,
  lintCorsPolicy,
  assertSafeCorsConfig
};

export default corscage;

import test from 'node:test';
import assert from 'node:assert/strict';
import { parseOrigin, normalizeOrigin } from '../src/index.mjs';

const validCases = [
  ['https://example.com', 'https://example.com', 443],
  ['http://example.com', 'http://example.com', 80],
  ['HTTPS://EXAMPLE.COM', 'https://example.com', 443],
  ['HtTp://ExAmPlE.CoM', 'http://example.com', 80],
  ['https://example.com:443', 'https://example.com', 443],
  ['http://example.com:80', 'http://example.com', 80],
  ['https://example.com:8443', 'https://example.com:8443', 8443],
  ['http://example.com:8080', 'http://example.com:8080', 8080],
  ['https://localhost', 'https://localhost', 443],
  ['http://localhost:3000', 'http://localhost:3000', 3000],
  ['https://app.localhost', 'https://app.localhost', 443],
  ['https://intranet', 'https://intranet', 443],
  ['https://xn--nxasmq6b.example.com', 'https://xn--nxasmq6b.example.com', 443],
  ['https://127.0.0.1', 'https://127.0.0.1', 443],
  ['https://255.255.255.255:65535', 'https://255.255.255.255:65535', 65535],
  ['https://[::1]', 'https://[::1]', 443],
  ['https://[2001:0db8:0:0:0:ff00:0042:8329]', 'https://[2001:db8::ff00:42:8329]', 443],
  ['https://[::ffff:192.0.2.1]:8443', 'https://[::ffff:c000:201]:8443', 8443],
  ['http://[2001:db8::]:80', 'http://[2001:db8::]', 80],
  ['https://[0:0:0:0:0:0:0:0]', 'https://[::]', 443]
];

for (const [input, normalized, port] of validCases) {
  test('parseOrigin canonicalizes valid origin ' + input, () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, true);
    assert.equal(parsed.isNull, false);
    assert.equal(parsed.normalized, normalized);
    assert.equal(parsed.port, port);
    assert.equal(normalizeOrigin(input), normalized);
    assert.equal(Object.isFrozen(parsed), true);
  });
}

test('parseOrigin recognizes null as an opaque origin serialization', () => {
  const parsed = parseOrigin('null');
  assert.equal(parsed.valid, true);
  assert.equal(parsed.isNull, true);
  assert.equal(parsed.normalized, 'null');
  assert.equal(parsed.scheme, null);
  assert.equal(parsed.host, null);
});

const invalidTypes = [
  undefined,
  null,
  0,
  1,
  false,
  true,
  {},
  [],
  new URL('https://example.com')
];

for (const input of invalidTypes) {
  test('parseOrigin rejects non-string input ' + Object.prototype.toString.call(input), () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, false);
    assert.equal(parsed.normalized, null);
    assert.equal(parsed.code, 'CORS_ORIGIN_TYPE');
    assert.equal(normalizeOrigin(input), null);
  });
}

const whitespaceAndControlCases = [
  ' https://example.com',
  'https://example.com ',
  '\thttps://example.com',
  'https://example.com\t',
  '\nhttps://example.com',
  'https://example.com\n',
  '\rhttps://example.com',
  'https://example.com\r',
  'https://exa mple.com',
  'https://example.com/\n',
  'https://example.com\r\n',
  'https://example.com\u0000',
  'https://example.com\u0001',
  'https://example.com\u0007',
  'https://example.com\u000b',
  'https://example.com\u000c',
  'https://example.com\u001f',
  'https://example.com\u007f',
  'https:// example.com',
  'https ://example.com',
  'https://example.com :443',
  'https://example.com:443 ',
  '  ',
  '\u00a0https://example.com',
  'https://example.com\u00a0'
];

for (const input of whitespaceAndControlCases) {
  test('parseOrigin rejects whitespace and control smuggling case ' + JSON.stringify(input), () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, false);
    assert.equal(parsed.normalized, null);
  });
}

const nonAsciiCases = [
  'https://éxample.com',
  'https://\u0435xample.com',
  'https://ex\u0430mple.com',
  'https://example。com',
  'https://example．com',
  'https://ｅｘａｍｐｌｅ.com',
  'https://παράδειγμα.example',
  'https://مثال.example',
  'https://例子.example',
  'https://example.com/\u00e9',
  'https://\u2024example.com',
  'https://ex\u200bample.com',
  'https://ex\u2060ample.com',
  'https://ex\ufeffample.com',
  'https://💥.example.com'
];

for (const input of nonAsciiCases) {
  test('parseOrigin rejects Unicode or confusable host case ' + encodeURIComponent(input), () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, false);
    assert.equal(parsed.code, 'CORS_ORIGIN_NON_ASCII');
  });
}

const structuralInvalidCases = [
  '',
  'example.com',
  '//example.com',
  'https:example.com',
  'https:/example.com',
  'https//example.com',
  'https://',
  'https:///example.com',
  'javascript://example.com',
  'data://example.com',
  'file://example.com',
  'ftp://example.com',
  'chrome-extension://abcdef',
  'about://blank',
  'https://example.com/',
  'https://example.com/path',
  'https://example.com/path/',
  'https://example.com?x=1',
  'https://example.com#frag',
  'https://example.com\\evil.example',
  'https://example.com/%2f',
  'https://user@example.com',
  'https://user:pass@example.com',
  'https://@example.com',
  'https://example.com@evil.example',
  'https://%65xample.com',
  'https://example%2ecom',
  'https://example.com%00',
  'https://example.com,https://evil.example',
  'https://example.com,null',
  'null,https://example.com',
  'https://example.com;param',
  'https://example.com&x',
  'https://example.com=x',
  'https://example.com+evil',
  'https://exam_ple.com',
  'https://example..com',
  'https://.example.com',
  'https://example.com.',
  'https://-example.com',
  'https://example-.com',
  'https://exa--mple.com/path'
];

for (const input of structuralInvalidCases) {
  test('parseOrigin rejects malformed structural case ' + JSON.stringify(input), () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, false);
    assert.equal(parsed.normalized, null);
  });
}

const invalidPortCases = [
  'https://example.com:',
  'https://example.com:abc',
  'https://example.com:80a',
  'https://example.com:+80',
  'https://example.com:-80',
  'https://example.com: 80',
  'https://example.com:08',
  'https://example.com:080',
  'https://example.com:0443',
  'https://example.com:000443',
  'https://example.com:0',
  'https://example.com:00',
  'https://example.com:65536',
  'https://example.com:65537',
  'https://example.com:99999',
  'https://example.com:100000',
  'https://example.com:1.5',
  'https://example.com:0x50',
  'https://example.com:443/'
];

for (const input of invalidPortCases) {
  test('parseOrigin rejects invalid port case ' + input, () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, false);
  });
}

const validPortCases = [
  ['https://example.com:1', 1],
  ['https://example.com:2', 2],
  ['https://example.com:79', 79],
  ['https://example.com:81', 81],
  ['https://example.com:442', 442],
  ['https://example.com:444', 444],
  ['https://example.com:8080', 8080],
  ['https://example.com:65534', 65534],
  ['https://example.com:65535', 65535]
];

for (const [input, port] of validPortCases) {
  test('parseOrigin accepts boundary valid port ' + input, () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, true);
    assert.equal(parsed.port, port);
    assert.equal(parsed.explicitPort, port);
  });
}

const invalidIPv4Cases = [
  'https://127.1',
  'https://127.0.1',
  'https://127.0.0.0.1',
  'https://256.0.0.1',
  'https://999.999.999.999',
  'https://01.2.3.4',
  'https://001.2.3.4',
  'https://1.02.3.4',
  'https://1.2.003.4',
  'https://1.2.3.004',
  'https://0x7f.0.0.1',
  'https://0X7F.0.0.1',
  'https://0177.0.0.1',
  'https://0x7f',
  'https://0x',
  'https://0X',
  'https://0x.1',
  'https://0xg.1',
  'https://09',
  'https://2130706433',
  'https://127..0.1',
  'https://127...1',
  'https://1.2.3.',
  'https://.1.2.3',
  'https://1.2.3.4.5',
  'https://1234',
  'https://999999',
  'https://1.2.3.256'
];

for (const input of invalidIPv4Cases) {
  test('parseOrigin rejects IPv4 obfuscation or malformed literal ' + input, () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, false);
  });
}

const validIPv4Cases = [
  'https://0.0.0.0',
  'https://1.2.3.4',
  'https://10.0.0.1',
  'https://127.0.0.1',
  'https://192.168.1.20',
  'https://255.255.255.255'
];

for (const input of validIPv4Cases) {
  test('parseOrigin accepts strict dotted IPv4 literal ' + input, () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, true);
    assert.equal(parsed.hostType, 'ipv4');
  });
}

const invalidIPv6Cases = [
  'https://::1',
  'https://[::1',
  'https://::1]',
  'https://[]',
  'https://[',
  'https://]',
  'https://[::1]x',
  'https://[::1]evil',
  'https://[::1]:',
  'https://[::1]:abc',
  'https://[::1]:0',
  'https://[::1]:065535',
  'https://[:::]',
  'https://[::::]',
  'https://[1::2::3]',
  'https://[1:2:3:4:5:6:7:8:9]',
  'https://[1:2:3:4:5:6:7]',
  'https://[gggg::]',
  'https://[12345::]',
  'https://[::ffff:999.1.1.1]',
  'https://[::ffff:192.168.1]',
  'https://[::ffff:192.168.1.1.1]',
  'https://[fe80::1%25eth0]',
  'https://[fe80::1%eth0]',
  'https://[::1]/',
  'https://[::1]?x=1',
  'https://[::1]#x'
];

for (const input of invalidIPv6Cases) {
  test('parseOrigin rejects malformed IPv6 literal ' + input, () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, false);
  });
}

const ipv6CanonicalCases = [
  ['https://[0:0:0:0:0:0:0:1]', 'https://[::1]'],
  ['https://[2001:DB8:0:0:0:0:0:1]', 'https://[2001:db8::1]'],
  ['https://[2001:0:0:1:0:0:1:1]', 'https://[2001::1:0:0:1:1]'],
  ['https://[0:0:1:0:0:1:0:0]', 'https://[::1:0:0:1:0:0]'],
  ['https://[1:0:0:2:0:0:3:4]', 'https://[1::2:0:0:3:4]'],
  ['https://[::ffff:1.2.3.4]', 'https://[::ffff:102:304]'],
  ['https://[64:ff9b::192.0.2.33]', 'https://[64:ff9b::c000:221]']
];

for (const [input, normalized] of ipv6CanonicalCases) {
  test('parseOrigin canonicalizes IPv6 literal ' + input, () => {
    const parsed = parseOrigin(input);
    assert.equal(parsed.valid, true);
    assert.equal(parsed.normalized, normalized);
    assert.equal(parsed.hostType, 'ipv6');
  });
}

test('parseOrigin enforces the strict origin length cap', () => {
  const label = 'a'.repeat(63);
  const host = Array.from({ length: 5 }, () => label).join('.');
  const longInput = 'https://' + host + '.example.com';
  assert.equal(parseOrigin(longInput).valid, false);
});

test('parseOrigin rejects a host label longer than 63 characters', () => {
  assert.equal(parseOrigin('https://' + 'a'.repeat(64) + '.example.com').valid, false);
});

test('parseOrigin accepts a host label at the 63 character boundary', () => {
  assert.equal(parseOrigin('https://' + 'a'.repeat(63) + '.example.com').valid, true);
});

test('parseOrigin marks localhost domain forms', () => {
  assert.equal(parseOrigin('https://localhost').isLocalhost, true);
  assert.equal(parseOrigin('https://app.localhost').isLocalhost, true);
});

test('parseOrigin marks loopback IP forms', () => {
  assert.equal(parseOrigin('https://127.0.0.1').isLocalhost, true);
  assert.equal(parseOrigin('https://127.255.255.254').isLocalhost, true);
  assert.equal(parseOrigin('https://[::1]').isLocalhost, true);
});

test('parseOrigin does not mark non-loopback IP forms as localhost', () => {
  assert.equal(parseOrigin('https://128.0.0.1').isLocalhost, false);
  assert.equal(parseOrigin('https://[::2]').isLocalhost, false);
});

test('parseOrigin result objects cannot be mutated', () => {
  const parsed = parseOrigin('https://example.com');
  assert.throws(() => {
    parsed.host = 'evil.example';
  }, TypeError);
  assert.equal(parsed.host, 'example.com');
});

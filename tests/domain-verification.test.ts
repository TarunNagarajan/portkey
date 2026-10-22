import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { fetchDomainVerificationFile, isPublicAddress, type DomainTransport } from '../server/domainVerification.js';

test('domain verifier rejects special IPv4 and IPv6 ranges including equivalent compressed spellings', () => {
  for (const address of ['0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.1.1', '172.31.0.1', '192.0.2.2', '192.88.99.4', '192.168.1.1', '198.18.0.1', '198.51.100.2', '203.0.113.3', '224.0.0.1']) {
    assert.equal(isPublicAddress(address), false, `${address} must not be accepted`);
  }
  for (const address of ['::1', '::ffff:8.8.8.8', '2001:db8::1', '2001:0db8::1', '2002::1', '3fff::1', '64:ff9b::808:808']) {
    assert.equal(isPublicAddress(address), false, `${address} must not be accepted`);
  }
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('2001:4860::1'), true);
  assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
});

test('domain verifier pins the approved DNS address while preserving HTTPS SNI and Host header', async () => {
  let resolvedHostname = '';
  let pinnedLookup = '';
  let servername = '';
  let hostHeader = '';
  let requestHostname = '';
  let agentDisabled = false;
  const transport: DomainTransport = (url, options, callback) => {
    requestHostname = url.hostname;
    agentDisabled = options.agent === false;
    servername = String((options as typeof options & { servername?: string }).servername);
    hostHeader = String(options.headers && (options.headers as Record<string, string>).Host);
    const lookup = options.lookup as (hostname: string, options: { all: true }, callback: (...args: unknown[]) => void) => void;
    lookup('portkey-test.invalid', { all: true }, (...args) => {
      const [, records] = args;
      pinnedLookup = JSON.stringify(records);
    });
    const clientRequest = new EventEmitter() as import('node:http').ClientRequest;
    queueMicrotask(() => {
      const response = new EventEmitter() as import('node:http').IncomingMessage;
      Object.assign(response, { statusCode: 200, headers: { 'content-type': 'application/json' } });
      callback(response);
      response.emit('data', Buffer.from('{"ok":true}'));
      response.emit('end');
    });
    Object.assign(clientRequest, { destroy: (error?: Error) => { if (error) clientRequest.emit('error', error); return clientRequest; } });
    return clientRequest;
  };
  const result = await fetchDomainVerificationFile('https://portkey-test.invalid', false, {
    resolve: async hostname => {
      resolvedHostname = hostname;
      return [{ address: '93.184.216.34', family: 4 }];
    },
    transport,
  }) as { ok: boolean };
  assert.equal(resolvedHostname, 'portkey-test.invalid');
  assert.equal(requestHostname, 'portkey-test.invalid');
  assert.equal(agentDisabled, true);
  assert.equal(servername, 'portkey-test.invalid');
  assert.equal(hostHeader, 'portkey-test.invalid');
  assert.equal(pinnedLookup, JSON.stringify([{ address: '93.184.216.34', family: 4 }]));
  assert.equal(result.ok, true);
});

test('domain verifier rejects mixed public and private DNS answers before connecting', async () => {
  let connected = false;
  await assert.rejects(fetchDomainVerificationFile('https://example.invalid', false, {
    resolve: async () => [
      { address: '8.8.8.8', family: 4 },
      { address: '192.168.1.10', family: 4 },
    ],
    request: async () => {
      connected = true;
      return { status: 200, contentType: 'application/json', body: Buffer.from('{}') };
    },
  }));
  assert.equal(connected, false);
});

test('domain verifier rejects redirects, oversized bodies and non-443 HTTPS targets', async () => {
  const resolver = async () => [{ address: '93.184.216.34', family: 4 }];
  await assert.rejects(fetchDomainVerificationFile('https://example.invalid:8443', false, { resolve: resolver }));
  await assert.rejects(fetchDomainVerificationFile('https://example.invalid', false, {
    resolve: resolver,
    request: async () => ({ status: 302, contentType: 'application/json', body: Buffer.from('{}') }),
  }), /Redirects/);
  await assert.rejects(fetchDomainVerificationFile('https://example.invalid', false, {
    resolve: resolver,
    request: async () => ({ status: 200, contentType: 'application/json', body: Buffer.alloc(4097) }),
  }), /too large/);
});

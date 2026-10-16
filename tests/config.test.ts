import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseConfiguration } from '../server/configuration.js';

const base = (values: NodeJS.ProcessEnv = {}) => ({ NODE_ENV: 'production', DATABASE_URL: 'postgres://redacted@db.example/portkey', ...values });

test('production configuration requires a public HTTPS DNS origin and normalizes its root slash', () => {
  assert.equal(parseConfiguration(base({ APP_ORIGIN: 'https://portkey.onrender.com/' })).origin, 'https://portkey.onrender.com');
  for (const value of ['', 'http://portkey.onrender.com', 'https://localhost', 'https://host.local', 'https://host.home.arpa', 'https://portkey.example', 'https://foo..com', 'https://bad_host.example.org', 'https://192.168.1.4', 'https://127.0.0.1', 'https://[::1]', 'https://user:pass@portkey.onrender.com', 'https://portkey.onrender.com/path', 'https://portkey.onrender.com?q=1', 'https://portkey.onrender.com#x']) {
    assert.throws(() => parseConfiguration(base({ APP_ORIGIN: value })), /APP_ORIGIN|origin/);
  }
});

test('Render origin is a fallback only when APP_ORIGIN is absent', () => {
  assert.equal(parseConfiguration(base({ RENDER_EXTERNAL_URL: 'https://portkey.onrender.com' })).origin, 'https://portkey.onrender.com');
  assert.throws(() => parseConfiguration(base({ APP_ORIGIN: 'http://localhost', RENDER_EXTERNAL_URL: 'https://portkey.onrender.com' })), /APP_ORIGIN/);
  assert.throws(() => parseConfiguration(base()), /APP_ORIGIN/);
});

test('database, host, port and proxy configuration are bounded', () => {
  assert.throws(() => parseConfiguration(base({ APP_ORIGIN: 'https://portkey.onrender.com', DATABASE_URL: '' })), /DATABASE_URL/);
  assert.equal(parseConfiguration(base({ APP_ORIGIN: 'https://portkey.onrender.com', DATABASE_URL: '', ALLOW_EMBEDDED_DATABASE: 'true' })).host, '0.0.0.0');
  assert.throws(() => parseConfiguration(base({ APP_ORIGIN: 'https://portkey.onrender.com', TRUST_PROXY_HOPS: '3' })), /configuration/);
  assert.equal(parseConfiguration(base({ APP_ORIGIN: 'https://portkey.onrender.com', TRUST_PROXY_HOPS: '2' })).trustProxyHops, 2);
  assert.throws(() => parseConfiguration({ NODE_ENV: 'development', PORT: '65536' }), /configuration/);
  assert.throws(() => parseConfiguration({ HOST: 'bad host' }), /HOST/);
  const secret = 'postgres://private-secret';
  assert.throws(() => parseConfiguration({ NODE_ENV: 'production', APP_ORIGIN: 'bad origin', DATABASE_URL: secret }), error => error instanceof Error && !error.message.includes(secret));
  const malformedDatabase = 'not-a-postgres-url-with-password=never-show-this';
  assert.throws(() => parseConfiguration(base({ APP_ORIGIN: 'https://portkey.onrender.com', DATABASE_URL: malformedDatabase })), error => error instanceof Error && /DATABASE_URL/.test(error.message) && !error.message.includes('never-show-this'));
  assert.equal(parseConfiguration(base({ APP_ORIGIN: 'https://portkey.onrender.com', DATABASE_URL: 'postgresql://user:password@db.example/portkey?sslmode=require' })).databaseUrl, 'postgresql://user:password@db.example/portkey?sslmode=require');
  assert.equal(parseConfiguration({}).host, '127.0.0.1');
  assert.equal(parseConfiguration({}).port, 3001);
});

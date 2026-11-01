import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

function production(overrides: Record<string, string> = {}) {
  const inherited = { ...process.env };
  delete inherited.ISSUER_PUBLIC_KEY;
  return spawnSync(process.execPath, ['--import', 'tsx', '-e', "import('./server/config.ts')"], {
    env: { ...inherited, NODE_ENV: 'production', APP_ORIGIN: 'https://portkey.example',
      ALLOW_DEMO_CREDENTIALS: 'false', ...overrides },
    encoding: 'utf8',
  });
}

test('production requires deliberate issuer configuration or an explicit demo opt-in', () => {
  const rejected = production();
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /Production requires ISSUER_PUBLIC_KEY/);
  assert.equal(production({ ALLOW_DEMO_CREDENTIALS: 'true' }).status, 0);
  assert.equal(production({ ISSUER_PUBLIC_KEY: '{"ax":"1","ay":"2"}' }).status, 0);
});

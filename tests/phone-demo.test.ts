import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { resolve } from 'node:path';
import { test } from 'node:test';
import type { ChildProcess } from 'node:child_process';
import { demoEnvironment, runPhoneDemo, validateTunnelUrl } from '../scripts/phone-demo.js';

function child() {
  const value = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(), stderr: new PassThrough(), exitCode: null as number | null, signalCode: null as NodeJS.Signals | null,
    connected: true, ipcMessages: [] as unknown[],
    kill() { value.exitCode = 0; value.emit('close', 0); return true; },
    send(message: unknown) { value.ipcMessages.push(message); setImmediate(() => value.kill()); return true; },
    setExit(code: number) { value.exitCode = code; },
  });
  return value as unknown as ChildProcess & { stdout: PassThrough; stderr: PassThrough; kill: () => boolean; send: (message: unknown) => boolean; setExit: (code: number) => void; ipcMessages: unknown[] };
}

test('temporary tunnel validation rejects lookalikes and non-origin URLs', () => {
  assert.equal(validateTunnelUrl('https://calm-otter.trycloudflare.com'), 'https://calm-otter.trycloudflare.com');
  for (const value of ['http://calm-otter.trycloudflare.com', 'https://trycloudflare.com', 'https://bad.trycloudflare.com.attacker.test', 'https://user@bad.trycloudflare.com', 'https://bad.trycloudflare.com/path', 'https://bad.trycloudflare.com?x=1']) assert.equal(validateTunnelUrl(value), null);
});

test('demo environment excludes inherited database and application secrets', () => {
  const oldDatabase = process.env.DATABASE_URL;
  const oldToken = process.env.SESSION_SECRET;
  process.env.DATABASE_URL = 'postgres://must-not-leak';
  process.env.SESSION_SECRET = 'must-not-leak-either';
  try {
    const env = demoEnvironment(3003, 'https://calm-otter.trycloudflare.com', 'C:/portkey');
    assert.equal(env.DATABASE_URL, undefined);
    assert.equal(env.SESSION_SECRET, undefined);
    assert.equal(env.PORT, '3003');
    assert.equal(env.APP_ORIGIN, 'https://calm-otter.trycloudflare.com');
    assert.equal(env.ALLOW_EMBEDDED_DATABASE, 'true');
    assert.equal(env.TRUST_PROXY_HOPS, '1');
    assert.equal(env.DATA_DIR, resolve('C:/portkey', '.data/phone-demo'));
    assert.equal(env.PORTKEY_LOAD_DOTENV, 'false');
  } finally {
    if (oldDatabase === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = oldDatabase;
    if (oldToken === undefined) delete process.env.SESSION_SECRET; else process.env.SESSION_SECRET = oldToken;
  }
});

test('demo launcher waits for a validated URL and API health, then cleans up owned children', async () => {
  const children: ReturnType<typeof child>[] = [];
  const calls: { command: string; args: string[]; env?: NodeJS.ProcessEnv }[] = [];
  const cleanup = await runPhoneDemo({
    cwd: process.cwd(), port: 3003, built: true, portAvailable: async () => true,
    spawnProcess: ((command: string, args: string[], options: { env?: NodeJS.ProcessEnv }) => {
      calls.push({ command, args, env: options.env });
      const value = child(); children.push(value);
      if (children.length === 1) setImmediate(() => value.stderr.write('https://calm-otter.trycloudflare.com\n'));
      return value;
    }) as never,
    fetcher: async (url) => new Response(String(url).endsWith('/api/config') ? JSON.stringify({ publicOrigin: 'https://calm-otter.trycloudflare.com' }) : JSON.stringify({ status: 'ok' }), { status: 200 }), wait: ms => new Promise(resolve => setTimeout(resolve, Math.min(ms, 2))), log: () => {},
  });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].args, ['tunnel', '--no-autoupdate', '--url', 'http://127.0.0.1:3003']);
  assert.deepEqual(calls[1].args.slice(0, 2), ['--import', 'tsx']);
  assert.equal(calls[1].env?.APP_ORIGIN, 'https://calm-otter.trycloudflare.com');
  const firstCleanup = cleanup();
  assert.equal(cleanup(), firstCleanup);
  await firstCleanup;
  assert.ok(children.every(value => value.exitCode === 0));
  assert.deepEqual(children[1].ipcMessages, [{ type: 'phone-demo:shutdown' }]);
});

test('readiness failure and startup cancellation stop owned processes', async () => {
  const failedChildren: ReturnType<typeof child>[] = [];
  await assert.rejects(runPhoneDemo({ port: 3003, built: true, portAvailable: async () => true, readinessTimeoutMs: 5,
    spawnProcess: (() => { const value = child(); failedChildren.push(value); if (failedChildren.length === 1) setImmediate(() => value.stderr.write('https://calm-otter.trycloudflare.com')); return value; }) as never,
    fetcher: async () => new Response('{}', { status: 503 }), wait: ms => new Promise(resolve => setTimeout(resolve, Math.min(ms, 2))), log: () => {},
  }), /did not become ready/);
  assert.ok(failedChildren.every(value => value.exitCode === 0));

  const controller = new AbortController();
  const cancelledChildren: ReturnType<typeof child>[] = [];
  setTimeout(() => controller.abort(), 2);
  await assert.rejects(runPhoneDemo({ port: 3003, built: true, portAvailable: async () => true, signal: controller.signal,
    spawnProcess: (() => { const value = child(); cancelledChildren.push(value); return value; }) as never,
    wait: ms => new Promise(resolve => setTimeout(resolve, Math.min(ms, 2))), log: () => {},
  }), /cancelled/);
  assert.equal(cancelledChildren[0].exitCode, 0);
});

test('unexpected tunnel exit shuts down the demo server and reports the failure', async () => {
  const children: ReturnType<typeof child>[] = [];
  let failure = '';
  const cleanup = await runPhoneDemo({ port: 3003, built: true, portAvailable: async () => true,
    spawnProcess: (() => { const value = child(); children.push(value); if (children.length === 1) setImmediate(() => value.stderr.write('https://calm-otter.trycloudflare.com')); return value; }) as never,
    fetcher: async (url) => new Response(String(url).endsWith('/api/config') ? JSON.stringify({ publicOrigin: 'https://calm-otter.trycloudflare.com' }) : JSON.stringify({ status: 'ok' }), { status: 200 }), wait: ms => new Promise(resolve => setTimeout(resolve, Math.min(ms, 2))), log: () => {},
    onFailure: message => { failure = message; },
  });
  children[0].setExit(1);
  children[0].emit('close', 1, null);
  for (let attempt = 0; attempt < 20 && (!failure || children[1].exitCode !== 0); attempt += 1) await new Promise(resolve => setTimeout(resolve, 1));
  assert.match(failure, /Cloudflared exited/);
  assert.equal(children[1].exitCode, 0);
  await cleanup();
});

test('server errors and tunnel exits during public HTTPS checks clean up both children', async () => {
  for (const failedChild of ['server', 'tunnel']) {
    const children: ReturnType<typeof child>[] = [];
    await assert.rejects(runPhoneDemo({ port: 3003, built: true, portAvailable: async () => true, readinessTimeoutMs: 2000,
      spawnProcess: (() => {
        const value = child(); children.push(value);
        if (children.length === 1) setImmediate(() => value.stderr.write('https://calm-otter.trycloudflare.com'));
        if (children.length === 2) setTimeout(() => {
          if (failedChild === 'server') value.emit('error', new Error('server failure'));
          else { children[0].setExit(1); children[0].emit('close', 1, null); }
        }, 1);
        return value;
      }) as never,
      fetcher: async url => {
        await new Promise(resolve => setTimeout(resolve, 5));
        return new Response(String(url).endsWith('/api/config') ? JSON.stringify({ publicOrigin: 'https://calm-otter.trycloudflare.com' }) : JSON.stringify({ status: 'ok' }), { status: 200 });
      },
      wait: ms => new Promise(resolve => setTimeout(resolve, Math.min(ms, 2))), log: () => {},
    }), failedChild === 'server' ? /Demo server could not start/ : /Cloudflared exited/);
    assert.equal(children.length, 2);
    assert.ok(children.every(value => value.exitCode === 0 || value.exitCode === 1));
  }
});

test('server shutdown falls back to force termination only after IPC grace expires', async () => {
  const children: ReturnType<typeof child>[] = [];
  const cleanup = await runPhoneDemo({ port: 3003, built: true, portAvailable: async () => true, shutdownTimeoutMs: 5,
    spawnProcess: (() => {
      const value = child(); children.push(value);
      if (children.length === 1) setImmediate(() => value.stderr.write('https://calm-otter.trycloudflare.com'));
      if (children.length === 2) value.send = (message: unknown) => { value.ipcMessages.push(message); return true; };
      return value;
    }) as never,
    fetcher: async url => new Response(String(url).endsWith('/api/config') ? JSON.stringify({ publicOrigin: 'https://calm-otter.trycloudflare.com' }) : JSON.stringify({ status: 'ok' }), { status: 200 }),
    wait: ms => new Promise(resolve => setTimeout(resolve, Math.min(ms, 2))), log: () => {},
  });
  await cleanup();
  assert.deepEqual(children[1].ipcMessages, [{ type: 'phone-demo:shutdown' }]);
  assert.equal(children[1].exitCode, 0);
});

test('launcher cleans its tunnel on startup timeout and reports cloudflared startup errors', async () => {
  const children: ReturnType<typeof child>[] = [];
  await assert.rejects(runPhoneDemo({ port: 3003, built: true, portAvailable: async () => true, tunnelTimeoutMs: 1,
    spawnProcess: (() => { const value = child(); children.push(value); return value; }) as never,
    wait: ms => new Promise(resolve => setTimeout(resolve, Math.min(ms, 2))), log: () => {},
  }), /Timed out/);
  assert.equal(children[0].exitCode, 0);
  await assert.rejects(runPhoneDemo({ port: 3003, built: true, portAvailable: async () => true,
    spawnProcess: (() => { const value = child(); setImmediate(() => value.emit('error', Object.assign(new Error('missing'), { code: 'ENOENT' }))); return value; }) as never,
    wait: ms => new Promise(resolve => setTimeout(resolve, Math.min(ms, 2))), log: () => {},
  }), /cloudflared was not found/);
});

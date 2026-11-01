// Serves the production build behind a Cloudflare quick tunnel so phones and
// other devices can use the app. Quick tunnels need no account, but the public
// URL changes each run.
//
//   npm run share
//
// The tunnel terminates HTTPS at Cloudflare and forwards to 127.0.0.1, so the
// API keeps its loopback bind. APP_ORIGIN is set to the tunnel URL, which is
// what the origin check (and the Secure session cookie) require.
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const startedPort = Number(process.env.PORT ?? 3001);
const tunnelPattern = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/;

function log(message) {
  console.log(`[share] ${message}`);
}

function run(command, args, options = {}) {
  return spawn(command, args, {
    cwd: root,
    stdio: 'inherit',
    ...options,
  });
}

function freePort(start) {
  return new Promise((resolvePort, reject) => {
    const probe = (port, attempts) => {
      if (attempts > 25) {
        reject(new Error(`No free port between ${start} and ${start + 25}.`));
        return;
      }
      const server = createServer();
      server.once('error', () => probe(port + 1, attempts + 1));
      server.once('listening', () => {
        server.close(() => resolvePort(port));
      });
      server.listen(port, '127.0.0.1');
    };
    probe(start, 0);
  });
}

async function waitForHealth(port, child) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) throw new Error('The API stopped while starting.');
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/health`);
      if (response.ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((done) => setTimeout(done, 500));
  }
  throw new Error('The API did not become healthy.');
}

function startTunnel(port) {
  return new Promise((resolveTunnel, reject) => {
    const child = run('cloudflared', [
      'tunnel',
      '--no-autoupdate',
      '--url',
      `http://127.0.0.1:${port}`,
    ], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NO_COLOR: '1' },
    });
    let seen = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error('cloudflared did not report a tunnel URL in time.'));
    }, 45_000);
    const read = (chunk) => {
      seen += chunk.toString();
      const match = seen.match(tunnelPattern);
      if (!match) return;
      clearTimeout(timer);
      resolveTunnel({ child, url: match[0] });
    };
    child.stdout.on('data', read);
    child.stderr.on('data', read);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(
        error.code === 'ENOENT'
          ? new Error('cloudflared is not installed. Install it, then rerun npm run share.')
          : error,
      );
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`cloudflared exited with code ${code}.`));
    });
  });
}

const children = [];
let closing = false;
function stop(code = 0) {
  if (closing) return;
  closing = true;
  for (const child of children) child.kill('SIGTERM');
  setTimeout(() => process.exit(code), 300);
}
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => stop(0));
}

try {
  log('building the app');
  const build = run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build']);
  const buildCode = await new Promise((done) => build.once('exit', done));
  if (buildCode !== 0) throw new Error(`The build failed (exit ${buildCode}).`);

  const port = await freePort(startedPort);
  log(`starting the tunnel to 127.0.0.1:${port}`);
  const tunnel = await startTunnel(port);
  children.push(tunnel.child);
  const tunnelChild = tunnel.child;
  tunnelChild.once('exit', () => {
    log('the tunnel closed; stopping');
    stop(0);
  });

  log(`starting the API with APP_ORIGIN=${tunnel.url}`);
  const api = run(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['tsx', 'server/index.ts'], {
    env: {
      ...process.env,
      PORT: String(port),
      APP_ORIGIN: tunnel.url,
      NODE_ENV: 'production',
      // Quick sharing is explicitly a course demo, including the public issuer.
      ALLOW_DEMO_CREDENTIALS: process.env.ALLOW_DEMO_CREDENTIALS ?? 'true',
      HOST: '127.0.0.1',
    },
  });
  children.push(api);
  const apiChild = api;
  apiChild.once('exit', (code) => {
    log(`the API stopped (exit ${code}); closing the tunnel`);
    stop(code ?? 0);
  });

  await waitForHealth(port, apiChild);
  console.log('');
  console.log(`  Portkey is reachable from any device on the internet:`);
  console.log('');
  console.log(`  ${tunnel.url}`);
  console.log('');
  console.log('  The URL is public and changes each run. Stop with Ctrl+C.');
  console.log('  HTTPS is provided by Cloudflare, so browser crypto and');
  console.log('  location work on phones.');
  console.log('');
} catch (error) {
  log(error instanceof Error ? error.message : String(error));
  stop(1);
}

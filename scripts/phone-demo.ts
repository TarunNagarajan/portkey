import { spawn as nodeSpawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type Spawn = typeof nodeSpawn;
type DemoOptions = {
  cwd?: string;
  port?: number;
  cloudflaredPath?: string;
  spawnProcess?: Spawn;
  fetcher?: typeof fetch;
  wait?: (ms: number) => Promise<void>;
  log?: (message: string) => void;
  tunnelTimeoutMs?: number;
  readinessTimeoutMs?: number;
  portAvailable?: (port: number) => Promise<boolean>;
  built?: boolean;
  signal?: AbortSignal;
  onFailure?: (message: string) => void;
  shutdownTimeoutMs?: number;
};

export function validateTunnelUrl(value: string): string | null {
  let url: URL;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash || !/^[a-z0-9-]+\.trycloudflare\.com$/i.test(url.hostname)) return null;
  return url.origin;
}

export function demoEnvironment(port: number, publicOrigin: string, cwd = process.cwd()): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const executablePath = process.env.PATH ?? process.env.Path;
  const windowsRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT;
  if (executablePath) env.PATH = executablePath;
  if (windowsRoot) env.SystemRoot = windowsRoot;
  for (const key of ['WINDIR', 'TEMP', 'TMP', 'HOME']) if (process.env[key]) env[key] = process.env[key];
  Object.assign(env, {
    NODE_ENV: 'production', HOST: '127.0.0.1', PORT: String(port), APP_ORIGIN: publicOrigin,
    TRUST_PROXY_HOPS: '1', ALLOW_EMBEDDED_DATABASE: 'true', DATA_DIR: resolve(cwd, '.data/phone-demo'),
    PORTKEY_LOAD_DOTENV: 'false', GEOCODING: 'false',
  });
  return env;
}

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolveResult) => {
    const server = createServer();
    server.once('error', () => resolveResult(false));
    server.listen(port, '127.0.0.1', () => server.close(() => resolveResult(true)));
  });
}

function stop(child: ChildProcess, gracefulServer = false, shutdownTimeoutMs = 10_000): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolveDone) => {
    const forceTimer = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }, gracefulServer ? shutdownTimeoutMs : 3000);
    child.once('close', () => { clearTimeout(forceTimer); resolveDone(); });
    if (gracefulServer && child.connected && child.send) {
      try { child.send({ type: 'phone-demo:shutdown' }); } catch { child.kill('SIGKILL'); }
    } else child.kill();
  });
}

export async function runPhoneDemo(options: DemoOptions = {}): Promise<() => Promise<void>> {
  const cwd = options.cwd ?? process.cwd();
  const port = options.port ?? 3003;
  const log = options.log ?? console.log;
  const wait = options.wait ?? ((ms: number) => new Promise(resolveWait => setTimeout(resolveWait, ms)));
  const fetcher = options.fetcher ?? fetch;
  const spawnProcess = options.spawnProcess ?? nodeSpawn;
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Demo port must be an integer from 1024 to 65535.');
  if (!await (options.portAvailable ?? portIsFree)(port)) throw new Error(`Port ${port} is already in use. Choose another PORTKEY_DEMO_PORT; no process was stopped.`);
  if (!options.built && !existsSync(resolve(cwd, 'dist/client/index.html'))) throw new Error('Production app is not built. Run npm run build, then npm run phone:demo.');
  const executable = options.cloudflaredPath ?? process.env.CLOUDFLARED_PATH ?? 'cloudflared';
  const children: ChildProcess[] = [];
  let serverChild: ChildProcess | null = null;
  let stopped = false;
  let ready = false;
  let failureState: Error | null = null;
  let resolveFailure!: (error: Error) => void;
  const failurePromise = new Promise<Error>(resolveError => { resolveFailure = resolveError; });
  let cleanupPromise: Promise<void> | null = null;
  const cleanup = () => {
    if (cleanupPromise) return cleanupPromise;
    stopped = true;
    cleanupPromise = (async () => { await Promise.all([...children].reverse().map(child => stop(child, child === serverChild, options.shutdownTimeoutMs))); })();
    return cleanupPromise;
  };
  const reportFailure = (error: Error, name: string, code: number | null = null, signal: NodeJS.Signals | null = null) => {
    if (stopped || failureState) return;
    failureState = error;
    resolveFailure(error);
    if (ready) {
      options.onFailure?.(`${name} exited while the phone demo was running (code ${code ?? 'none'}, signal ${signal ?? 'none'}).`);
      void cleanup();
    }
  };
  const watchChild = (child: ChildProcess, name: string) => {
    child.once('error', error => {
      const missing = (error as NodeJS.ErrnoException).code === 'ENOENT' && name === 'Cloudflared';
      reportFailure(new Error(missing
        ? 'cloudflared was not found. Install it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ or set CLOUDFLARED_PATH.'
        : `${name} could not start.`), name);
    });
    child.once('close', (code, signal) => reportFailure(new Error(`${name} exited before the demo stopped.`), name, code, signal));
  };
  const cancelled = new Promise<never>((_resolve, reject) => {
    if (options.signal?.aborted) reject(new Error('Phone demo startup was cancelled.'));
    else options.signal?.addEventListener('abort', () => reject(new Error('Phone demo startup was cancelled.')), { once: true });
  });
  const tunnel = spawnProcess(executable, ['tunnel', '--no-autoupdate', '--url', `http://127.0.0.1:${port}`], {
    cwd, env: demoEnvironment(port, 'https://pending.trycloudflare.com', cwd), stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  });
  children.push(tunnel);
  watchChild(tunnel, 'Cloudflared');
  let output = '';
  const foundUrl = new Promise<string>(resolveUrl => {
    const onData = (chunk: Buffer) => {
      output = `${output}${chunk.toString('utf8')}`.slice(-16000);
      for (const match of output.matchAll(/https:\/\/[^\s"'<>]+/g)) {
        const valid = validateTunnelUrl(match[0].replace(/[),.;]+$/, ''));
        if (valid) { resolveUrl(valid); return; }
      }
    };
    tunnel.stdout?.on('data', onData);
    tunnel.stderr?.on('data', onData);
  });
  let publicOrigin: string;
  try {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      publicOrigin = await Promise.race([foundUrl, cancelled, failurePromise.then(error => { throw error; }), new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error('Timed out waiting for Cloudflare to provide a temporary HTTPS address.')), options.tunnelTimeoutMs ?? 120_000);
      })]);
    } finally { if (timeout) clearTimeout(timeout); }
    const server = spawnProcess(process.execPath, ['--import', 'tsx', resolve(cwd, 'server/index.ts')], {
      cwd, env: demoEnvironment(port, publicOrigin, cwd), stdio: ['ignore', 'inherit', 'inherit', 'ipc'], windowsHide: true,
    });
    serverChild = server;
    children.push(server);
    watchChild(server, 'Demo server');
    const deadline = Date.now() + (options.readinessTimeoutMs ?? 45_000);
    while (Date.now() < deadline) {
      if (failureState) throw failureState;
      if (server.exitCode !== null || server.signalCode !== null) throw new Error('The demo server exited during startup.');
      if (options.signal?.aborted) throw new Error('Phone demo startup was cancelled.');
      try {
        const [healthResponse, configResponse] = await Promise.race([Promise.all([
          fetcher(`${publicOrigin}/api/health`, { signal: AbortSignal.timeout(5000), redirect: 'error' }),
          fetcher(`${publicOrigin}/api/config`, { signal: AbortSignal.timeout(5000), redirect: 'error' }),
        ]), cancelled, failurePromise.then(error => { throw error; })]);
        if (healthResponse.ok && configResponse.ok) {
          const health = await healthResponse.json() as { status?: unknown };
          const publicConfig = await configResponse.json() as { publicOrigin?: unknown };
          if (failureState) throw failureState;
          if (options.signal?.aborted) throw new Error('Phone demo startup was cancelled.');
          if (health.status === 'ok' && publicConfig.publicOrigin === publicOrigin) { ready = true; break; }
        }
      } catch {}
      await wait(500);
    }
    if (!ready) throw new Error('The demo server did not become ready before the startup timeout.');
    log(`Phone demo: ${publicOrigin}`);
    log('This address is temporary. Keep this computer and this terminal running while participants use it.');
    return cleanup;
  } catch (error) {
    await cleanup();
    throw error;
  }
}

async function main() {
  const port = process.env.PORTKEY_DEMO_PORT ? Number(process.env.PORTKEY_DEMO_PORT) : 3003;
  const controller = new AbortController();
  let failureMessage = '';
  let resolveFailure!: () => void;
  const failure = new Promise<void>(resolveDone => { resolveFailure = resolveDone; });
  const onSignal = () => controller.abort();
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  let cleanup: (() => Promise<void>) | undefined;
  try {
    cleanup = await runPhoneDemo({ port, signal: controller.signal, onFailure: message => { failureMessage = message; resolveFailure(); } });
    await Promise.race([
      new Promise<void>(resolveDone => controller.signal.addEventListener('abort', () => resolveDone(), { once: true })),
      failure,
    ]);
    if (failureMessage) throw new Error(failureMessage);
  } finally {
    await cleanup?.();
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error instanceof Error ? error.message : 'Phone demo could not start.'); process.exitCode = 1; });
}

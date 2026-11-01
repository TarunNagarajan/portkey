// Local test harness only. Production uses the configured HTTPS reverse proxy.
import https from 'node:https';
import http from 'node:http';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
const directory = mkdtempSync(join(tmpdir(), 'portkey-https-'));
const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', key, '-out', cert], { stdio: 'ignore' });
const child = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], {
  env: { ...process.env, PORT: '3003', HOST: '127.0.0.1', APP_ORIGIN: 'https://localhost:5443', NODE_ENV: 'production', ALLOW_DEMO_CREDENTIALS: 'true', DATA_DIR: `.data/e2e-production-${process.pid}-${Date.now()}` }, stdio: 'inherit',
});
const server = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (request, response) => {
  const upstream = http.request({ hostname: '127.0.0.1', port: 3003, path: request.url, method: request.method, headers: { ...request.headers, host: 'localhost:5443' } }, result => {
    response.writeHead(result.statusCode ?? 502, result.headers); result.pipe(response);
  });
  upstream.on('error', () => { response.writeHead(502); response.end(); }); request.pipe(upstream);
});
server.listen(5443, '127.0.0.1');
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { server.close(); child.kill(signal); });
child.on('exit', code => { server.close(); process.exit(code ?? 1); });

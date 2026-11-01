// An isolated HTTP load probe against the real PostgreSQL driver.
import { performance } from 'node:perf_hooks';
import { mkdir, writeFile } from 'node:fs/promises';
import { createApp } from '../server/app.js';
import { migrate } from '../server/migrations.js';
import { openDatabase } from '../tests/database.js';
if (!process.env.TEST_DATABASE_URL) throw new Error('Set TEST_DATABASE_URL to a test PostgreSQL database.');
const database = await openDatabase(); await migrate(database);
const servers = [createApp(database, { origin: 'http://localhost', secure: false }), createApp(database, { origin: 'http://localhost', secure: false })].map(app => app.listen(0, '127.0.0.1'));
await Promise.all(servers.map(server => new Promise<void>(resolve => server.on('listening', resolve))));
try {
  const bases = servers.map(server => `http://127.0.0.1:${(server.address() as {port: number}).port}`);
  const samples: number[] = []; const counts: Record<string, number> = {};
  const start = performance.now();
  for (let batch = 0; batch < 10; batch++) await Promise.all(Array.from({ length: 20 }, async (_, i) => {
    const before = performance.now(); const response = await fetch(`${bases[i % 2]}/api/session`, { method: 'POST', headers: { Origin: 'http://localhost' } });
    samples.push(performance.now() - before); counts[response.status] = (counts[response.status] ?? 0) + 1;
  }));
  samples.sort((a, b) => a - b);
  const result = { requests: 200, concurrency: 20, instances: 2, counts, durationMs: performance.now() - start, p50Ms: samples[99], p95Ms: samples[189], measuredAt: new Date().toISOString() };
  if (counts['200'] !== 30 || counts['429'] !== 170) throw new Error(`Shared rate-limit mismatch: ${JSON.stringify(counts)}`);
  await mkdir('benchmark-results', { recursive: true }); await writeFile('benchmark-results/postgres-load.json', JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} finally {
  await Promise.all(servers.map(server => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))));
  await database.close();
}

import express from 'express';
import { resolve } from 'node:path';
import { createApp } from '../server/app.js';
import { openDatabase } from '../server/database.js';
import { migrate } from '../server/migrations.js';

const port = Number(process.env.PORTKEY_BUILT_ASSETS_PORT ?? 5175);
const origin = `http://localhost:${port}`;
const database = await openDatabase();
await migrate(database);
const app = createApp(database, { origin, secure: false, rateLimiting: false });
const clientDirectory = resolve('dist/client');
app.use(express.static(clientDirectory));
app.get('/{*path}', (request, response, next) => {
  if (request.path.startsWith('/api/')) return next();
  response.sendFile(resolve(clientDirectory, 'index.html'));
});
const server = app.listen(port, '127.0.0.1');

async function stop() {
  await new Promise<void>((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  await database.close();
  process.exit(0);
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => void stop());

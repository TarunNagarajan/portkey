import express from 'express';
import { resolve } from 'node:path';
import { createApp } from './app.js';
import { config } from './config.js';
import { openDatabase } from './database.js';
import { migrate } from './migrations.js';
import { runSubmissionCleanupPass, startCleanupScheduler } from './cleanup.js';

const database = await openDatabase({ url: config.databaseUrl, dataDir: config.dataDir });
await migrate(database);
const app = createApp(database, {
  origin: config.origin,
  secure: config.production,
  trustProxyHops: config.trustProxyHops,
  geocoding: config.geocoding,
  nominatimUrl: config.nominatimUrl,
});
const cleanup = startCleanupScheduler(() => runSubmissionCleanupPass(database));
if (config.production) {
  app.use(express.static(resolve('dist/client')));
  app.get('/{*path}', (_request, response) => response.sendFile(resolve('dist/client/index.html')));
}
const server = app.listen(config.port, config.host, () => console.log(`Portkey API listening on ${config.host}:${config.port}`));
let stopping = false;
function stopServer() {
  if (stopping) return;
  stopping = true;
  const cleanupDrain = cleanup.stop();
  server.close(() => {
    void cleanupDrain.then(() => database.close()).then(() => process.exit(0));
  });
}
process.on('message', (message: unknown) => {
  if (message && typeof message === 'object' && !Array.isArray(message) &&
      Object.keys(message).length === 1 && 'type' in message && message.type === 'phone-demo:shutdown') stopServer();
});
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, stopServer);
}

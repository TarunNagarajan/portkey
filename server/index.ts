import express from 'express';
import { resolve } from 'node:path';
import { createApp } from './app.js';
import { config } from './config.js';
import { openDatabase } from './database.js';
import { migrate } from './migrations.js';
import { runFileCleanupPass, startCleanupScheduler } from './cleanup.js';

const database = await openDatabase({ url: config.databaseUrl, dataDir: config.dataDir });
await migrate(database);
const app = createApp(database, {
  origin: config.origin,
  trustProxyHops: config.trustProxyHops,
  metricsToken: config.metricsToken,
  secure: config.production,
  geocoding: config.geocoding,
  nominatimUrl: config.nominatimUrl,
});
const cleanup = startCleanupScheduler(() => runFileCleanupPass(database));
if (config.production) {
  app.use(express.static(resolve('dist/client')));
  app.get('/{*path}', (_request, response) => response.sendFile(resolve('dist/client/index.html')));
}
const server = app.listen(config.port, config.host, () => console.log(`Portkey API: http://${config.host}:${config.port}`));
let stopping = false;
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    if (stopping) return;
    stopping = true;
    const cleanupDrain = cleanup.stop();
    server.close(() => {
      void cleanupDrain.then(() => database.close()).then(() => process.exit(0));
    });
  });
}

import { config } from './config.js';
import { openDatabase } from './database.js';
import { migrate } from './migrations.js';

const database = await openDatabase({ url: config.databaseUrl, dataDir: config.dataDir });
try {
  await migrate(database);
  console.log('Database migrations applied.');
} finally { await database.close(); }

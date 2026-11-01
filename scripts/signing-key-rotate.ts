import { config } from '../server/config.js';
import { openDatabase } from '../server/database.js';
import { migrate } from '../server/migrations.js';
import { rotateSigningKey } from '../server/platformCrypto.js';

const args = process.argv.slice(2);
if (args.some((argument) => argument !== '--offline-embedded'))
  throw new Error('Usage: npm run signing-keys:rotate [-- --offline-embedded]');
const offlineEmbedded = args.includes('--offline-embedded');
if (!config.databaseUrl && !offlineEmbedded)
  throw new Error('No DATABASE_URL is configured. For embedded rotation, stop the local Portkey server first, then rerun with --offline-embedded.');
if (config.databaseUrl && offlineEmbedded)
  throw new Error('--offline-embedded is only valid when DATABASE_URL is not configured.');

const database = await openDatabase({ url: config.databaseUrl, dataDir: config.dataDir });
try {
  await migrate(database);
  await rotateSigningKey(database);
  console.log('Platform receipt signing key rotated.');
} finally {
  await database.close();
}

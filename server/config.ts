import 'dotenv/config';
import { z } from 'zod';

const environment = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  APP_ORIGIN: z.url().default('http://localhost:5173'),
  DATABASE_URL: z.string().min(1).optional(),
  DATA_DIR: z.string().min(1).default('.data/portkey'),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development')
}).parse(process.env);

export const config = {
  port: environment.PORT,
  origin: new URL(environment.APP_ORIGIN).origin,
  databaseUrl: environment.DATABASE_URL,
  dataDir: environment.DATA_DIR,
  production: environment.NODE_ENV === 'production'
};

if (config.production && !config.origin.startsWith('https://')) {
  throw new Error('Production requires an HTTPS APP_ORIGIN.');
}

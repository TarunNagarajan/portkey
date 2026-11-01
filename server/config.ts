import 'dotenv/config';
import { z } from 'zod';

const environment = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  APP_ORIGIN: z.url().default('http://localhost:5173'),
  DATABASE_URL: z.string().min(1).optional(),
  DATA_DIR: z.string().min(1).default('.data/portkey'),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  GEOCODING: z.enum(['true', 'false']).default('true').transform(value => value === 'true'),
  NOMINATIM_URL: z.url().default('https://nominatim.openstreetmap.org'),
  ISSUER_PUBLIC_KEY: z.preprocess(value => value === '' ? undefined : value, z.string().min(1).optional()),
  METRICS_TOKEN: z.preprocess(value => value === '' ? undefined : value, z.string().min(32).optional()),
  ALLOW_DEMO_CREDENTIALS: z.enum(['true', 'false']).default('false').transform(value => value === 'true'),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(3).default(0),
  HOST: z.string().min(1).default('127.0.0.1')
}).parse(process.env);

export const config = {
  port: environment.PORT,
  host: environment.HOST,
  trustProxyHops: environment.TRUST_PROXY_HOPS,
  origin: new URL(environment.APP_ORIGIN).origin,
  databaseUrl: environment.DATABASE_URL,
  dataDir: environment.DATA_DIR,
  production: environment.NODE_ENV === 'production',
  geocoding: environment.GEOCODING,
  nominatimUrl: environment.NOMINATIM_URL,
  issuerPublicKey: environment.ISSUER_PUBLIC_KEY,
  metricsToken: environment.METRICS_TOKEN,
  allowDemoCredentials: environment.ALLOW_DEMO_CREDENTIALS
};

if (config.production && !config.origin.startsWith('https://')) {
  throw new Error('Production requires an HTTPS APP_ORIGIN.');
}

if (config.production && !config.issuerPublicKey && !config.allowDemoCredentials) {
  throw new Error('Production requires ISSUER_PUBLIC_KEY. Set ALLOW_DEMO_CREDENTIALS=true only for a public course demo.');
}

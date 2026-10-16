import { isIP } from 'node:net';
import { z } from 'zod';

const optional = (value: unknown) => typeof value === 'string' && value.trim() === '' ? undefined : value;
const inputSchema = z.object({
  PORT: z.preprocess(optional, z.coerce.number().int().min(1).max(65535).default(3001)),
  APP_ORIGIN: z.preprocess(optional, z.string().optional()),
  RENDER_EXTERNAL_URL: z.preprocess(optional, z.string().optional()),
  DATABASE_URL: z.preprocess(optional, z.string().min(1).optional()),
  DATA_DIR: z.preprocess(optional, z.string().min(1).default('.data/portkey')),
  HOST: z.preprocess(optional, z.string().optional()),
  TRUST_PROXY_HOPS: z.preprocess(optional, z.coerce.number().int().min(0).max(2).default(0)),
  ALLOW_EMBEDDED_DATABASE: z.preprocess(optional, z.enum(['true', 'false']).default('false')).transform(value => value === 'true'),
  NODE_ENV: z.preprocess(optional, z.enum(['development', 'test', 'production']).default('development')),
  GEOCODING: z.preprocess(optional, z.enum(['true', 'false']).default('true')).transform(value => value === 'true'),
  NOMINATIM_URL: z.preprocess(optional, z.url().default('https://nominatim.openstreetmap.org')),
});

function validOrigin(value: string, production: boolean): string {
  if (value !== value.trim()) throw new Error('APP_ORIGIN must be a valid HTTP or HTTPS origin.');
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('APP_ORIGIN must be a valid HTTP or HTTPS origin.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash)
    throw new Error('APP_ORIGIN must contain only an HTTP or HTTPS origin.');
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const isLoopback = hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '127.0.0.1' || hostname === '::1' || /^127\./.test(hostname);
  const localName = /(^|\.)(local|internal|test|example|invalid|localhost|home|lan|onion)$/.test(hostname) || hostname.endsWith('.home.arpa') || hostname === 'home.arpa' || hostname === '0.0.0.0';
  const ipLiteral = isIP(hostname) !== 0;
  const singleLabel = !hostname.includes('.');
  const validDnsName = hostname.length <= 253 && hostname.split('.').every(label => label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
  if (production && (url.protocol !== 'https:' || isLoopback || localName || ipLiteral || singleLabel || !validDnsName))
    throw new Error('Production APP_ORIGIN must be a public HTTPS DNS origin.');
  if (url.protocol === 'https:' && url.port === '443') url.port = '';
  if (url.protocol === 'http:' && url.port === '80') url.port = '';
  return url.origin;
}

function validHost(host: string): string {
  if (!host || /[\s/\\?#@]/.test(host) || (!isIP(host) && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/i.test(host)))
    throw new Error('HOST must be a usable bind address or hostname.');
  return host;
}

function validDatabaseUrl(value?: string): string | undefined {
  if (!value) return undefined;
  if (value !== value.trim()) throw new Error('DATABASE_URL must be a valid PostgreSQL connection URL.');
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('DATABASE_URL must be a valid PostgreSQL connection URL.'); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname)
    throw new Error('DATABASE_URL must be a valid PostgreSQL connection URL.');
  return value;
}

export function parseConfiguration(source: NodeJS.ProcessEnv) {
  const parsed = inputSchema.safeParse(source);
  if (!parsed.success) throw new Error('Application configuration is invalid. Check the documented environment settings.');
  const env = parsed.data;
  const production = env.NODE_ENV === 'production';
  const selectedOrigin = env.APP_ORIGIN ?? (production ? env.RENDER_EXTERNAL_URL : undefined) ?? (production ? undefined : 'http://localhost:5173');
  if (!selectedOrigin) throw new Error('Production requires APP_ORIGIN or Render RENDER_EXTERNAL_URL.');
  const databaseUrl = validDatabaseUrl(env.DATABASE_URL);
  if (production && !databaseUrl && !env.ALLOW_EMBEDDED_DATABASE)
    throw new Error('Production requires DATABASE_URL unless ALLOW_EMBEDDED_DATABASE=true is explicitly set.');
  return {
    port: env.PORT,
    host: validHost(env.HOST ?? (production ? '0.0.0.0' : '127.0.0.1')),
    origin: validOrigin(selectedOrigin, production),
    databaseUrl,
    dataDir: env.DATA_DIR,
    production,
    trustProxyHops: env.TRUST_PROXY_HOPS,
    geocoding: env.GEOCODING,
    nominatimUrl: env.NOMINATIM_URL,
  };
}

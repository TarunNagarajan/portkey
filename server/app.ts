import express, { type ErrorRequestHandler } from 'express';
import helmet from 'helmet';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import { ZodError } from 'zod';
import type { Database } from './database.js';
import { HttpError } from './errors.js';
import { createGeocoder } from './geocoding.js';
import { DatabaseRateStore } from './rateStore.js';
import { operationsRoutes } from './operations.js';
import { recoveryRoutes } from './recovery.js';
import { issuerRoutes } from './issuerRoutes.js';
import { roomRoutes } from './rooms.js';
import { roomFileRoutes } from './roomFiles.js';
import { keyRoutes } from './keys.js';
import { sessionControls } from './sessions.js';

export interface AppOptions {
  origin: string;
  secure: boolean;
  rateLimiting?: boolean;
  geocoding?: boolean;
  nominatimUrl?: string;
  trustProxyHops?: number;
  metricsToken?: string;
}

export function createApp(database: Database, options: AppOptions) {
  const app = express();
  const sessions = sessionControls(database, options);
  app.disable('x-powered-by');
  app.set('trust proxy', options.trustProxyHops ?? 0);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          // Credential proofs compile WebAssembly and run the prover in a blob
          // worker. Everything else keeps Helmet's defaults.
          'script-src': ["'self'", "'wasm-unsafe-eval'"],
          'worker-src': ["'self'", 'blob:'],
        },
      },
    }),
  );
  app.use(express.json({ limit: '256kb' }));
  app.use('/api', (_request, response, next) => {
    response.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.get('/api/health', async (_request, response) => {
    await database.query('SELECT 1');
    response.json({ status: 'ok' });
  });
  app.use('/api', sessions.load);
  if (options.rateLimiting !== false) {
    app.use('/api', rateLimit({ store: new DatabaseRateStore(database, 'general'), windowMs: 60_000, limit: request => request.session ? 120 : 600,
      // A supported 250-chunk file needs more than 120 requests. File chunks
      // have their own bounded budget below.
      skip: request => ['GET', 'PUT'].includes(request.method) && /^\/rooms\/[^/]+\/files\/[^/]+\/chunks\/[^/]+$/.test(request.path),
      keyGenerator: request => request.session?.id ?? ipKeyGenerator(request.ip ?? '127.0.0.1'),
      standardHeaders: 'draft-8', legacyHeaders: false,
      message: { error: { code: 'RATE_LIMITED', message: 'Too many requests. Please wait a minute.' } } }));
  }
  if (options.rateLimiting !== false) {
    // A new cookie must not reset the IP's session-creation budget.
    app.post('/api/session', rateLimit({ store: new DatabaseRateStore(database, 'sessions'), windowMs: 60_000, limit: 30,
      skip: request => Boolean(request.session),
      standardHeaders: 'draft-8', legacyHeaders: false,
      message: { error: { code: 'RATE_LIMITED', message: 'Too many session requests. Please wait a minute.' } } }));
  }
  app.post('/api/session', sessions.checkOrigin, sessions.start);
  app.use('/api', operationsRoutes(database, options.metricsToken));
  app.use('/api', issuerRoutes(database));
  app.use('/api', sessions.authenticate);
  app.use('/api', (request, response, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return next();
    sessions.checkOrigin(request, response, () => sessions.checkCsrf(request, response, next));
  });
  app.use('/api', roomRoutes(database, createGeocoder(options.geocoding !== false, options.nominatimUrl)));
  app.use('/api', keyRoutes(database));
  app.use('/api', recoveryRoutes(database));
  if (options.rateLimiting !== false) {
    app.use('/api/rooms/:roomId/files/:fileId/chunks/:index', rateLimit({
      store: new DatabaseRateStore(database, 'chunks'), windowMs: 60_000, limit: 600,
      keyGenerator: request => request.session!.id,
      standardHeaders: 'draft-8', legacyHeaders: false,
      message: { error: { code: 'RATE_LIMITED', message: 'Too many file chunks. Please wait a minute.' } },
    }));
  }
  app.use('/api', roomFileRoutes(database));
  app.use('/api', (_request, response) => {
    response.status(404).json({ error: { code: 'NOT_FOUND', message: 'API endpoint not found.' } });
  });
  const handleError: ErrorRequestHandler = (error, _request, response, _next) => {
    if (error instanceof ZodError) {
      response.status(422).json({ error: { code: 'INVALID_INPUT', message: error.issues.map(issue => `${issue.path.join('.') || 'input'}: ${issue.message}`).join('; ') } });
    } else if (error instanceof HttpError) {
      response.status(error.status).json({ error: { code: error.code, message: error.message } });
    } else if (error.type === 'entity.parse.failed' || error.type === 'entity.too.large') {
      response.status(error.type === 'entity.too.large' ? 413 : 400).json({ error: { code: 'INVALID_BODY', message: 'Request body is invalid or too large.' } });
    } else {
      console.error('API request failed', { name: error instanceof Error ? error.name : 'UnknownError' });
      response.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong. Please try again.' } });
    }
  };
  app.use(handleError);
  return app;
}

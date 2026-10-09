import express, { type ErrorRequestHandler } from 'express';
import helmet from 'helmet';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import { ZodError } from 'zod';
import type { Database } from './database.js';
import { HttpError } from './errors.js';
import { roomRoutes } from './rooms.js';
import { sessionControls } from './sessions.js';

export interface AppOptions { origin: string; secure: boolean; rateLimiting?: boolean }

export function createApp(database: Database, options: AppOptions) {
  const app = express();
  const sessions = sessionControls(database, options);
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(express.json({ limit: '8kb' }));
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
    app.use('/api', rateLimit({ windowMs: 60_000, limit: request => request.session ? 120 : 600,
      keyGenerator: request => request.session?.id ?? ipKeyGenerator(request.ip ?? '127.0.0.1'),
      standardHeaders: 'draft-8', legacyHeaders: false,
      message: { error: { code: 'RATE_LIMITED', message: 'Too many requests. Please wait a minute.' } } }));
  }
  app.post('/api/session', sessions.checkOrigin, sessions.start);
  app.use('/api', sessions.authenticate);
  app.use('/api', (request, response, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return next();
    sessions.checkOrigin(request, response, () => sessions.checkCsrf(request, response, next));
  });
  app.use('/api', roomRoutes(database));
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
      console.error(error);
      response.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong. Please try again.' } });
    }
  };
  app.use(handleError);
  return app;
}

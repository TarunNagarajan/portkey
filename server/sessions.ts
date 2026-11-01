import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { parse, serialize } from 'cookie';
import type { Request, Response, NextFunction } from 'express';
import type { Database } from './database.js';
import { requireCondition } from './errors.js';

interface Session { id: string; expiresAt: Date; csrfToken: string }

declare global {
  namespace Express {
    interface Request { session?: Session }
  }
}

const digest = (value: string) => createHash('sha256').update(value).digest('hex');

export function sessionControls(database: Database, options: { origin: string; secure: boolean }) {
  const cookieName = options.secure ? '__Host-portkey_session' : 'portkey_session';

  async function load(request: Request, _response: Response, next: NextFunction) {
    const token = parse(request.headers.cookie ?? '')[cookieName];
    if (token && /^[A-Za-z0-9_-]{43}$/.test(token)) {
      const [row] = await database.query<{ id: string; expires_at: Date }>(
        'SELECT id, expires_at FROM sessions WHERE token_hash = $1 AND expires_at > clock_timestamp()', [digest(token)]
      );
      if (row) request.session = { id: row.id, expiresAt: row.expires_at, csrfToken: digest(`csrf:${token}`) };
    }
    next();
  }

  function checkOrigin(request: Request, _response: Response, next: NextFunction) {
    requireCondition(request.get('origin') === options.origin, 403, 'ORIGIN_REJECTED', 'Request origin is not allowed.');
    next();
  }

  function authenticate(request: Request, _response: Response, next: NextFunction) {
    requireCondition(request.session, 401, 'SESSION_REQUIRED', 'Start a browser session first.');
    next();
  }

  function checkCsrf(request: Request, _response: Response, next: NextFunction) {
    const expected = request.session?.csrfToken ?? '';
    const received = request.get('x-csrf-token') ?? '';
    requireCondition(/^[a-f0-9]{64}$/.test(received) && expected.length === received.length &&
      timingSafeEqual(Buffer.from(expected), Buffer.from(received)), 403, 'CSRF_REJECTED', 'Reload the page and try again.');
    next();
  }

  async function start(request: Request, response: Response) {
    if (!request.session) {
      const token = randomBytes(32).toString('base64url');
      const id = randomUUID();
      const [row] = await database.query<{ expires_at: Date }>(
        `INSERT INTO sessions (id, token_hash, expires_at)
         VALUES ($1, $2, clock_timestamp() + interval '30 days') RETURNING expires_at`, [id, digest(token)]
      );
      request.session = { id, expiresAt: row.expires_at, csrfToken: digest(`csrf:${token}`) };
      response.setHeader('Set-Cookie', serialize(cookieName, token, {
        httpOnly: true, secure: options.secure, sameSite: 'strict', path: '/', expires: row.expires_at
      }));
    }
    response.json({ csrfToken: request.session.csrfToken, expiresAt: request.session.expiresAt.toISOString() });
  }

  return { load, checkOrigin, authenticate, checkCsrf, start };
}

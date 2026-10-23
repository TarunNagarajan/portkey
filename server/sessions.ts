import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { parse, serialize } from "cookie";
import type { Request, Response, NextFunction } from "express";
import type { Database } from "./database.js";
import { requireCondition } from "./errors.js";

interface Session {
  id: string;
  expiresAt: Date;
  csrfToken: string;
}
interface Organizer {
  id: string;
  accountId: string;
  sessionId: string;
  expiresAt: Date;
  verifiedAt: Date;
}

declare global {
  namespace Express {
    interface Request {
      session?: Session;
      organizer?: Organizer;
      ownerId: string | null;
    }
  }
}

const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");

export function sessionControls(
  database: Database,
  options: { origin: string; secure: boolean },
) {
  const cookieName = options.secure
    ? "__Host-portkey_session"
    : "portkey_session";

  async function load(
    request: Request,
    _response: Response,
    next: NextFunction,
  ) {
    request.ownerId = null;
    const token = parse(request.headers.cookie ?? "")[cookieName];
    if (token && /^[A-Za-z0-9_-]{43}$/.test(token)) {
      const [row] = await database.query<{ id: string; expires_at: Date }>(
        "SELECT id, expires_at FROM sessions WHERE token_hash = $1 AND expires_at > clock_timestamp()",
        [digest(token)],
      );
      if (row)
        request.session = {
          id: row.id,
          expiresAt: row.expires_at,
          csrfToken: digest(`csrf:${token}`),
        };
    }
    const organizerToken = parse(request.headers.cookie ?? "")[
      organizerCookieName(options.secure)
    ];
    if (organizerToken && /^[A-Za-z0-9_-]{43}$/.test(organizerToken)) {
      const [organizer] = await database.query<{
        id: string;
        account_id: string;
        session_id: string;
        expires_at: Date;
        verified_at: Date;
        owner_session_id: string;
      }>(
        `SELECT os.id, os.account_id, os.id AS session_id, os.expires_at, os.verified_at, oa.owner_session_id
         FROM organizer_sessions os JOIN organizer_accounts oa ON oa.id=os.account_id
         WHERE os.token_digest=$1 AND os.expires_at>clock_timestamp() AND os.auth_generation=oa.auth_generation`,
        [Buffer.from(digest(organizerToken), "hex")],
      );
      if (organizer && request.session) {
        request.organizer = {
          id: organizer.id,
          accountId: organizer.account_id,
          sessionId: organizer.session_id,
          expiresAt: organizer.expires_at,
          verifiedAt: organizer.verified_at,
        };
        request.ownerId = organizer.owner_session_id;
        await database.query(
          "UPDATE organizer_sessions SET last_used_at=clock_timestamp() WHERE id=$1",
          [organizer.id],
        );
      }
    }
    if (request.session && !request.organizer) {
      const [owner] = await database.query<{
        available: boolean;
        account_id: string | null;
      }>("SELECT available,account_id FROM owner_authorities WHERE id=$1", [
        request.session.id,
      ]);
      if (owner?.available && owner.account_id === null)
        request.ownerId = request.session.id;
    }
    next();
  }

  function checkOrigin(
    request: Request,
    _response: Response,
    next: NextFunction,
  ) {
    requireCondition(
      request.get("origin") === options.origin,
      403,
      "ORIGIN_REJECTED",
      "Request origin is not allowed.",
    );
    next();
  }

  function authenticate(
    request: Request,
    _response: Response,
    next: NextFunction,
  ) {
    requireCondition(
      request.session,
      401,
      "SESSION_REQUIRED",
      "Start a browser session first.",
    );
    next();
  }

  function checkCsrf(
    request: Request,
    _response: Response,
    next: NextFunction,
  ) {
    const expected = request.session?.csrfToken ?? "";
    const received = request.get("x-csrf-token") ?? "";
    requireCondition(
      /^[a-f0-9]{64}$/.test(received) &&
        expected.length === received.length &&
        timingSafeEqual(Buffer.from(expected), Buffer.from(received)),
      403,
      "CSRF_REJECTED",
      "Reload the page and try again.",
    );
    next();
  }

  async function start(request: Request, response: Response) {
    if (!request.session) {
      const token = randomBytes(32).toString("base64url");
      const id = randomUUID();
      const [row] = await database.query<{ expires_at: Date }>(
        `INSERT INTO sessions (id, token_hash, expires_at)
         VALUES ($1, $2, clock_timestamp() + interval '30 days') RETURNING expires_at`,
        [id, digest(token)],
      );
      request.session = {
        id,
        expiresAt: row.expires_at,
        csrfToken: digest(`csrf:${token}`),
      };
      response.setHeader(
        "Set-Cookie",
        serialize(cookieName, token, {
          httpOnly: true,
          secure: options.secure,
          sameSite: "strict",
          path: "/",
          expires: row.expires_at,
        }),
      );
    }
    response.json({
      csrfToken: request.session.csrfToken,
      expiresAt: request.session.expiresAt.toISOString(),
    });
  }

  return { load, checkOrigin, authenticate, checkCsrf, start };
}

export function organizerCookieName(secure: boolean) {
  return secure ? "__Host-portkey_organizer" : "portkey_organizer";
}
export { digest as tokenDigest };

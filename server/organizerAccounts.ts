import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { serialize } from "cookie";
import {
  Router,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import { z } from "zod";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type WebAuthnCredential,
  type AuthenticatorTransport,
} from "@simplewebauthn/server";
import type { Database, Queries } from "./database.js";
import { HttpError, requireCondition } from "./errors.js";
import { organizerCookieName, tokenDigest } from "./sessions.js";

const token = () => randomBytes(32).toString("base64url");
const hash = (value: string) => createHash("sha256").update(value).digest();
const rpId = (origin: string) => new URL(origin).hostname;
const inputResponse = z
  .object({
    response: z.record(z.string(), z.unknown()),
    label: z.string().trim().min(1).max(64).optional(),
  })
  .strict();
const recoveryInput = z
  .object({
    recoveryKey: z
      .string()
      .regex(/^pk_recovery_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/i),
  })
  .strict();
type Ceremony = {
  id: string;
  challenge: string;
  kind: string;
  browser_session_id: string;
  organizer_session_id: string | null;
  account_id: string | null;
  auth_generation: number | null;
  recovery_digest: Buffer | null;
  prospective_account_id: string | null;
  prospective_user_handle: Buffer | null;
  target_credential_id: string | null;
};
type CredentialRow = {
  credential_id: string;
  account_id: string;
  public_key: Buffer;
  counter: string | number;
  transports: string[];
  device_type: "singleDevice" | "multiDevice";
  backed_up: boolean;
  label: string;
};

function cookie(
  response: Response,
  secure: boolean,
  value: string,
  expires?: Date,
) {
  response.setHeader(
    "Set-Cookie",
    serialize(organizerCookieName(secure), value, {
      httpOnly: true,
      secure,
      sameSite: "strict",
      path: "/",
      ...(expires ? { expires } : {}),
    }),
  );
}
function removeCookie(response: Response, secure: boolean) {
  cookie(response, secure, "", new Date(0));
}
function secretKey(accountId: string) {
  return `pk_recovery_${accountId}.${token()}`;
}
function secretDigest(value: string) {
  return hash(value);
}
function genericAuthError(): never {
  throw new HttpError(
    401,
    "AUTHENTICATION_FAILED",
    "Passkey or recovery key could not be verified.",
  );
}

export function organizerAccountRoutes(
  database: Database,
  options: { origin: string; secure: boolean },
  guards: {
    checkOrigin: (req: Request, res: Response, next: NextFunction) => void;
    checkCsrf: (req: Request, res: Response, next: NextFunction) => void;
  },
) {
  const router = Router();
  const secureRequest = (req: Request, res: Response, next: NextFunction) =>
    guards.checkOrigin(req, res, () => guards.checkCsrf(req, res, next));
  const requireBrowser = (req: Request) =>
    requireCondition(
      req.session,
      401,
      "SESSION_REQUIRED",
      "Start a browser session first.",
    );
  const activeAccount = (req: Request) =>
    requireCondition(
      req.organizer && req.ownerId,
      401,
      "ACCOUNT_REQUIRED",
      "Sign in with your passkey to manage organizer access.",
    );
  const requireFresh = async (tx: Queries, req: Request) => {
    activeAccount(req);
    await tx.query("SELECT id FROM organizer_accounts WHERE id=$1 FOR UPDATE", [
      req.organizer!.accountId,
    ]);
    const [session] = await tx.query<{ valid: boolean }>(
      `SELECT os.expires_at > clock_timestamp()
        AND os.auth_generation = $3
        AND os.verified_at > clock_timestamp() - interval '5 minutes' AS valid
      FROM organizer_sessions os
      WHERE os.id = $1 AND os.account_id = $2
      FOR UPDATE`,
      [
        req.organizer!.id,
        req.organizer!.accountId,
        (
          await tx.query<{ auth_generation: number }>(
            "SELECT auth_generation FROM organizer_accounts WHERE id=$1",
            [req.organizer!.accountId],
          )
        )[0]?.auth_generation,
      ],
    );
    requireCondition(
      session?.valid,
      401,
      "RECENT_VERIFICATION_REQUIRED",
      "Verify with your passkey again to continue.",
    );
  };
  const saveCeremony = async (
    req: Request,
    kind: string,
    challenge: string,
    extras: Partial<Ceremony> = {},
  ) => {
    const browserId = req.session!.id;
    return database.transaction(async (tx) => {
      await tx.query("SELECT id FROM sessions WHERE id=$1 FOR UPDATE", [
        browserId,
      ]);
      await tx.query(
        "DELETE FROM organizer_ceremonies WHERE expires_at<=clock_timestamp() OR consumed_at<clock_timestamp()-interval '1 day'",
      );
      const [count] = await tx.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM organizer_ceremonies WHERE browser_session_id=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()",
        [browserId],
      );
      requireCondition(
        count.count < 10,
        429,
        "CEREMONY_LIMIT",
        "Too many passkey attempts are active in this browser. Wait a few minutes and try again.",
      );
      const id = randomUUID();
      await tx.query(
        `INSERT INTO organizer_ceremonies(id,challenge,kind,browser_session_id,organizer_session_id,account_id,auth_generation,recovery_digest,prospective_account_id,prospective_user_handle,target_credential_id,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp()+interval '5 minutes')`,
        [
          id,
          challenge,
          kind,
          browserId,
          extras.organizer_session_id ?? null,
          extras.account_id ?? null,
          extras.auth_generation ?? null,
          extras.recovery_digest ?? null,
          extras.prospective_account_id ?? null,
          extras.prospective_user_handle ?? null,
          extras.target_credential_id ?? null,
        ],
      );
      return id;
    });
  };
  const registrationOptions = async (
    req: Request,
    kind: string,
    accountId: string | null,
    userHandle: Buffer,
    userName: string,
    extras: Partial<Ceremony> = {},
  ) => {
    const challenge = token();
    const exclude = accountId
      ? await database.query<{ credential_id: string; transports: string[] }>(
          "SELECT credential_id,transports FROM organizer_credentials WHERE account_id=$1",
          [accountId],
        )
      : [];
    const publicKey = await generateRegistrationOptions({
      rpName: "Portkey",
      rpID: rpId(options.origin),
      userName,
      userDisplayName: "Portkey organizer",
      userID: new Uint8Array(userHandle),
      challenge,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      excludeCredentials: exclude.map((c) => ({
        id: c.credential_id,
        transports: c.transports,
      })),
    });
    const ceremonyId = await saveCeremony(req, kind, publicKey.challenge, {
      ...extras,
      account_id: accountId,
      prospective_user_handle: userHandle,
    });
    return { ceremonyId, options: publicKey };
  };
  const sessionCookie = async (
    tx: Queries,
    response: Response,
    accountId: string,
    generation: number,
    fresh = true,
  ) => {
    await tx.query("SELECT id FROM organizer_accounts WHERE id=$1 FOR UPDATE", [
      accountId,
    ]);
    const [count] = await tx.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM organizer_sessions WHERE account_id=$1 AND expires_at>clock_timestamp()",
      [accountId],
    );
    if (count.count >= 20)
      await tx.query(
        "DELETE FROM organizer_sessions WHERE id=(SELECT id FROM organizer_sessions WHERE account_id=$1 AND expires_at>clock_timestamp() ORDER BY last_used_at ASC LIMIT 1)",
        [accountId],
      );
    const raw = token();
    const [created] = await tx.query<{ expires_at: Date }>(
      `INSERT INTO organizer_sessions(id,account_id,token_digest,auth_generation,expires_at,verified_at)
      VALUES($1,$2,$3,$4,clock_timestamp()+interval '7 days',clock_timestamp()) RETURNING expires_at`,
      [
        randomUUID(),
        accountId,
        Buffer.from(tokenDigest(raw), "hex"),
        generation,
      ],
    );
    cookie(response, options.secure, raw, created.expires_at);
    return fresh;
  };
  const consumeCeremony = async (
    tx: Queries,
    req: Request,
    id: string,
    kinds: string[],
  ) => {
    const [browser] = await tx.query<{ id: string }>(
      "SELECT id FROM sessions WHERE id=$1 AND expires_at>clock_timestamp() FOR UPDATE",
      [req.session!.id],
    );
    requireCondition(
      browser,
      401,
      "SESSION_EXPIRED",
      "This browser session expired. Start a new passkey attempt.",
    );
    const [row] = await tx.query<Ceremony>(
      `SELECT * FROM organizer_ceremonies WHERE id=$1 AND browser_session_id=$2 AND kind=ANY($3::text[]) AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE`,
      [id, req.session!.id, kinds],
    );
    requireCondition(
      row,
      400,
      "CEREMONY_INVALID",
      "This passkey attempt expired or was already used. Start again.",
    );
    if (["reauth", "add_passkey"].some((kind) => kinds.includes(kind)))
      requireCondition(
        req.organizer && row.organizer_session_id === req.organizer.id,
        400,
        "CEREMONY_INVALID",
        "This passkey attempt is no longer available. Start again.",
      );
    return row;
  };
  const markConsumed = async (tx: Queries, ceremonyId: string) => {
    const [row] = await tx.query<{ id: string }>(
      `UPDATE organizer_ceremonies SET consumed_at=clock_timestamp()
      WHERE id=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING id`,
      [ceremonyId],
    );
    requireCondition(
      row,
      400,
      "CEREMONY_INVALID",
      "This passkey attempt expired or was already used. Start again.",
    );
  };
  const verifyRegistration = async (
    response: Record<string, unknown>,
    challenge: string,
  ) => {
    guardResponse(response);
    let result;
    try {
      result = await verifyRegistrationResponse({
        response: response as never,
        expectedChallenge: challenge,
        expectedOrigin: options.origin,
        expectedRPID: rpId(options.origin),
        requireUserVerification: true,
      });
    } catch {
      genericAuthError();
    }
    requireCondition(
      result.verified && result.registrationInfo.userVerified,
      401,
      "PASSKEY_REJECTED",
      "The authenticator did not verify its user. Try again with device unlock enabled.",
    );
    return result.registrationInfo;
  };
  const addCredential = async (
    tx: Queries,
    accountId: string,
    info: Awaited<ReturnType<typeof verifyRegistration>>,
    label: string,
  ) => {
    const [count] = await tx.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM organizer_credentials WHERE account_id=$1",
      [accountId],
    );
    requireCondition(
      count.count < 10,
      409,
      "PASSKEY_LIMIT",
      "This account already has 10 passkeys. Remove one before adding another.",
    );
    const credentialId = info.credential.id;
    const decoded = Buffer.from(credentialId, "base64url");
    requireCondition(
      credentialId.length <= 1024 &&
        decoded.length > 0 &&
        decoded.length <= 768 &&
        decoded.toString("base64url") === credentialId,
      400,
      "PASSKEY_REJECTED",
      "The authenticator response is invalid.",
    );
    await tx.query(
      `INSERT INTO organizer_credentials(credential_id,account_id,public_key,counter,transports,device_type,backed_up,label)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        credentialId,
        accountId,
        Buffer.from(info.credential.publicKey),
        info.credential.counter,
        (info.credential.transports ?? [])
          .filter((t) =>
            [
              "ble",
              "cable",
              "hybrid",
              "internal",
              "nfc",
              "smart-card",
              "usb",
            ].includes(t),
          )
          .slice(0, 7),
        info.credentialDeviceType,
        info.credentialBackedUp,
        label,
      ],
    );
  };
  const authOptions = async (
    req: Request,
    kind: string,
    accountId: string | null,
    generation: number | null,
    digestValue: Buffer | null,
  ) => {
    const challenge = token();
    const publicKey = await generateAuthenticationOptions({
      rpID: rpId(options.origin),
      challenge,
      userVerification: "required",
      allowCredentials: [],
    });
    return {
      ceremonyId: await saveCeremony(req, kind, publicKey.challenge, {
        account_id: accountId,
        auth_generation: generation,
        recovery_digest: digestValue,
        organizer_session_id: kind === "reauth" ? req.organizer?.id : null,
      }),
      options: publicKey,
    };
  };
  function guardResponse(response: Record<string, unknown>) {
    requireCondition(
      typeof response.id === "string" &&
        response.id === response.rawId &&
        /^[A-Za-z0-9_-]{1,1024}$/.test(response.id),
      400,
      "PASSKEY_REJECTED",
      "The authenticator response is invalid.",
    );
    const decodedId = Buffer.from(response.id, "base64url");
    requireCondition(
      decodedId.length > 0 &&
        decodedId.length <= 768 &&
        decodedId.toString("base64url") === response.id,
      400,
      "PASSKEY_REJECTED",
      "The authenticator response is invalid.",
    );
    const clientData = (
      response.response as Record<string, unknown> | undefined
    )?.clientDataJSON;
    requireCondition(
      typeof clientData === "string" && clientData.length <= 16384,
      400,
      "PASSKEY_REJECTED",
      "The authenticator response is invalid.",
    );
    try {
      const data = JSON.parse(
        Buffer.from(clientData, "base64url").toString("utf8"),
      ) as Record<string, unknown>;
      requireCondition(
        (data.crossOrigin === undefined || data.crossOrigin === false) &&
          data.topOrigin === undefined,
        400,
        "PASSKEY_REJECTED",
        "Passkeys must be used on the Portkey site itself.",
      );
    } catch {
      genericAuthError();
    }
  }
  const limiter = (limit: number, browser: boolean) =>
    rateLimit({
      windowMs: 60_000,
      limit,
      keyGenerator: browser
        ? (req) => req.session?.id ?? ipKeyGenerator(req.ip ?? "127.0.0.1")
        : (req) => ipKeyGenerator(req.ip ?? "127.0.0.1"),
      standardHeaders: "draft-8",
      legacyHeaders: false,
      message: {
        error: {
          code: "RATE_LIMITED",
          message: "Too many passkey attempts. Wait a minute and try again.",
        },
      },
    });
  const authIpLimit = limiter(30, false);
  const authBrowserLimit = limiter(20, true);
  const recoveryIpLimit = limiter(5, false);
  const recoveryBrowserLimit = limiter(5, true);
  async function verifyAssertion(
    tx: Queries,
    ceremony: Ceremony,
    response: Record<string, unknown>,
  ) {
    guardResponse(response);
    const credentialId = typeof response.id === "string" ? response.id : "";
    const [credentialSnapshot] = await tx.query<CredentialRow>(
      "SELECT * FROM organizer_credentials WHERE credential_id=$1 AND ($2::uuid IS NULL OR account_id=$2)",
      [credentialId, ceremony.account_id],
    );
    if (!credentialSnapshot) genericAuthError();
    await tx.query("SELECT id FROM organizer_accounts WHERE id=$1 FOR UPDATE", [
      credentialSnapshot.account_id,
    ]);
    const [credential] = await tx.query<CredentialRow>(
      "SELECT * FROM organizer_credentials WHERE credential_id=$1 AND account_id=$2 FOR UPDATE",
      [credentialId, credentialSnapshot.account_id],
    );
    if (!credential) genericAuthError();
    const userHandle = (
      response.response as { userHandle?: unknown } | undefined
    )?.userHandle;
    const [account] = await tx.query<{
      user_handle: Buffer;
      auth_generation: number;
      recovery_digest: Buffer;
      owner_session_id: string;
    }>(
      "SELECT user_handle,auth_generation,recovery_digest,owner_session_id FROM organizer_accounts WHERE id=$1 FOR UPDATE",
      [credential.account_id],
    );
    if (
      !account ||
      (userHandle != null &&
        (typeof userHandle !== "string" ||
          userHandle.length > 128 ||
          Buffer.from(userHandle, "base64url").length !==
            account.user_handle.length ||
          Buffer.from(userHandle, "base64url").toString("base64url") !==
            userHandle ||
          !timingSafeEqual(
            Buffer.from(userHandle, "base64url"),
            account.user_handle,
          )))
    )
      genericAuthError();
    if (
      ceremony.account_id &&
      (ceremony.account_id !== credential.account_id ||
        ceremony.auth_generation !== account.auth_generation)
    )
      genericAuthError();
    if (
      ceremony.recovery_digest &&
      !timingSafeEqual(ceremony.recovery_digest, account.recovery_digest)
    )
      genericAuthError();
    const data: WebAuthnCredential = {
      id: credential.credential_id,
      publicKey: new Uint8Array(credential.public_key),
      counter: Number(credential.counter),
      transports: credential.transports as AuthenticatorTransport[],
    };
    let verified;
    try {
      verified = await verifyAuthenticationResponse({
        response: response as never,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: options.origin,
        expectedRPID: rpId(options.origin),
        credential: data,
        requireUserVerification: true,
      });
    } catch {
      genericAuthError();
    }
    if (
      !verified.verified ||
      !verified.authenticationInfo.userVerified ||
      verified.authenticationInfo.credentialID !== credential.credential_id
    )
      genericAuthError();
    return { credential, account, auth: verified.authenticationInfo };
  }

  router.get("/account/status", async (req, res) => {
    const [preview] = req.session
      ? await database.query<{
          rooms: number;
          groups: number;
          contracts: number;
          apps: number;
          claimed: boolean;
        }>(
          `SELECT
      (SELECT count(*)::int FROM rooms WHERE owner_id=$1) rooms,
      (SELECT count(*)::int FROM credential_groups WHERE owner_session_id=$1) groups,
      (SELECT count(*)::int FROM platform_contracts WHERE owner_session_id=$1) contracts,
      (SELECT count(*)::int FROM platform_apps WHERE owner_session_id=$1) apps,
      EXISTS(SELECT 1 FROM organizer_accounts WHERE owner_session_id=$1) claimed`,
          [req.session.id],
        )
      : [];
    const visiblePreview = preview?.claimed ? null : (preview ?? null);
    res.json({
      signedIn: !!req.organizer,
      sessionExpiresAt: req.organizer?.expiresAt.toISOString() ?? null,
      preview: visiblePreview,
      canAdopt: !!req.session && !req.organizer && preview?.claimed === false,
    });
  });
  router.post(
    "/account/signup/options",
    authIpLimit,
    authBrowserLimit,
    secureRequest,
    async (req, res) => {
      requireBrowser(req);
      requireCondition(
        !req.organizer,
        409,
        "ALREADY_SIGNED_IN",
        "Sign out before creating another organizer account.",
      );
      const parsed = z
        .object({ adopt: z.literal(true) })
        .strict()
        .safeParse(req.body);
      requireCondition(
        parsed.success,
        422,
        "ADOPTION_REQUIRED",
        "Confirm that this account should secure this browser’s current workspace.",
      );
      const [owner] = await database.query<{
        available: boolean;
        account_id: string | null;
      }>("SELECT available,account_id FROM owner_authorities WHERE id=$1", [
        req.session!.id,
      ]);
      requireCondition(
        owner?.available && !owner.account_id,
        409,
        "WORKSPACE_UNAVAILABLE",
        "This browser workspace is already secured or has expired.",
      );
      const accountId = randomUUID(),
        handle = randomBytes(32);
      res.setHeader("Cache-Control", "no-store");
      res.json(
        await registrationOptions(
          req,
          "signup",
          null,
          handle,
          `organizer-${accountId}`,
          { prospective_account_id: accountId },
        ),
      );
    },
  );
  router.post(
    "/account/signup/verify",
    authIpLimit,
    authBrowserLimit,
    secureRequest,
    async (req, res) => {
      requireBrowser(req);
      requireCondition(
        !req.organizer,
        409,
        "ALREADY_SIGNED_IN",
        "Sign out before creating another organizer account.",
      );
      const parsed = inputResponse
        .extend({ ceremonyId: z.string().uuid() })
        .strict()
        .safeParse(req.body);
      requireCondition(
        parsed.success,
        422,
        "INVALID_INPUT",
        "Passkey response is invalid.",
      );
      const result = await database.transaction(async (tx) => {
        await tx.query("SELECT id FROM sessions WHERE id=$1 FOR UPDATE", [
          req.session!.id,
        ]);
        const c = await consumeCeremony(tx, req, parsed.data.ceremonyId, [
          "signup",
        ]);
        const info = await verifyRegistration(
          parsed.data.response,
          c.challenge,
        );
        requireCondition(
          c.prospective_account_id && c.prospective_user_handle,
          400,
          "CEREMONY_INVALID",
          "Start account creation again.",
        );
        await tx.query("SELECT id FROM sessions WHERE id=$1 FOR UPDATE", [
          req.session!.id,
        ]);
        const [owner] = await tx.query<{
          available: boolean;
          account_id: string | null;
        }>("SELECT available,account_id FROM owner_authorities WHERE id=$1", [
          req.session!.id,
        ]);
        requireCondition(
          owner?.available && !owner.account_id,
          409,
          "WORKSPACE_UNAVAILABLE",
          "This browser workspace is already secured or has expired.",
        );
        const recoveryKey = secretKey(c.prospective_account_id);
        await tx.query(
          "INSERT INTO organizer_accounts(id,user_handle,owner_session_id,recovery_digest) VALUES($1,$2,$3,$4)",
          [
            c.prospective_account_id,
            c.prospective_user_handle,
            req.session!.id,
            secretDigest(recoveryKey),
          ],
        );
        await addCredential(
          tx,
          c.prospective_account_id,
          info,
          parsed.data.label ?? "Passkey",
        );
        await markConsumed(tx, c.id);
        await sessionCookie(tx, res, c.prospective_account_id, 1);
        return { recoveryKey };
      });
      res.json({ signedIn: true, recoveryKey: result.recoveryKey });
    },
  );
  router.post(
    "/account/login/options",
    authIpLimit,
    authBrowserLimit,
    secureRequest,
    async (req, res) => {
      requireBrowser(req);
      res.setHeader("Cache-Control", "no-store");
      res.json(await authOptions(req, "login", null, null, null));
    },
  );
  router.post(
    "/account/login/verify",
    authIpLimit,
    authBrowserLimit,
    secureRequest,
    async (req, res) => {
      requireBrowser(req);
      const parsed = inputResponse
        .extend({ ceremonyId: z.string().uuid() })
        .strict()
        .safeParse(req.body);
      requireCondition(
        parsed.success,
        422,
        "INVALID_INPUT",
        "Passkey response is invalid.",
      );
      const responseCredentialId =
        typeof parsed.data.response.id === "string"
          ? parsed.data.response.id
          : "";
      const [snapshot] = await database.query<{ account_id: string }>(
        "SELECT account_id FROM organizer_credentials WHERE credential_id=$1",
        [responseCredentialId],
      );
      if (!snapshot) genericAuthError();
      await database.transaction(async (tx) => {
        await tx.query(
          "SELECT id FROM organizer_accounts WHERE id=$1 FOR UPDATE",
          [snapshot.account_id],
        );
        const c = await consumeCeremony(tx, req, parsed.data.ceremonyId, [
          "login",
        ]);
        const verified = await verifyAssertion(tx, c, parsed.data.response);
        await tx.query(
          "UPDATE organizer_credentials SET counter=$2,backed_up=$3,last_used_at=clock_timestamp() WHERE credential_id=$1",
          [
            verified.credential.credential_id,
            verified.auth.newCounter,
            verified.auth.credentialBackedUp,
          ],
        );
        await markConsumed(tx, c.id);
        await sessionCookie(
          tx,
          res,
          verified.credential.account_id,
          verified.account.auth_generation,
        );
      });
      res.json({ signedIn: true });
    },
  );
  router.post(
    "/account/reauthenticate/options",
    authIpLimit,
    authBrowserLimit,
    secureRequest,
    async (req, res) => {
      activeAccount(req);
      const [a] = await database.query<{ auth_generation: number }>(
        "SELECT auth_generation FROM organizer_accounts WHERE id=$1",
        [req.organizer!.accountId],
      );
      requireCondition(a, 401, "ACCOUNT_REQUIRED", "Sign in again.");
      res.setHeader("Cache-Control", "no-store");
      res.json(
        await authOptions(
          req,
          "reauth",
          req.organizer!.accountId,
          a.auth_generation,
          null,
        ),
      );
    },
  );
  router.post(
    "/account/reauthenticate/verify",
    authIpLimit,
    authBrowserLimit,
    secureRequest,
    async (req, res) => {
      activeAccount(req);
      const parsed = inputResponse
        .extend({ ceremonyId: z.string().uuid() })
        .strict()
        .safeParse(req.body);
      requireCondition(
        parsed.success,
        422,
        "INVALID_INPUT",
        "Passkey response is invalid.",
      );
      await database.transaction(async (tx) => {
        const [snapshot] = await tx.query<Ceremony>(
          "SELECT * FROM organizer_ceremonies WHERE id=$1 AND browser_session_id=$2 AND kind='reauth'",
          [parsed.data.ceremonyId, req.session!.id],
        );
        requireCondition(
          snapshot?.account_id === req.organizer!.accountId &&
            snapshot.organizer_session_id === req.organizer!.id,
          400,
          "CEREMONY_INVALID",
          "Start verification again.",
        );
        await tx.query(
          "SELECT id FROM organizer_accounts WHERE id=$1 FOR UPDATE",
          [snapshot.account_id],
        );
        const c = await consumeCeremony(tx, req, parsed.data.ceremonyId, [
          "reauth",
        ]);
        const verified = await verifyAssertion(tx, c, parsed.data.response);
        requireCondition(
          verified.credential.account_id === req.organizer!.accountId,
          401,
          "AUTHENTICATION_FAILED",
          "Passkey could not be verified.",
        );
        await tx.query(
          "UPDATE organizer_credentials SET counter=$2,backed_up=$3,last_used_at=clock_timestamp() WHERE credential_id=$1",
          [
            verified.credential.credential_id,
            verified.auth.newCounter,
            verified.auth.credentialBackedUp,
          ],
        );
        const [session] = await tx.query<{ id: string }>(
          `UPDATE organizer_sessions SET verified_at=clock_timestamp() WHERE id=$1 AND account_id=$2 AND expires_at>clock_timestamp() AND auth_generation=$3 RETURNING id`,
          [
            req.organizer!.id,
            req.organizer!.accountId,
            verified.account.auth_generation,
          ],
        );
        requireCondition(
          session,
          401,
          "ACCOUNT_SESSION_EXPIRED",
          "Sign in again with your passkey.",
        );
        await markConsumed(tx, c.id);
      });
      res.json({ verified: true });
    },
  );
  router.post(
    "/account/passkeys/options",
    authIpLimit,
    authBrowserLimit,
    secureRequest,
    async (req, res) => {
      activeAccount(req);
      await database.transaction((tx) => requireFresh(tx, req));
      const [a] = await database.query<{
        user_handle: Buffer;
        auth_generation: number;
      }>(
        "SELECT user_handle,auth_generation FROM organizer_accounts WHERE id=$1",
        [req.organizer!.accountId],
      );
      requireCondition(a, 401, "ACCOUNT_REQUIRED", "Sign in again.");
      res.setHeader("Cache-Control", "no-store");
      res.json(
        await registrationOptions(
          req,
          "add_passkey",
          req.organizer!.accountId,
          a.user_handle,
          `organizer-${req.organizer!.accountId}`,
          {
            auth_generation: a.auth_generation,
            organizer_session_id: req.organizer!.id,
          },
        ),
      );
    },
  );
  router.post(
    "/account/passkeys/verify",
    authIpLimit,
    authBrowserLimit,
    secureRequest,
    async (req, res) => {
      activeAccount(req);
      const parsed = inputResponse
        .extend({ ceremonyId: z.string().uuid() })
        .strict()
        .safeParse(req.body);
      requireCondition(
        parsed.success,
        422,
        "INVALID_INPUT",
        "Passkey response is invalid.",
      );
      await database.transaction(async (tx) => {
        const [snapshot] = await tx.query<Ceremony>(
          "SELECT * FROM organizer_ceremonies WHERE id=$1 AND browser_session_id=$2",
          [parsed.data.ceremonyId, req.session!.id],
        );
        requireCondition(
          snapshot?.account_id === req.organizer!.accountId &&
            snapshot.organizer_session_id === req.organizer!.id,
          400,
          "CEREMONY_INVALID",
          "Start passkey enrollment again.",
        );
        const [account] = await tx.query<{ auth_generation: number }>(
          "SELECT auth_generation FROM organizer_accounts WHERE id=$1 FOR UPDATE",
          [snapshot.account_id],
        );
        await requireFresh(tx, req);
        const c = await consumeCeremony(tx, req, parsed.data.ceremonyId, [
          "add_passkey",
        ]);
        requireCondition(
          account && c.auth_generation === account.auth_generation,
          400,
          "CEREMONY_INVALID",
          "Start passkey enrollment again.",
        );
        const info = await verifyRegistration(
          parsed.data.response,
          c.challenge,
        );
        await addCredential(
          tx,
          c.account_id!,
          info,
          parsed.data.label ?? "Passkey",
        );
        await markConsumed(tx, c.id);
      });
      res.json({ added: true });
    },
  );
  router.delete(
    "/account/passkeys/:credentialId",
    secureRequest,
    async (req, res) => {
      activeAccount(req);
      const id = z.string().min(1).max(1024).parse(req.params.credentialId);
      await database.transaction(async (tx) => {
        await requireFresh(tx, req);
        const [count] = await tx.query<{ count: number }>(
          "SELECT count(*)::int AS count FROM organizer_credentials WHERE account_id=$1",
          [req.organizer!.accountId],
        );
        requireCondition(
          count.count > 1,
          409,
          "FINAL_PASSKEY",
          "An account must keep at least one passkey.",
        );
        const [deleted] = await tx.query<{ credential_id: string }>(
          "DELETE FROM organizer_credentials WHERE account_id=$1 AND credential_id=$2 RETURNING credential_id",
          [req.organizer!.accountId, id],
        );
        requireCondition(
          deleted,
          404,
          "PASSKEY_NOT_FOUND",
          "Passkey not found.",
        );
      });
      res.status(204).end();
    },
  );
  router.post("/account/recovery/rotate", secureRequest, async (req, res) => {
    activeAccount(req);
    const result = await database.transaction(async (tx) => {
      await requireFresh(tx, req);
      const key = secretKey(req.organizer!.accountId);
      await tx.query(
        "UPDATE organizer_accounts SET recovery_digest=$2 WHERE id=$1",
        [req.organizer!.accountId, secretDigest(key)],
      );
      await tx.query(
        "UPDATE organizer_ceremonies SET consumed_at=clock_timestamp() WHERE account_id=$1 AND kind='recovery' AND consumed_at IS NULL",
        [req.organizer!.accountId],
      );
      return key;
    });
    res.json({ recoveryKey: result });
  });
  router.get("/account/sessions", async (req, res) => {
    activeAccount(req);
    const sessions = await database.query<{
      id: string;
      created_at: Date;
      last_used_at: Date;
      expires_at: Date;
    }>(
      "SELECT id,created_at,last_used_at,expires_at FROM organizer_sessions WHERE account_id=$1 AND expires_at>clock_timestamp() ORDER BY last_used_at DESC",
      [req.organizer!.accountId],
    );
    res.json({
      sessions: sessions.map((s) => ({
        ...s,
        current: s.id === req.organizer!.id,
        created_at: s.created_at.toISOString(),
        last_used_at: s.last_used_at.toISOString(),
        expires_at: s.expires_at.toISOString(),
      })),
    });
  });
  router.post(
    "/account/sessions/:id/revoke",
    secureRequest,
    async (req, res) => {
      activeAccount(req);
      const id = z.string().uuid().parse(req.params.id);
      await database.transaction(async (tx) => {
        await requireFresh(tx, req);
        const [deleted] = await tx.query<{ id: string }>(
          "DELETE FROM organizer_sessions WHERE id=$1 AND account_id=$2 AND id<>$3 RETURNING id",
          [id, req.organizer!.accountId, req.organizer!.id],
        );
        requireCondition(
          deleted,
          404,
          "SESSION_NOT_FOUND",
          "Organizer session not found.",
        );
      });
      res.status(204).end();
    },
  );
  router.post("/account/logout", secureRequest, async (req, res) => {
    requireBrowser(req);
    if (req.organizer)
      await database.transaction(async (tx) => {
        await tx.query(
          "SELECT id FROM organizer_accounts WHERE id=$1 FOR UPDATE",
          [req.organizer!.accountId],
        );
        await tx.query(
          "DELETE FROM organizer_sessions WHERE id=$1 AND account_id=$2",
          [req.organizer!.id, req.organizer!.accountId],
        );
      });
    removeCookie(res, options.secure);
    res.json({ signedIn: false });
  });
  router.get("/account/passkeys", async (req, res) => {
    activeAccount(req);
    const rows = await database.query<{
      credential_id: string;
      label: string;
      device_type: string;
      backed_up: boolean;
      created_at: Date;
      last_used_at: Date | null;
    }>(
      "SELECT credential_id,label,device_type,backed_up,created_at,last_used_at FROM organizer_credentials WHERE account_id=$1 ORDER BY created_at",
      [req.organizer!.accountId],
    );
    res.json({
      passkeys: rows.map((r) => ({
        ...r,
        created_at: r.created_at.toISOString(),
        last_used_at: r.last_used_at?.toISOString() ?? null,
      })),
    });
  });
  router.post(
    "/account/recovery/options",
    recoveryIpLimit,
    recoveryBrowserLimit,
    secureRequest,
    async (req, res) => {
      requireBrowser(req);
      const parsed = recoveryInput.safeParse(req.body);
      if (!parsed.success) genericAuthError();
      const [locator, secret] = parsed.data.recoveryKey.split(".");
      const id = locator.slice("pk_recovery_".length),
        idParsed = z.string().uuid().safeParse(id);
      const secretBytes = Buffer.from(secret, "base64url");
      if (
        !idParsed.success ||
        id.toLowerCase() !== idParsed.data.toLowerCase() ||
        secretBytes.length !== 32 ||
        secretBytes.toString("base64url") !== secret
      )
        genericAuthError();
      const [a] = await database.query<{
        id: string;
        auth_generation: number;
        recovery_digest: Buffer;
        user_handle: Buffer;
      }>(
        "SELECT id,auth_generation,recovery_digest,user_handle FROM organizer_accounts WHERE id=$1",
        [id],
      );
      const digest = secretDigest(parsed.data.recoveryKey);
      if (
        !a ||
        digest.length !== a.recovery_digest.length ||
        !timingSafeEqual(digest, a.recovery_digest)
      )
        genericAuthError();
      res.setHeader("Cache-Control", "no-store");
      res.json(
        await registrationOptions(
          req,
          "recovery",
          a.id,
          a.user_handle,
          `organizer-${a.id}`,
          {
            auth_generation: a.auth_generation,
            recovery_digest: a.recovery_digest,
          },
        ),
      );
    },
  );
  router.post(
    "/account/recovery/verify",
    recoveryIpLimit,
    recoveryBrowserLimit,
    secureRequest,
    async (req, res) => {
      requireBrowser(req);
      const parsed = inputResponse
        .extend({ ceremonyId: z.string().uuid() })
        .strict()
        .safeParse(req.body);
      requireCondition(
        parsed.success,
        422,
        "INVALID_INPUT",
        "Passkey response is invalid.",
      );
      const [snapshot] = await database.query<Ceremony>(
        "SELECT * FROM organizer_ceremonies WHERE id=$1 AND browser_session_id=$2 AND kind='recovery'",
        [parsed.data.ceremonyId, req.session!.id],
      );
      requireCondition(
        snapshot?.account_id,
        400,
        "CEREMONY_INVALID",
        "Start recovery again.",
      );
      const accountId = snapshot.account_id;
      const result = await database.transaction(async (tx) => {
        const [account] = await tx.query<{
          auth_generation: number;
          recovery_digest: Buffer;
        }>(
          "SELECT auth_generation,recovery_digest FROM organizer_accounts WHERE id=$1 FOR UPDATE",
          [snapshot.account_id],
        );
        const c = await consumeCeremony(tx, req, parsed.data.ceremonyId, [
          "recovery",
        ]);
        if (
          !account ||
          account.auth_generation !== c.auth_generation ||
          !c.recovery_digest ||
          account.recovery_digest.length !== c.recovery_digest.length ||
          !timingSafeEqual(account.recovery_digest, c.recovery_digest)
        )
          genericAuthError();
        const info = await verifyRegistration(
          parsed.data.response,
          c.challenge,
        );
        await markConsumed(tx, c.id);
        const newKey = secretKey(accountId);
        await tx.query(
          "DELETE FROM organizer_credentials WHERE account_id=$1",
          [accountId],
        );
        await addCredential(
          tx,
          accountId,
          info,
          parsed.data.label ?? "Replacement passkey",
        );
        await tx.query("DELETE FROM organizer_sessions WHERE account_id=$1", [
          accountId,
        ]);
        await tx.query(
          "UPDATE organizer_accounts SET auth_generation=auth_generation+1,recovery_digest=$2 WHERE id=$1",
          [accountId, secretDigest(newKey)],
        );
        await tx.query(
          "UPDATE organizer_ceremonies SET consumed_at=clock_timestamp() WHERE account_id=$1 AND consumed_at IS NULL",
          [accountId],
        );
        await sessionCookie(tx, res, accountId, account.auth_generation + 1);
        return newKey;
      });
      res.json({ signedIn: true, recoveryKey: result });
    },
  );
  return router;
}

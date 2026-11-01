import { randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import pg from "pg";
import { createPortkeyClient } from "portkey";

const env = (key) => {
  if (!process.env[key]) throw new Error(`Missing ${key}`);
  return process.env[key];
};
const appOrigin = new URL(env("APP_ORIGIN"));
if (
  appOrigin.origin !== process.env.APP_ORIGIN ||
  !["http:", "https:"].includes(appOrigin.protocol)
)
  throw new Error("APP_ORIGIN must be an exact origin.");
const secure = appOrigin.protocol === "https:";
if (
  !secure &&
  !["localhost", "127.0.0.1", "[::1]"].includes(appOrigin.hostname)
)
  throw new Error("HTTP is allowed only for loopback development.");
const sessionSecret = env("SESSION_SECRET");
if (
  Buffer.byteLength(sessionSecret) < 32 ||
  sessionSecret.startsWith("replace_")
)
  throw new Error(
    "SESSION_SECRET must contain at least 32 cryptographically random bytes; replace the example placeholder.",
  );
const proxyHops = secure ? Number(env("TRUST_PROXY_HOPS")) : 0;
if (
  secure &&
  (!Number.isSafeInteger(proxyHops) || proxyHops < 1 || proxyHops > 5)
)
  throw new Error(
    "TRUST_PROXY_HOPS must match the trusted HTTPS proxy chain (1 to 5).",
  );
const pool = new pg.Pool({ connectionString: env("DATABASE_URL"), max: 5 });
const databaseSchema = process.env.DATABASE_SCHEMA ?? "public";
if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(databaseSchema))
  throw new Error(
    "DATABASE_SCHEMA must be a simple PostgreSQL schema identifier.",
  );
const quotedSchema = `"${databaseSchema}"`;
const claimsTable = `${quotedSchema}."rp_callback_claims"`;
if (databaseSchema !== "public")
  await pool.query(`CREATE SCHEMA IF NOT EXISTS ${quotedSchema}`);
const store = new (connectPgSimple(session))({
  pool,
  schemaName: databaseSchema,
  tableName: "rp_sessions",
  createTableIfMissing: true,
  ttl: 600,
});
await pool.query(`
  CREATE TABLE IF NOT EXISTS ${claimsTable} (
    session_id text NOT NULL,
    flow_id text NOT NULL,
    claimed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, flow_id)
  )
`);
await pool.query(
  `DELETE FROM ${claimsTable} WHERE claimed_at < now() - interval '1 day'`,
);
const client = createPortkeyClient({
  origin: env("PORTKEY_ORIGIN"),
  apiKey: env("PORTKEY_APP_KEY"),
  appId: env("PORTKEY_APP_ID"),
});
const domainChallenge = process.env.PORTKEY_DOMAIN_CHALLENGE ?? "";
if (domainChallenge && !/^[A-Za-z0-9_-]{43}$/.test(domainChallenge))
  throw new Error(
    "PORTKEY_DOMAIN_CHALLENGE must be a 43-character base64url value.",
  );
const contractId = env("PORTKEY_CONTRACT_ID");
const contractVersion = Number(env("PORTKEY_CONTRACT_VERSION"));
const contractDigest = env("PORTKEY_CONTRACT_DIGEST");
if (
  !Number.isSafeInteger(contractVersion) ||
  contractVersion < 1 ||
  !/^[a-f0-9]{64}$/.test(contractDigest)
)
  throw new Error("Contract pin is invalid.");
const callback = new URL("/portkey/callback", appOrigin).href;
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", proxyHops || false);
app.use(express.json({ limit: "4kb" }));
app.use(express.urlencoded({ extended: false, limit: "4kb", parameterLimit: 10 }));
app.use((_req, res, next) => {
  res.set({
    "Cache-Control": "no-store",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  next();
});
app.use(
  session({
    name: "rp.sid",
    store,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure,
      path: "/",
      maxAge: 600_000,
    },
  }),
);

function sameOrigin(req, res, next) {
  if (
    req.get("origin") !== appOrigin.origin ||
    req.get("sec-fetch-site") === "cross-site"
  )
    return res.status(403).send("Request origin rejected.");
  next();
}
function csrfValid(req) {
  const token = req.get("x-csrf-token") ?? req.body?.csrf;
  if (
    typeof token !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(token) ||
    typeof req.session.csrf !== "string"
  )
    return false;
  const a = Buffer.from(token);
  const b = Buffer.from(req.session.csrf);
  return a.length === b.length && timingSafeEqual(a, b);
}
const save = (req) =>
  new Promise((resolve, reject) =>
    req.session.save((error) => (error ? reject(error) : resolve())),
  );

app.get("/", (req, res) => {
  req.session.csrf ??= randomBytes(32).toString("base64url");
  res.type("html").send(`<!doctype html>
    <meta charset="utf-8">
    <title>Portkey relying party</title>
    <h1>Membership check</h1>
    <p>Eligibility is verified against the pinned contract.</p>
    <form id="start-form" method="post" action="/start">
      <input type="hidden" name="csrf" value="${req.session.csrf}">
      <button>Continue with Portkey</button>
    </form>
    <p id="start-message" role="status"></p>
    <script src="/start.js" defer></script>`);
});
app.get("/.well-known/portkey-app.json", (_req, res) => {
  if (!domainChallenge) return res.sendStatus(404);
  res.json({ appId: process.env.PORTKEY_APP_ID, challenge: domainChallenge });
});
app.get("/start.js", (_req, res) =>
  res.type("text/javascript").send(`
    const form = document.querySelector("#start-form");
    const message = document.querySelector("#start-message");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button");
      button.disabled = true;
      message.textContent = "Connecting to Portkey…";
      try {
        const response = await fetch("/start", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "content-type": "application/json",
            "x-csrf-token": form.elements.csrf.value,
          },
          body: "{}",
        });
        if (!response.ok) throw new Error("Portkey could not start a request.");
        const { walletUrl } = await response.json();
        location.assign(walletUrl);
      } catch {
        message.textContent = "Portkey could not start. Reload and try again.";
        button.disabled = false;
      }
    });
  `),
);
app.post("/start", sameOrigin, async (req, res, next) => {
  try {
    if (!csrfValid(req)) return res.status(403).send("Reload and try again.");
    const flow = await client.createProofRequest({
      contractId,
      contractVersion,
      redirectUri: callback,
    });
    req.session.pending = {
      flowId: randomBytes(24).toString("base64url"),
      requestId: flow.requestId,
      state: flow.state,
      verifier: flow.codeVerifier,
      expiresAt: flow.expiresAt,
      createdAt: Date.now(),
    };
    await save(req);
    if (req.is("application/json")) res.json({ walletUrl: flow.walletUrl });
    else res.redirect(303, flow.walletUrl);
  } catch (error) {
    next(error);
  }
});
app.get("/portkey/callback", (_req, res) =>
  res.type("html").send(`<!doctype html>
    <meta charset="utf-8">
    <title>Completing verification</title>
    <p>Completing verification…</p>
    <script type="module" src="/callback.js"></script>`),
);
app.get("/callback-helper.js", (_req, res, next) => {
  try {
    res
      .type("text/javascript")
      .sendFile(fileURLToPath(import.meta.resolve("portkey/browser")));
  } catch (error) {
    next(error);
  }
});
app.get("/callback.js", (_req, res) =>
  res.type("text/javascript").send(`
    import { readPortkeyCallback } from "/callback-helper.js";
    const callback = readPortkeyCallback();
    const csrf = await fetch("/csrf", { credentials: "same-origin" }).then((r) => r.json());
    const response = await fetch("/portkey/callback", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": csrf.token },
      body: JSON.stringify(callback),
    });
    location.replace(response.ok ? "/result" : "/");
  `),
);
app.get("/csrf", (req, res) => res.json({ token: req.session.csrf ?? "" }));
app.post("/portkey/callback", sameOrigin, async (req, res, next) => {
  try {
    if (!csrfValid(req)) return res.status(403).send("Reload and try again.");
    const pending = req.session.pending;
    const { code, state } = req.body ?? {};
    if (
      !pending ||
      typeof code !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(code) ||
      typeof state !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(state) ||
      Date.now() - pending.createdAt > 600_000 ||
      Date.parse(pending.expiresAt) <= Date.now()
    )
      return res.status(400).send("Verification expired. Start again.");
    const expected = Buffer.from(pending.state);
    const returned = Buffer.from(state);
    if (
      expected.length !== returned.length ||
      !timingSafeEqual(expected, returned)
    )
      return res
        .status(403)
        .send("This result belongs to another session.");
    // This unique insert is committed before exchange and binds the one-use claim to the current server session.
    const claim = await pool.query(
      `INSERT INTO ${claimsTable}(session_id, flow_id)
       VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING flow_id`,
      [req.sessionID, pending.flowId],
    );
    if (claim.rowCount !== 1) return res.status(409).send("This callback was already used.");
    delete req.session.pending;
    await save(req);
    const result = await client.exchange(
      pending.requestId,
      code,
      pending.verifier,
      { contractId, contractVersion, contractDigest },
    );
    req.session.result = {
      passed: result.claims.result,
      contractId,
      contractVersion,
      verifiedAt: new Date().toISOString(),
      expiresAt: result.claims.exp * 1000,
    };
    await save(req);
    res.sendStatus(204);
  } catch (error) {
    next(error);
  }
});
app.get("/result", async (req, res, next) => {
  try {
    if (req.session.result?.expiresAt <= Date.now()) {
      delete req.session.result;
      await save(req);
    }
    res.type("html").send(
      req.session.result?.passed
        ? "<!doctype html><h1>Eligibility confirmed</h1><p>Portkey verified the pinned contract.</p>"
        : "<!doctype html><h1>No current verified result</h1><a href=\"/\">Start again</a>",
    );
  } catch (error) {
    next(error);
  }
});
app.use((error, _req, res, _next) => {
  console.error("Relying-party request failed", error instanceof Error ? error.name : "unknown error");
  res.status(500).send("Verification could not be completed. Start a new request.");
});
const server = app.listen(Number(process.env.PORT ?? 5310), "127.0.0.1", () =>
  console.log(`Relying party listening at ${appOrigin.origin}`),
);
const claimPruner = setInterval(() => {
  void pool
    .query(
      `DELETE FROM ${claimsTable} WHERE claimed_at < now() - interval '1 day'`,
    )
    .catch(() => undefined);
}, 60 * 60_000);
claimPruner.unref();
let closing = false;
const shutdown = async () => {
  if (closing) return;
  closing = true;
  clearInterval(claimPruner);
  await new Promise((resolve) => server.close(resolve));
  await pool.end();
};
process.on("SIGINT", () => { void shutdown(); });
process.on("SIGTERM", () => { void shutdown(); });

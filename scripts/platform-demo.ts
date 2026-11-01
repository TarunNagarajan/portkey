import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import { serialize } from "cookie";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type Server } from "node:http";
import { basename, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { rm } from "node:fs/promises";
import { createApp } from "../server/app.js";
import { openDatabase } from "../server/database.js";
import { migrate } from "../server/migrations.js";
import { organizerCookieName } from "../server/sessions.js";
import {
  runSubmissionCleanupPass,
  startCleanupScheduler,
} from "../server/cleanup.js";
import { createPortkeyClient, type ReceiptClaims } from "../sdk/index.js";

const walletOrigin = "http://localhost:5300";
const bootstrapToken =
  process.env.PORTKEY_PLATFORM_DEMO_BOOTSTRAP_TOKEN ??
  randomBytes(32).toString("base64url");
if (!/^[A-Za-z0-9_-]{43}$/.test(bootstrapToken))
  throw new Error("Invalid local demo bootstrap configuration.");
const bootstrapDigest = createHash("sha256").update(bootstrapToken).digest();
let bootstrapClaimed = false;
let organizerCookie = "";
const root = process.cwd();
const demoData = resolve(
  process.env.PORTKEY_PLATFORM_DEMO_DATA_DIR ??
    resolve(root, ".data/platform-demo"),
);
const cleanupDemoData =
  Boolean(process.env.PORTKEY_PLATFORM_DEMO_DATA_DIR) &&
  demoData.startsWith(`${resolve(tmpdir())}${sep}`) &&
  basename(demoData).startsWith("portkey-platform-demo-");
const apps = [
  {
    name: "Northstar Learning",
    port: 5301,
    host: "northstar.localhost",
    cookie: "pk_demo_northstar",
    tagline: "Your learning dashboard",
  },
  {
    name: "Fieldnote Community",
    port: 5302,
    host: "fieldnote.localhost",
    cookie: "pk_demo_fieldnote",
    tagline: "Your community workspace",
  },
] as const;
type DemoApp = (typeof apps)[number] & {
  id: string;
  apiKey: string;
  contractId: string;
  contractVersion: number;
  contractDigest: string;
  enrollmentUrl: string;
  challenge: string | null;
};
interface Pending {
  requestId: string;
  codeVerifier: string;
  state: string;
  expiresAt: number;
}
interface RPUserSession {
  id: string;
  appId: string;
  token: string;
  csrf: string;
  expiresAt: number;
  pending?: Pending;
  receipt?: ReceiptClaims;
  usedJtis: string[];
}

const sessions = new Map<string, RPUserSession>();
const servers: Server[] = [];
let database: Awaited<ReturnType<typeof openDatabase>> | null = null;
let cleanupScheduler: ReturnType<typeof startCleanupScheduler> | null = null;
let stopped = false;
let ready = false;
let readyApplications: Array<{ name: string; origin: string }> = [];

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
function html(title: string, body: string, csrf = "") {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf" content="${escapeHtml(csrf)}"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/style.css"><script src="/app.js" defer></script></head><body>${body}</body></html>`;
}

async function listen(server: Server, port: number, host = "127.0.0.1") {
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolveListen();
    });
  });
  servers.push(server);
}

async function postBrowser(
  path: string,
  cookie: string,
  csrf: string,
  body: unknown = {},
  method: "POST" | "PUT" = "POST",
) {
  const response = await fetch(`${walletOrigin}/api${path}`, {
    method,
    headers: {
      Origin: walletOrigin,
      Cookie: cookie,
      "X-CSRF-Token": csrf,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    redirect: "error",
  });
  const value = (await response.json().catch(() => null)) as {
    error?: { message?: string };
  } | null;
  if (!response.ok)
    throw new Error(
      value?.error?.message ?? `Portkey setup failed (${response.status}).`,
    );
  return value as Record<string, any>;
}

async function startOwnerSession() {
  const response = await fetch(`${walletOrigin}/api/session`, {
    method: "POST",
    headers: { Origin: walletOrigin },
  });
  if (!response.ok) throw new Error("Could not start a Portkey setup session.");
  const cookieHeader = response.headers.get("set-cookie") ?? "";
  const cookie = cookieHeader.split(";", 1)[0];
  const value = (await response.json()) as { csrfToken: string };
  if (!cookie || !value.csrfToken)
    throw new Error("Portkey did not create a setup session.");
  return { cookie, csrf: value.csrfToken };
}

function getSession(request: Request, app: DemoApp): RPUserSession | null {
  const cookie = request.headers.cookie
    ?.split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${app.cookie}=`));
  const token = cookie?.slice(app.cookie.length + 1);
  const session = token ? sessions.get(token) : undefined;
  if (!session || session.appId !== app.id || session.expiresAt <= Date.now())
    return null;
  return session;
}

function startSession(response: Response, app: DemoApp) {
  if (sessions.size >= 500) {
    const now = Date.now();
    for (const [token, item] of sessions)
      if (item.expiresAt <= now) sessions.delete(token);
    if (sessions.size >= 500)
      throw new Error(
        "The demo has reached its temporary browser session limit. Restart it later.",
      );
  }
  const token = randomBytes(32).toString("base64url");
  const session: RPUserSession = {
    id: randomBytes(16).toString("hex"),
    appId: app.id,
    token,
    csrf: randomBytes(32).toString("base64url"),
    expiresAt: Date.now() + 60 * 60_000,
    usedJtis: [],
  };
  sessions.set(token, session);
  response.setHeader(
    "Set-Cookie",
    `${app.cookie}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600`,
  );
  return session;
}

function requireSession(request: Request, response: Response, app: DemoApp) {
  const session = getSession(request, app);
  if (!session) {
    response
      .status(401)
      .send(
        html(
          app.name,
          '<main><h1>Session unavailable</h1><p>Return to the application home page and try again.</p><a href="/">Open application</a></main>',
        ),
      );
    return null;
  }
  return session;
}

function csrf(
  request: Request,
  response: Response,
  session: RPUserSession,
  origin: string,
) {
  const supplied = request.get("x-csrf-token") ?? "";
  const expected = Buffer.from(session.csrf);
  const actual = Buffer.from(supplied);
  if (
    request.get("origin") !== origin ||
    expected.length !== actual.length ||
    !timingSafeEqual(expected, actual)
  ) {
    response.status(403).json({ error: "Refresh the page and try again." });
    return false;
  }
  return true;
}

function renderMain(app: DemoApp, session: RPUserSession) {
  const verified =
    session.receipt && session.receipt.exp > Math.floor(Date.now() / 1000);
  return html(
    app.name,
    `<main><p class="eyebrow">PORTKEY DEMO APPLICATION</p><h1>${escapeHtml(app.name)}</h1><p>${escapeHtml(app.tagline)}</p>
    <section><h2>Check a membership credential</h2><p>This demo app uses its own backend. Portkey only returns a short-lived signed eligibility receipt after you approve a real membership proof.</p>
    <p><a href="${walletOrigin}/contracts/${app.contractId}/versions/${app.contractVersion}">Review the public Portkey contract</a></p>
    <p><a class="button secondary" href="/credential">Get the issuer’s demo enrollment link</a></p>
    <form id="start" data-csrf="${escapeHtml(session.csrf)}"><button type="submit">Continue with Portkey</button></form><p id="start-message" role="status"></p>
    ${verified ? `<p class="success">Access is available in this application session until ${new Date(session.receipt!.exp * 1000).toLocaleTimeString()}.</p><a class="button" href="/benefit">Open the protected area</a>` : '<p class="muted">This browser session does not have access yet.</p>'}
    </section><p class="muted">This sample is a protocol demo. It does not authenticate a real-world identity.</p></main>`,
    session.csrf,
  );
}

function createRelyingApp(config: DemoApp) {
  const server = express();
  server.disable("x-powered-by");
  server.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    next();
  });
  server.use(express.json({ limit: "2kb" }));
  server.use(express.urlencoded({ extended: false, limit: "2kb" }));
  const appOrigin = `http://${config.host}:${config.port}`;
  const client = createPortkeyClient({
    origin: walletOrigin,
    apiKey: config.apiKey,
    appId: config.id,
  });

  server.get("/.well-known/portkey-app.json", (_request, response) => {
    if (!config.challenge) {
      response.status(404).json({ error: "Not available" });
      return;
    }
    response.json({ appId: config.id, challenge: config.challenge });
  });
  server.get("/style.css", (_request, response) =>
    response
      .type("text/css")
      .send(
        "body{font:16px system-ui,sans-serif;background:#f5f7fb;color:#142238;margin:0}main{max-width:680px;margin:10vh auto;padding:28px;background:#fff;border:1px solid #dfe6f0;border-radius:12px}h1{font-size:2.2rem}.eyebrow{color:#315da8;font-weight:700;font-size:.8rem;letter-spacing:.1em}section{border-top:1px solid #e2e8f1;margin-top:24px;padding-top:18px}button,.button{display:inline-block;border:0;border-radius:7px;background:#235ec8;color:#fff;padding:12px 16px;font:inherit;text-decoration:none;cursor:pointer}.secondary{background:#e8eef8;color:#1b355b}.muted{color:#596a81;font-size:.92rem}.success{color:#17613e;background:#eaf7f0;padding:12px;border-radius:6px}",
      ),
  );
  server.get("/app.js", (_request, response) =>
    response
      .type("application/javascript")
      .send(
        `if(location.pathname==='/'){document.querySelector('#start')?.addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget;const button=form.querySelector('button');button.disabled=true;try{const r=await fetch('/start',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':form.dataset.csrf},body:'{}'});const d=await r.json();if(!r.ok)throw new Error();location.assign(d.walletUrl)}catch{document.querySelector('#start-message').textContent='Portkey is unavailable. Try again in a moment.';button.disabled=false}})}if(location.pathname==='/callback'){const p=new URLSearchParams(location.hash.slice(1));const value={code:p.get('code'),state:p.get('state'),error:p.get('error')};history.replaceState(null,'',location.pathname);fetch('/callback/session',{credentials:'same-origin'}).then(async s=>{if(!s.ok)throw new Error('Application session unavailable.');const d=await s.json();return fetch('/callback',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':d.csrf},body:JSON.stringify(value)})}).then(async r=>{const d=await r.json();if(r.ok){location.replace('/')}else{document.querySelector('#message').textContent=d.error||'The request could not be completed.'}}).catch(()=>{document.querySelector('#message').textContent='The application could not confirm the result. Start again.'})}`,
      ),
  );
  server.get("/", (request, response) => {
    const session =
      getSession(request, config) ?? startSession(response, config);
    response.type("html").send(renderMain(config, session));
  });
  server.get("/credential", (request, response) => {
    if (!requireSession(request, response, config)) return;
    response.redirect(302, config.enrollmentUrl);
  });
  server.get("/callback", (_request, response) => {
    response
      .type("html")
      .send(
        html(
          config.name,
          '<main><p class="eyebrow">PORTKEY RETURN</p><h1>Checking the result</h1><p id="message" role="status">Confirming this application request…</p></main>',
        ),
      );
  });
  server.get("/callback/session", (request, response) => {
    const session = requireSession(request, response, config);
    if (!session) return;
    response.json({ csrf: session.csrf });
  });
  server.post("/start", async (request, response) => {
    const session = requireSession(request, response, config);
    if (!session) return;
    const originHeader = request.get("origin");
    const submitted =
      request.get("x-csrf-token") ?? String(request.body?.csrf ?? "");
    if (originHeader !== appOrigin || submitted !== session.csrf) {
      response.status(403).send(renderMain(config, session));
      return;
    }
    if (session.expiresAt <= Date.now()) {
      response.status(401).send(renderMain(config, session));
      return;
    }
    try {
      const requestFlow = await client.createProofRequest({
        contractId: config.contractId,
        contractVersion: config.contractVersion,
        redirectUri: `${appOrigin}/callback`,
      });
      session.pending = {
        requestId: requestFlow.requestId,
        codeVerifier: requestFlow.codeVerifier,
        state: requestFlow.state,
        expiresAt: Date.parse(requestFlow.expiresAt),
      };
      if (request.is("application/json"))
        response.json({ walletUrl: requestFlow.walletUrl });
      else response.redirect(303, requestFlow.walletUrl);
    } catch {
      console.error(
        "The Portkey membership request could not be started. Confirm the local wallet is ready and try again.",
      );
      response
        .status(503)
        .type("html")
        .send(
          html(
            config.name,
            '<main><h1>Portkey is unavailable</h1><p>Try again in a moment.</p><a href="/">Return to the application</a></main>',
            session.csrf,
          ),
        );
    }
  });
  server.post("/callback", async (request, response) => {
    const session = requireSession(request, response, config);
    if (!session || !csrf(request, response, session, appOrigin)) return;
    const body = request.body as {
      code?: unknown;
      state?: unknown;
      error?: unknown;
    };
    const pending = session.pending;
    if (
      !pending ||
      pending.expiresAt <= Date.now() ||
      typeof body.state !== "string"
    ) {
      session.pending = undefined;
      response
        .status(400)
        .json({ error: "This application request expired. Start again." });
      return;
    }
    const expected = Buffer.from(pending.state);
    const received = Buffer.from(body.state);
    if (
      expected.length !== received.length ||
      !timingSafeEqual(expected, received)
    ) {
      response.status(403).json({
        error: "This result belongs to a different application session.",
      });
      return;
    }
    if (body.error === "access_denied") {
      session.pending = undefined;
      response.json({ status: "declined" });
      return;
    }
    if (
      typeof body.code !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(body.code)
    ) {
      session.pending = undefined;
      response
        .status(400)
        .json({ error: "The return code is invalid. Start again." });
      return;
    }
    session.pending = undefined;
    try {
      const { claims } = await client.exchange(
        pending.requestId,
        body.code,
        pending.codeVerifier,
        {
          contractId: config.contractId,
          contractVersion: config.contractVersion,
          contractDigest: config.contractDigest,
        },
      );
      if (
        session.usedJtis.includes(claims.jti) ||
        session.usedJtis.length >= 64
      )
        throw new Error("Receipt was already used.");
      session.usedJtis.push(claims.jti);
      session.receipt = claims;
      response.json({ status: "verified" });
    } catch (error) {
      console.error(
        "Demo receipt exchange failed. Start a new membership check; if it repeats, restart the demo and review the local service status.",
      );
      response.status(400).json({
        error: "The result could not be verified. Start a new request.",
      });
    }
  });
  server.get("/benefit", (request, response) => {
    const session = requireSession(request, response, config);
    if (!session) return;
    if (
      !session.receipt ||
      session.receipt.exp <= Math.floor(Date.now() / 1000) ||
      !session.usedJtis.includes(session.receipt.jti)
    ) {
      response
        .status(403)
        .type("html")
        .send(
          html(
            config.name,
            '<main><h1>Access is not available</h1><p>Complete a current membership check first.</p><a href="/">Return</a></main>',
            session.csrf,
          ),
        );
      return;
    }
    response
      .type("html")
      .send(
        html(
          config.name,
          `<main><p class="eyebrow">PROTECTED AREA</p><h1>Membership confirmed</h1><p>The current application session is eligible through ${new Date(session.receipt.exp * 1000).toLocaleTimeString()}.</p><p>No credential identifier was sent to this application.</p><a href="/">Return to application</a></main>`,
          session.csrf,
        ),
      );
  });
  server.use((_request, response) => response.status(404).send("Not found."));
  return createServer(server);
}

function parseDemoClaimBody(
  request: Request,
  response: Response,
  next: NextFunction,
) {
  express.json({ limit: "2kb" })(request, response, (error) => {
    if (!error) return next();
    response
      .status(error?.status === 413 ? 413 : 400)
      .json({ error: "Request body is invalid or too large." });
  });
}

async function claimDemoOrganizer(request: Request, response: Response) {
  const origin = request.get("origin") ?? "";
  const host = request.get("host") ?? "";
  const sessionCookie = request.headers.cookie
    ?.split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith("portkey_session="))
    ?.slice("portkey_session=".length) ?? "";
  const expectedCsrf = createHash("sha256")
    .update(`csrf:${sessionCookie}`)
    .digest("hex");
  const suppliedCsrf = request.get("x-csrf-token") ?? "";
  const capability = request.body?.capability;
  const canonicalCapability =
    typeof capability === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(capability) &&
    Buffer.from(capability, "base64url").length === 32 &&
    Buffer.from(capability, "base64url").toString("base64url") === capability;
  const suppliedDigest = canonicalCapability
    ? createHash("sha256").update(capability).digest()
    : Buffer.alloc(32);
  const validCsrf =
    /^[A-Za-z0-9_-]{43}$/.test(sessionCookie) &&
    /^[a-f0-9]{64}$/.test(suppliedCsrf) &&
    timingSafeEqual(Buffer.from(suppliedCsrf), Buffer.from(expectedCsrf));
  const validCapability = timingSafeEqual(suppliedDigest, bootstrapDigest);
  const [liveSession] = validCsrf
    ? await database!.query<{ id: string }>(
        "SELECT id FROM sessions WHERE token_hash=$1 AND expires_at>clock_timestamp()",
        [createHash("sha256").update(sessionCookie).digest("hex")],
      )
    : [];
  if (
    origin !== walletOrigin ||
    host !== "localhost:5300" ||
    !validCsrf ||
    !liveSession
  ) {
    response.status(403).json({ error: "Request could not be verified." });
    return;
  }
  if (bootstrapClaimed || !validCapability || !organizerCookie) {
    response.status(410).json({ error: "Organizer setup is unavailable." });
    return;
  }
  bootstrapClaimed = true;
  const [cookieName, cookieToken] = organizerCookie.split("=", 2);
  response.setHeader("Set-Cookie", [
    serialize(cookieName, cookieToken, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      path: "/",
      maxAge: 30 * 24 * 60 * 60,
    }),
    serialize(organizerCookieName(false), "", {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      path: "/",
      maxAge: 0,
      expires: new Date(0),
    }),
  ]);
  response.status(204).end();
}

async function setupDemo() {
  database = await openDatabase({ dataDir: demoData });
  await migrate(database);
  cleanupScheduler = startCleanupScheduler(() =>
    runSubmissionCleanupPass(database!),
  );
  const demoHost = express();
  demoHost.disable("x-powered-by");
  demoHost.use("/platform-demo", (_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    next();
  });
  demoHost.get("/platform-demo/ready", (_request, response) => {
    if (!ready) return response.sendStatus(503);
    response.json({ status: "ready", applications: readyApplications });
  });
  demoHost.get("/platform-demo/organizer", (_request, response) => {
    response.setHeader("Cache-Control", "no-store");
    response
      .type("html")
      .send(
        `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Organizer setup</title><script src="/platform-demo/organizer.js" defer></script></head><body><main><h1>Organizer workspace setup</h1><p>This setup signs this browser out of its current organizer session on this local demo and switches to the sample workspace. Existing organizer accounts and workspaces remain intact. Create a passkey account for the sample workspace to continue.</p><p id="status" role="status">Claiming the local demonstration workspace…</p><p id="error" role="alert"></p></main></body></html>`,
      );
  });
  demoHost.get("/platform-demo/organizer.js", (_request, response) => {
    response.setHeader("Cache-Control", "no-store");
    response.type("application/javascript").send(`(async()=>{const status=document.querySelector('#status');const error=document.querySelector('#error');const params=new URLSearchParams(location.hash.slice(1));const capability=params.get('setup');history.replaceState(null,'',location.pathname);try{if(!capability)throw new Error('Open the organizer setup link printed by the local demo process.');const sessionResponse=await fetch('/api/session',{method:'POST',credentials:'same-origin'});if(!sessionResponse.ok)throw new Error('Could not establish a browser session.');const session=await sessionResponse.json();const response=await fetch('/platform-demo/claim',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrfToken},body:JSON.stringify({capability})});if(!response.ok)throw new Error('This organizer setup link is invalid or has already been used. Restart the local demo for a new link.');location.replace('/account')}catch(cause){status.textContent='Setup was not completed.';error.textContent=cause instanceof Error?cause.message:'Unable to complete organizer setup.'}})();`);
  });
  demoHost.post("/platform-demo/claim", parseDemoClaimBody, claimDemoOrganizer);
  demoHost.use(
    createApp(database, {
      origin: walletOrigin,
      secure: false,
      geocoding: false,
    }),
  );
  demoHost.use(
    express.static(resolve(root, "dist/client"), {
      index: false,
      fallthrough: true,
    }),
  );
  demoHost.get("/{*path}", (_request, response) =>
    response.sendFile(resolve(root, "dist/client/index.html")),
  );
  const walletServer = createServer(demoHost);
  await listen(walletServer, 5300);
  const address = walletServer.address();
  if (
    !address ||
    typeof address === "string" ||
    address.address !== "127.0.0.1"
  )
    throw new Error("The organizer demo must bind to the loopback interface.");

  const issuer = await startOwnerSession();
  organizerCookie = issuer.cookie;
  const group = await postBrowser(
    "/credential-groups",
    issuer.cookie,
    issuer.csrf,
    {
      name: "Portkey demonstration members",
      description:
        "A demo group. Membership comes from a one-use issuer enrollment link.",
    },
  );
  const invite = await postBrowser(
    `/credential-groups/${group.id}/enrollments`,
    issuer.cookie,
    issuer.csrf,
    { count: 1 },
  );
  const enrollmentToken = invite.enrollments[0].token as string;
  const contract = await postBrowser(
    "/platform/contracts",
    issuer.cookie,
    issuer.csrf,
    {
      name: "Demonstration membership",
      issuerLabel: "Portkey sample issuer",
      description: "Membership in the demonstration group.",
      groupIds: [group.id],
    },
  );
  const enrollmentUrl = `${walletOrigin}/credentials/${group.id}#enroll=${enrollmentToken}`;

  const configurations: DemoApp[] = [];
  for (const app of apps) {
    const config: DemoApp = {
      ...app,
      id: "",
      apiKey: "",
      contractId: contract.id,
      contractVersion: 1,
      contractDigest: contract.digest,
      enrollmentUrl,
      challenge: null,
    };
    const owner = await startOwnerSession();
    const registered = await postBrowser(
      "/platform/apps",
      owner.cookie,
      owner.csrf,
      {
        name: config.name,
        origin: `http://${config.host}:${config.port}`,
        redirectUris: [`http://${config.host}:${config.port}/callback`],
      },
    );
    config.id = registered.id as string;
    config.apiKey = registered.apiKey as string;
    const domainChallenge = await postBrowser(
      `/platform/apps/${config.id}/domain-challenge`,
      owner.cookie,
      owner.csrf,
      {},
    );
    config.challenge = domainChallenge.challenge as string;
    const rpServer = createRelyingApp(config);
    await listen(rpServer, config.port);
    await postBrowser(
      `/platform/apps/${config.id}/verify-domain`,
      owner.cookie,
      owner.csrf,
      {},
    );
    await postBrowser(
      `/platform/apps/${config.id}/trust`,
      owner.cookie,
      owner.csrf,
      { contracts: [{ contractId: contract.id, version: 1 }] },
      "PUT",
    );
    config.challenge = null;
    configurations.push(config);
  }
  readyApplications = configurations.map((app) => ({
    name: app.name,
    origin: `http://${app.host}:${app.port}`,
  }));
  ready = true;
  return { configurations };
}

async function shutdown() {
  if (stopped) return;
  stopped = true;
  if (cleanupScheduler) await cleanupScheduler.stop();
  await Promise.all(
    servers.map(
      (server) =>
        new Promise<void>((resolveClose) => server.close(() => resolveClose())),
    ),
  );
  if (database) await database.close();
  if (cleanupDemoData) await rm(demoData, { recursive: true, force: true });
}

async function main() {
  const { configurations } = await setupDemo();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions)
      if (session.expiresAt <= now) sessions.delete(token);
  }, 60_000);
  timer.unref();
  process.once("SIGINT", () => {
    clearInterval(timer);
    void shutdown().then(() => process.exit(0));
  });
  process.once("SIGTERM", () => {
    clearInterval(timer);
    void shutdown().then(() => process.exit(0));
  });
  console.log("Portkey verification demo is ready.");
  for (const app of configurations)
    console.log(`${app.name}: http://${app.host}:${app.port}`);
  console.log(`Portkey wallet: ${walletOrigin}`);
  console.log(
    `Organizer workspace setup (one use, local only): ${walletOrigin}/platform-demo/organizer#setup=${bootstrapToken}`,
  );
  console.log(
    "Open the organizer setup link first, adopt the workspace with a passkey, then use the same enrolled credential in both applications and the proof room.",
  );
}

void main().catch(async () => {
  console.error(
    "The demo could not start. Check whether its local ports are available and the built client assets are present.",
  );
  await shutdown();
  process.exitCode = 1;
});

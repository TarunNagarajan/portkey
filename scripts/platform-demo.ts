import express, { type Request, type Response } from "express";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type Server } from "node:http";
import { basename, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { rm } from "node:fs/promises";
import { createApp } from "../server/app.js";
import { openDatabase } from "../server/database.js";
import { migrate } from "../server/migrations.js";
import { createPortkeyClient, type ReceiptClaims } from "../sdk/index.js";

const walletOrigin = "http://127.0.0.1:5300";
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

async function listen(server: Server, port: number) {
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
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
    } catch (error) {
      console.error(
        "Demo relying-party request failed:",
        error instanceof Error ? error.message : "unknown error",
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
    } catch {
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

async function setupDemo() {
  database = await openDatabase({ dataDir: demoData });
  await migrate(database);
  const wallet = createApp(database, {
    origin: walletOrigin,
    secure: false,
    geocoding: false,
  });
  wallet.get("/platform-demo/ready", (_request, response) => {
    if (!ready) return response.sendStatus(503);
    response.json({ status: "ready", applications: readyApplications });
  });
  const walletServer = createServer(wallet);
  await listen(walletServer, 5300);
  wallet.use(
    express.static(resolve(root, "dist/client"), {
      index: false,
      fallthrough: true,
    }),
  );
  wallet.get("/{*path}", (_request, response) =>
    response.sendFile(resolve(root, "dist/client/index.html")),
  );

  const issuer = await startOwnerSession();
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
    "Open either app, save the issuer demonstration credential once, then approve a request in Portkey. The same saved credential works in the other app.",
  );
}

void main().catch(async (error) => {
  console.error(
    error instanceof Error ? error.message : "The demo could not start.",
  );
  await shutdown();
  process.exitCode = 1;
});

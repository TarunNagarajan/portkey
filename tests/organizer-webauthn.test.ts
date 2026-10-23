import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, before, beforeEach, test } from "node:test";
import supertest from "supertest";
import type { Express } from "express";
import { createApp } from "../server/app.js";
import { openDatabase, type Database } from "../server/database.js";
import { migrate } from "../server/migrations.js";
import { challengeFrom, createPasskey } from "./helpers/organizerPasskey.js";

const origin = "http://localhost:5173";
let database: Database;
let app: Express;

before(async () => {
  database = await openDatabase();
  await migrate(database);
  // Production account/IP/browser guards remain enabled. Every browser fixture
  // gets its own anonymous session, keeping the production buckets meaningful.
});

beforeEach(() => {
  // Reset in-memory rate-limit buckets between independent API scenarios.
  app = createApp(database, { origin, secure: false });
});

after(async () => {
  if (database) await database.close();
  const curve = (globalThis as typeof globalThis & { curve_bn128?: { terminate: () => Promise<void> } }).curve_bn128;
  if (curve) await curve.terminate();
});

async function browser() {
  const agent = supertest.agent(app);
  const session = await agent.post("/api/session").set("Origin", origin).expect(200);
  const csrf = session.body.csrfToken as string;
  return {
    agent,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) => agent.post(`/api${path}`).set("Origin", origin).set("X-CSRF-Token", csrf).send(body),
    delete: (path: string) => agent.delete(`/api${path}`).set("Origin", origin).set("X-CSRF-Token", csrf),
  };
}

async function register(b: Awaited<ReturnType<typeof browser>>, passkey = createPasskey()) {
  const options = await b.post("/account/signup/options", { adopt: true }).expect(200);
  const response = passkey.registration(challengeFrom(options.body.options), origin);
  const result = await b.post("/account/signup/verify", {
    ceremonyId: options.body.ceremonyId,
    response,
    label: "API acceptance key",
  }).expect(200);
  assert.equal(result.body.signedIn, true);
  assert.match(result.body.recoveryKey, /^pk_recovery_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/i);
  return { passkey, recoveryKey: result.body.recoveryKey as string };
}

async function loginOptions(b: Awaited<ReturnType<typeof browser>>) {
  return b.post("/account/login/options", {}).expect(200);
}

test("real none-attestation signup adopts an owner and a second browser signs in usernamelessly", async () => {
  const first = await browser();
  const { passkey, recoveryKey } = await register(first);
  const keys = await database.query<{ credential_id: string; public_key: Buffer; recovery_digest: Buffer }>(
    "SELECT credential_id,public_key,recovery_digest FROM organizer_credentials JOIN organizer_accounts ON organizer_accounts.id=organizer_credentials.account_id",
  );
  assert.equal(keys.length, 1);
  assert.equal(keys[0].credential_id, passkey.id);
  assert.deepEqual(keys[0].public_key, passkey.coseKey);
  assert.equal(keys[0].recovery_digest.length, 32);
  assert.deepEqual(Buffer.from(keys[0].recovery_digest), createHash("sha256").update(recoveryKey).digest());

  const second = await browser();
  const options = await loginOptions(second);
  assert.equal(options.body.options.allowCredentials.length, 0);
  const handle = Buffer.from((await database.query<{ user_handle: Buffer }>("SELECT user_handle FROM organizer_accounts ORDER BY created_at DESC LIMIT 1"))[0].user_handle).toString("base64url");
  const signed = passkey.assertion(challengeFrom(options.body.options), origin, { counter: 1, userHandle: handle });
  const loggedIn = await second.post("/account/login/verify", { ceremonyId: options.body.ceremonyId, response: signed }).expect(200);
  assert.equal(loggedIn.body.signedIn, true);
  const listed = await second.get("/account/passkeys").expect(200);
  assert.equal(listed.body.passkeys.length, 1);
  assert.equal(listed.body.passkeys[0].credential_id, passkey.id);
  assert.ok(!JSON.stringify(listed.body).includes(Buffer.from(passkey.coseKey).toString("base64url")));
});

test("assertion verification rejects invalid origin, RP, UV, UP, signature, handle, unknown key, and replay", async () => {
  const owner = await browser();
  const { passkey } = await register(owner);
  const account = (await database.query<{ user_handle: Buffer }>("SELECT user_handle FROM organizer_accounts ORDER BY created_at DESC LIMIT 1"))[0];
  assert(account);
  const cases: Array<[string, Record<string, unknown>]> = [
    ["wrong origin", { origin: "https://attacker.example", rpId: "localhost" }],
    ["wrong RP ID", { rpId: "attacker.example" }],
    ["missing user verification", { flags: 0x01 }],
    ["missing user presence", { flags: 0x04 }],
    ["tampered signature", { tamper: true }],
    ["wrong user handle", { userHandle: Buffer.from("another-account").toString("base64url") }],
  ];
  for (const [label, options] of cases) {
    const b = await browser();
    const ceremony = await loginOptions(b);
    const response = passkey.assertion(challengeFrom(ceremony.body.options), (options.origin as string) ?? origin, { userHandle: Buffer.from(account.user_handle).toString("base64url"), ...options });
    const result = await b.post("/account/login/verify", { ceremonyId: ceremony.body.ceremonyId, response });
    assert.equal(result.status, 401, `${label} must fail as an authentication error`);
    assert.equal((await b.get("/account/status")).body.signedIn, false, `${label} created a session`);
  }
  assert.equal(account.user_handle.length, 32);

  const unknownBrowser = await browser();
  const unknownCeremony = await loginOptions(unknownBrowser);
  const unknown = createPasskey("unknown-key");
  const unknownResult = await unknownBrowser.post("/account/login/verify", {
    ceremonyId: unknownCeremony.body.ceremonyId,
    response: unknown.assertion(challengeFrom(unknownCeremony.body.options), origin, { userHandle: Buffer.from(account.user_handle).toString("base64url") }),
  });
  assert.equal(unknownResult.status, 401);

  const replayBrowser = await browser();
  const replayOptions = await loginOptions(replayBrowser);
  const handle = Buffer.from(account.user_handle).toString("base64url");
  const assertion = passkey.assertion(challengeFrom(replayOptions.body.options), origin, { counter: 7, userHandle: handle });
  const initialLogin = await replayBrowser.post("/account/login/verify", { ceremonyId: replayOptions.body.ceremonyId, response: assertion });
  assert.equal(initialLogin.status, 200, JSON.stringify(initialLogin.body));
  await replayBrowser.post("/account/logout", {}).expect(200);
  const replayOptions2 = await loginOptions(replayBrowser);
  const repeatedCounter = passkey.assertion(challengeFrom(replayOptions2.body.options), origin, { counter: 7, userHandle: handle });
  const replay = await replayBrowser.post("/account/login/verify", { ceremonyId: replayOptions2.body.ceremonyId, response: repeatedCounter });
  assert.equal(replay.status, 401, "a repeated authenticator counter must be rejected");
});

test("ceremonies bind browser and kind, are single-use, and adoption stays explicit", async () => {
  const owner = await browser();
  await owner.post("/account/signup/options", { adopt: false }).expect(422);
  const signup = await owner.post("/account/signup/options", { adopt: true }).expect(200);
  const passkey = createPasskey();
  const body = { ceremonyId: signup.body.ceremonyId, response: passkey.registration(challengeFrom(signup.body.options), origin) };
  const other = await browser();
  const crossBrowser = await other.post("/account/signup/verify", body);
  assert.equal(crossBrowser.status, 400);
  await owner.post("/account/signup/verify", body).expect(200);
  await owner.post("/account/logout", {}).expect(200);
  const usedAgain = await owner.post("/account/signup/verify", body);
  assert.equal(usedAgain.status, 400);

  const loginCeremony = await loginOptions(owner);
  const wrongKind = await owner.post("/account/signup/verify", {
    ceremonyId: loginCeremony.body.ceremonyId,
    response: passkey.registration(challengeFrom(loginCeremony.body.options), origin),
  });
  assert.equal(wrongKind.status, 400);
  const expired = await loginOptions(owner);
  await database.query("UPDATE organizer_ceremonies SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", [expired.body.ceremonyId]);
  const expiredResult = await owner.post("/account/login/verify", {
    ceremonyId: expired.body.ceremonyId,
    response: passkey.assertion(challengeFrom(expired.body.options), origin),
  });
  assert.equal(expiredResult.status, 400, "expired challenge must not authenticate");

  const accountHandle = Buffer.from((await database.query<{ user_handle: Buffer }>("SELECT user_handle FROM organizer_accounts ORDER BY created_at DESC LIMIT 1"))[0].user_handle).toString("base64url");
  const freshLogin = await loginOptions(owner);
  await owner.post("/account/login/verify", { ceremonyId: freshLogin.body.ceremonyId, response: passkey.assertion(challengeFrom(freshLogin.body.options), origin, { userHandle: accountHandle, counter: 1 }) }).expect(200);
  const pendingAdd = await owner.post("/account/passkeys/options", {}).expect(200);
  const addedKey = createPasskey("pending-add");
  const pendingAddResponse = addedKey.registration(challengeFrom(pendingAdd.body.options), origin);
  await owner.post("/account/logout", {}).expect(200);
  const postAddLogoutLogin = await loginOptions(owner);
  await owner.post("/account/login/verify", { ceremonyId: postAddLogoutLogin.body.ceremonyId, response: passkey.assertion(challengeFrom(postAddLogoutLogin.body.options), origin, { userHandle: accountHandle, counter: 2 }) }).expect(200);
  const invalidatedAdd = await owner.post("/account/passkeys/verify", { ceremonyId: pendingAdd.body.ceremonyId, response: pendingAddResponse, label: "Must not survive logout" });
  assert.equal(invalidatedAdd.status, 400, JSON.stringify(invalidatedAdd.body));

  const nextLogin = await loginOptions(owner);
  await owner.post("/account/login/verify", { ceremonyId: nextLogin.body.ceremonyId, response: passkey.assertion(challengeFrom(nextLogin.body.options), origin, { userHandle: accountHandle, counter: 3 }) }).expect(200);
  const pendingReauth = await owner.post("/account/reauthenticate/options", {}).expect(200);
  const pendingProof = passkey.assertion(challengeFrom(pendingReauth.body.options), origin, { userHandle: accountHandle, counter: 3 });
  await owner.post("/account/logout", {}).expect(200);
  const postReauthLogout = await loginOptions(owner);
  await owner.post("/account/login/verify", { ceremonyId: postReauthLogout.body.ceremonyId, response: passkey.assertion(challengeFrom(postReauthLogout.body.options), origin, { userHandle: accountHandle, counter: 4 }) }).expect(200);
  const invalidatedReauth = await owner.post("/account/reauthenticate/verify", { ceremonyId: pendingReauth.body.ceremonyId, response: pendingProof });
  assert.equal(invalidatedReauth.status, 400, JSON.stringify(invalidatedReauth.body));
});

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import supertest from "supertest";
import type { Express } from "express";
import { createApp } from "../server/app.js";
import { openDatabase, type Database } from "../server/database.js";
import { migrate } from "../server/migrations.js";

const origin = "http://localhost:5173";
let database: Database;
let app: Express;

before(async () => {
  database = await openDatabase();
  await migrate(database);
  app = createApp(database, { origin, secure: false, rateLimiting: false });
});
after(async () => {
  await database.close();
});

test("account signup options preview but do not claim the current workspace", async () => {
  const agent = supertest.agent(app);
  const session = await agent
    .post("/api/session")
    .set("Origin", origin)
    .expect(200);
  const csrf = session.body.csrfToken as string;
  const create = (path: string, body: object) =>
    agent
      .post(`/api${path}`)
      .set("Origin", origin)
      .set("X-CSRF-Token", csrf)
      .send(body);
  await create("/rooms", {
    title: "Account adoption room",
    description: "Existing room",
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  }).expect(201);
  const before = await agent.get("/api/account/status").expect(200);
  assert.equal(before.body.canAdopt, true);
  assert.equal(before.body.preview.rooms, 1);
  await create("/account/signup/options", { adopt: false }).expect(422);
  const options = await create("/account/signup/options", {
    adopt: true,
  }).expect(200);
  assert.match(options.body.ceremonyId, /^[0-9a-f-]{36}$/i);
  assert.equal(
    options.body.options.authenticatorSelection.residentKey,
    "required",
  );
  assert.equal(
    options.body.options.authenticatorSelection.userVerification,
    "required",
  );
  assert.equal(options.body.options.attestation, "none");
  await create("/account/signup/verify", {
    ceremonyId: options.body.ceremonyId,
    label: "Test passkey",
    response: {
      id: "invalid",
      rawId: "invalid",
      type: "public-key",
      response: {},
    },
  }).expect(400);
  const after = await agent.get("/api/account/status").expect(200);
  assert.equal(after.body.signedIn, false);
  assert.equal(after.body.canAdopt, true);
  assert.equal(after.body.preview.rooms, 1);
  const accounts = await database.query("SELECT id FROM organizer_accounts");
  assert.equal(accounts.length, 0);
});

test("account writes require the configured origin and browser CSRF token", async () => {
  const agent = supertest.agent(app);
  await agent.post("/api/session").set("Origin", origin).expect(200);
  await agent
    .post("/api/account/login/options")
    .set("Origin", "https://other.example")
    .send({})
    .expect(403);
  await agent
    .post("/api/account/login/options")
    .set("Origin", origin)
    .send({})
    .expect(403);
});

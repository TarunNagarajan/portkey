import assert from "node:assert/strict";
import { createHash, randomUUID, webcrypto } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, beforeEach, test } from "node:test";
import supertest from "supertest";
import type { Express } from "express";
import { Group } from "@semaphore-protocol/group";
import { Identity } from "@semaphore-protocol/identity";
import { createPortkeyClient } from "../sdk/index.js";
import { createApp } from "../server/app.js";
import { openDatabase, type Database } from "../server/database.js";
import { migrate } from "../server/migrations.js";
import { platformContractDigest } from "../shared/platform.js";
import { challengeFrom, createPasskey } from "./helpers/organizerPasskey.js";
import { createKey, decryptChunk, decryptDescriptor, exportEncryptedBackup, hpkeOpen, hpkeSeal } from "../client/submissionCrypto.js";

const origin = "http://localhost:5173";
let database: Database;
let app: Express;

function cookiePairs(header: string | string[] | undefined) {
  return (Array.isArray(header) ? header : header ? [header] : []).map((value) => value.split(";")[0]);
}

before(async () => {
  database = await openDatabase();
  await migrate(database);
});
beforeEach(() => {
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
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) => agent.post(`/api${path}`).set("Origin", origin).set("X-CSRF-Token", csrf).send(body),
    delete: (path: string) => agent.delete(`/api${path}`).set("Origin", origin).set("X-CSRF-Token", csrf),
  };
}

test("recovery options do not mutate the account, and one genuine concurrent replacement wins", async () => {
  const owner = await browser();
  const original = createPasskey();
  const signup = await owner.post("/account/signup/options", { adopt: true }).expect(200);
  const registered = await owner.post("/account/signup/verify", {
    ceremonyId: signup.body.ceremonyId,
    response: original.registration(challengeFrom(signup.body.options), origin),
  }).expect(200);
  const recoveryKey = registered.body.recoveryKey as string;
  const before = await database.query<{ id: string; recovery_digest: Buffer; auth_generation: number }>("SELECT id,recovery_digest,auth_generation FROM organizer_accounts ORDER BY created_at DESC LIMIT 1");
  assert.equal(before.length, 1);
  assert.deepEqual(Buffer.from(before[0].recovery_digest), createHash("sha256").update(recoveryKey).digest());

  const badKey = await owner.post("/account/recovery/options", { recoveryKey: recoveryKey.slice(0, -1) + (recoveryKey.endsWith("A") ? "B" : "A") });
  assert.equal(badKey.status, 401);
  const afterBad = (await database.query<{ recovery_digest: Buffer; auth_generation: number; count: number }>("SELECT recovery_digest,auth_generation,(SELECT count(*)::int FROM organizer_credentials WHERE account_id=organizer_accounts.id) count FROM organizer_accounts WHERE id=$1", [before[0].id]))[0];
  assert.deepEqual(afterBad.recovery_digest, before[0].recovery_digest);
  assert.equal(afterBad.auth_generation, before[0].auth_generation);
  assert.equal(afterBad.count, 1);

  const replacement = createPasskey();
  const recovery = await owner.post("/account/recovery/options", { recoveryKey }).expect(200);
  const response = replacement.registration(challengeFrom(recovery.body.options), origin);
  const finish = { ceremonyId: recovery.body.ceremonyId, response, label: "Replacement device" };
  const races = await Promise.all([owner.post("/account/recovery/verify", finish), owner.post("/account/recovery/verify", finish)]);
  assert.equal(races.filter((r) => r.status === 200).length, 1, "exactly one recovery finish should commit");
  assert.equal(races.filter((r) => r.status === 400).length, 1);
  const winner = races.find((r) => r.status === 200)!;
  assert.match(winner.body.recoveryKey, /^pk_recovery_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/i);
  assert.notEqual(winner.body.recoveryKey, recoveryKey);

  const account = (await database.query<{ user_handle: Buffer; auth_generation: number; count: number }>("SELECT user_handle,auth_generation,(SELECT count(*)::int FROM organizer_credentials WHERE account_id=organizer_accounts.id) count FROM organizer_accounts WHERE id=$1", [before[0].id]))[0];
  assert.equal(account.auth_generation, before[0].auth_generation + 1);
  assert.equal(account.count, 1);
  assert.equal((await database.query("SELECT credential_id FROM organizer_credentials WHERE account_id=$1 AND credential_id=$2", [before[0].id, original.id])).length, 0);
  assert.equal((await database.query("SELECT credential_id FROM organizer_credentials WHERE account_id=$1 AND credential_id=$2", [before[0].id, replacement.id])).length, 1);

  const oldKeyAttempt = await owner.post("/account/recovery/options", { recoveryKey });
  assert.equal(oldKeyAttempt.status, 401);
  const newBrowser = await browser();
  const newLogin = await newBrowser.post("/account/login/options", {}).expect(200);
  const newAuth = replacement.assertion(challengeFrom(newLogin.body.options), origin, { userHandle: Buffer.from(account.user_handle).toString("base64url"), counter: 1 });
  await newBrowser.post("/account/login/verify", { ceremonyId: newLogin.body.ceremonyId, response: newAuth }).expect(200);
  const oldBrowser = await browser();
  const oldLogin = await oldBrowser.post("/account/login/options", {}).expect(200);
  const oldAuth = original.assertion(challengeFrom(oldLogin.body.options), origin, { userHandle: Buffer.from(account.user_handle).toString("base64url"), counter: 2 });
  assert.equal((await oldBrowser.post("/account/login/verify", { ceremonyId: oldLogin.body.ceremonyId, response: oldAuth })).status, 401);
});

test("passkey removal and recovery rotation cannot substitute for a recent verified assertion", async () => {
  const owner = await browser();
  const original = createPasskey();
  const signup = await owner.post("/account/signup/options", { adopt: true }).expect(200);
  await owner.post("/account/signup/verify", {
    ceremonyId: signup.body.ceremonyId,
    response: original.registration(challengeFrom(signup.body.options), origin),
  }).expect(200);
  const account = (await database.query<{ id: string; session_id: string; user_handle: Buffer }>("SELECT oa.id,os.id session_id,oa.user_handle FROM organizer_accounts oa JOIN organizer_sessions os ON os.account_id=oa.id ORDER BY oa.created_at DESC LIMIT 1"))[0];
  await database.query("UPDATE organizer_sessions SET verified_at=clock_timestamp()-interval '6 minutes' WHERE id=$1", [account.session_id]);

  const removal = await owner.delete(`/account/passkeys/${encodeURIComponent(original.id)}`);
  assert.equal(removal.status, 401, "removal must require a fresh passkey assertion");
  const rotation = await owner.post("/account/recovery/rotate", {});
  assert.equal(rotation.status, 401, "rotation must require a fresh passkey assertion");
  assert.equal((await database.query("SELECT credential_id FROM organizer_credentials WHERE account_id=$1", [account.id])).length, 1);

  const reauth = await owner.post("/account/reauthenticate/options", {}).expect(200);
  const proof = original.assertion(challengeFrom(reauth.body.options), origin, { userHandle: Buffer.from(account.user_handle).toString("base64url"), counter: 1 });
  const reauthResult = await owner.post("/account/reauthenticate/verify", { ceremonyId: reauth.body.ceremonyId, response: proof });
  assert.equal(reauthResult.status, 200, JSON.stringify(reauthResult.body));
  const added = createPasskey();
  const addOptions = await owner.post("/account/passkeys/options", {}).expect(200);
  await owner.post("/account/passkeys/verify", {
    ceremonyId: addOptions.body.ceremonyId,
    response: added.registration(challengeFrom(addOptions.body.options), origin),
    label: "Second key",
  }).expect(200);
  await owner.delete(`/account/passkeys/${encodeURIComponent(original.id)}`).expect(204);
  const list = await owner.get("/account/passkeys").expect(200);
  assert.deepEqual(list.body.passkeys.map((key: { credential_id: string }) => key.credential_id), [added.id]);
});

test("migration 011 preserves populated legacy IDs and account authority survives database reopen and anchor expiry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "portkey-account-upgrade-"));
  let legacyDb: Database | undefined;
  let platformServer: Server | undefined;
  try {
    legacyDb = await openDatabase({ dataDir: directory });
    await legacyDb.exec("CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, checksum CHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())");
    const migrationsDirectory = new URL("../server/migrations/", import.meta.url);
    const names = (await readdir(migrationsDirectory)).filter((name) => /^0(0[1-9]|10)_.*\.sql$/.test(name)).sort();
    assert.equal(names.length, 10, "the fixture should apply exactly migrations 001 through 010");
    for (const name of names) {
      const sql = (await readFile(new URL(name, migrationsDirectory), "utf8")).replace(/\r\n/g, "\n");
      await legacyDb.transaction(async (tx) => {
        await tx.exec(sql);
        await tx.query("INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)", [name, createHash("sha256").update(sql).digest("hex")]);
      });
    }

    const probe = createServer();
    await new Promise<void>((resolve, reject) => {
      probe.once("error", reject);
      probe.listen(0, "127.0.0.1", () => {
        probe.off("error", reject);
        resolve();
      });
    });
    const probeAddress = probe.address();
    assert(probeAddress && typeof probeAddress === "object");
    const platformOrigin = `http://127.0.0.1:${probeAddress.port}`;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const legacyApp = createApp(legacyDb, { origin: platformOrigin, secure: false });
    platformServer = createServer(legacyApp);
    await new Promise<void>((resolve, reject) => {
      platformServer!.once("error", reject);
      platformServer!.listen(probeAddress.port, "127.0.0.1", () => {
        platformServer!.off("error", reject);
        resolve();
      });
    });
    const legacyOwner = supertest.agent(legacyApp);
    const sessionResponse = await legacyOwner.post("/api/session").set("Origin", platformOrigin).expect(200);
    const anonymousCookie = cookiePairs(sessionResponse.headers["set-cookie"]).join("; ");
    const ownerSession = (await legacyDb.query<{ id: string }>("SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1"))[0].id;
    const roomId = "10000000-0000-4000-8000-000000000001";
    const groupId = "20000000-0000-4000-8000-000000000001";
    const inviteId = "30000000-0000-4000-8000-000000000001";
    const contractId = "40000000-0000-4000-8000-000000000001";
    const appId = "50000000-0000-4000-8000-000000000001";
    const domain = "http://localhost:5174";
    const platformSecret = "A".repeat(43);
    const platformApiKey = `pk_live_${platformSecret}`;
    const enrollmentToken = Buffer.alloc(32, 0x42).toString("base64url");
    const proofIdentity = new Identity();
    const contractDigest = platformContractDigest(contractId, 1, [groupId]);
    await legacyDb.query("INSERT INTO rooms(id,owner_id,join_code,title,description,status,expires_at) VALUES($1,$2,$3,$4,$5,'open',clock_timestamp()+interval '6 hours')", [roomId, ownerSession, "ABCDEF1234567890", "Legacy room", "Room created before organizer accounts"]);
    await legacyDb.query("INSERT INTO room_recipient_keys(room_id,public_key,fingerprint) VALUES($1,$2,$3)", [roomId, Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 0x11)]), "a".repeat(64)]);
    await legacyDb.query("INSERT INTO session_recipient_keys(room_id,session_id,public_key,fingerprint) VALUES($1,$2,$3,$4)", [roomId, ownerSession, Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 0x22)]), "b".repeat(64)]);
    await legacyDb.query("INSERT INTO credential_groups(id,owner_session_id,name,description) VALUES($1,$2,$3,$4)", [groupId, ownerSession, "Legacy cohort", "Persisted issuer group"]);
    await legacyDb.query("INSERT INTO credential_group_invites(id,group_id,invite_number,token_digest) VALUES($1,$2,1,$3)", [inviteId, groupId, createHash("sha256").update(Buffer.from(enrollmentToken, "base64url")).digest()]);
    await legacyDb.query("INSERT INTO platform_contracts(id,owner_session_id,name,issuer_label) VALUES($1,$2,$3,$4)", [contractId, ownerSession, "Legacy contract", "Legacy issuer"]);
    await legacyDb.query("INSERT INTO platform_contract_versions(contract_id,version,description,group_ids,digest) VALUES($1,1,$2,ARRAY[$3]::uuid[],$4)", [contractId, "Persisted contract version", groupId, contractDigest]);
    await legacyDb.query("INSERT INTO platform_apps(id,owner_session_id,name,origin,redirect_uris,key_digest,domain_verified_at) VALUES($1,$2,$3,$4,ARRAY[$5]::text[],$6,clock_timestamp())", [appId, ownerSession, "Legacy relying app", domain, `${domain}/callback`, createHash("sha256").update(platformSecret).digest()]);
    await legacyDb.query("INSERT INTO platform_app_trust(app_id,contract_id,contract_version) VALUES($1,$2,1)", [appId, contractId]);
    const participantSessionId = randomUUID();
    await legacyDb.query("INSERT INTO sessions(id,token_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '6 hours')", [participantSessionId, createHash("sha256").update(randomUUID()).digest("hex")]);
    await legacyDb.query("INSERT INTO memberships(id,room_id,session_id,label,status,decided_at) VALUES($1,$2,$3,'Legacy participant','approved',clock_timestamp())", [randomUUID(), roomId, participantSessionId]);

    // Create a genuine encrypted submission under the legacy stable owner ID.
    // After adoption, a different browser must still select and decrypt that envelope.
    const keyPair = await createKey();
    await legacyDb.query("UPDATE room_recipient_keys SET public_key=$2,fingerprint=$3 WHERE room_id=$1", [roomId, Buffer.from(keyPair.publicKey), keyPair.fingerprint]);
    await legacyDb.query("UPDATE session_recipient_keys SET public_key=$3,fingerprint=$4 WHERE room_id=$1 AND session_id=$2", [roomId, ownerSession, Buffer.from(keyPair.publicKey), keyPair.fingerprint]);
    const submissionId = randomUUID();
    const objectId = submissionId;
    const plaintext = new TextEncoder().encode("legacy encrypted file survives account adoption");
    const fileKey = webcrypto.getRandomValues(new Uint8Array(32));
    const salt = webcrypto.getRandomValues(new Uint8Array(32));
    const noncePrefix = webcrypto.getRandomValues(new Uint8Array(8));
    const metadataNonce = webcrypto.getRandomValues(new Uint8Array(12));
    const derive = async (label: string) => {
      const material = await webcrypto.subtle.importKey("raw", fileKey, "HKDF", false, ["deriveKey"]);
      return webcrypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(`portkey-private-submission-v1:${label}`) }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    };
    const descriptorValue = { protocol: "portkey-private-submission-v1", filename: "legacy.txt", mediaType: "text/plain", size: plaintext.length, chunkSizes: [plaintext.length], keySalt: Buffer.from(salt).toString("base64"), noncePrefix: Buffer.from(noncePrefix).toString("base64"), metadataNonce: Buffer.from(metadataNonce).toString("base64") };
    const metadataAad = new TextEncoder().encode(JSON.stringify({ protocol: "portkey-private-submission-v1", roomId, objectId, purpose: "encrypted-descriptor" }));
    const encryptedMetadata = new Uint8Array(await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: metadataNonce, additionalData: metadataAad }, await derive("metadata"), new TextEncoder().encode(JSON.stringify(descriptorValue))));
    const descriptor = Buffer.concat([Buffer.from([1]), Buffer.from(salt), Buffer.from(noncePrefix), Buffer.from(metadataNonce), Buffer.from(encryptedMetadata)]);
    const chunkNonce = new Uint8Array(12); chunkNonce.set(noncePrefix); new DataView(chunkNonce.buffer).setUint32(8, 0, false);
    const chunkAad = new TextEncoder().encode(JSON.stringify({ protocol: "portkey-private-submission-v1", roomId, objectId, purpose: "content-chunk", index: 0, plainLength: plaintext.length }));
    const chunk = new Uint8Array(await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: chunkNonce, additionalData: chunkAad }, await derive("content"), plaintext));
    const envelopeInfo = new TextEncoder().encode(JSON.stringify({ protocol: "portkey-private-submission-v1", roomId, objectId, recipientFingerprint: keyPair.fingerprint, purpose: "submission-file-key" }));
    const envelope = await hpkeSeal(keyPair.publicKey, fileKey, envelopeInfo);
    const manifest = createHash("sha256").update(descriptor).update(createHash("sha256").update(chunk).digest()).digest("hex");
    await legacyDb.query("INSERT INTO private_submissions(id,room_id,submitter_id,encrypted_descriptor,chunk_count,encrypted_bytes,status,manifest_sha256,receipt,completed_at) VALUES($1,$2,$3,$4,1,$5,'complete',$6,'{}'::jsonb,clock_timestamp())", [submissionId, roomId, participantSessionId, descriptor, chunk.length, manifest]);
    await legacyDb.query("INSERT INTO submission_envelopes(submission_id,recipient_id,enc,ciphertext) VALUES($1,$2,$3,$4)", [submissionId, ownerSession, Buffer.from(envelope.enc), Buffer.from(envelope.ciphertext)]);
    await legacyDb.query("INSERT INTO submission_chunks(submission_id,chunk_index,ciphertext,sha256) VALUES($1,0,$2,$3)", [submissionId, Buffer.from(chunk), createHash("sha256").update(chunk).digest("hex")]);
    const backupPassword = "migration test backup passphrase";
    const backup = JSON.parse(await exportEncryptedBackup(roomId, keyPair, backupPassword)) as { salt: string; nonce: string; ciphertext: string };
    const backupMaterial = await webcrypto.subtle.importKey("raw", new TextEncoder().encode(backupPassword), "PBKDF2", false, ["deriveKey"]);
    const backupAes = await webcrypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: Buffer.from(backup.salt, "base64"), iterations: 600000 }, backupMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const backupPlaintext = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(backup.nonce, "base64"), additionalData: new TextEncoder().encode("portkey-key-backup-v1") }, backupAes, Buffer.from(backup.ciphertext, "base64"));
    const saved = JSON.parse(new TextDecoder().decode(backupPlaintext)) as { publicKey: string; privateKey: string; fingerprint: string; roomId: string };
    assert.equal(saved.roomId, roomId);
    const restoredKey = { publicKey: Buffer.from(saved.publicKey, "base64"), privateKey: Buffer.from(saved.privateKey, "base64"), fingerprint: saved.fingerprint };

    await migrate(legacyDb);
    const ownerKey = createPasskey();
    const signupOptions = await legacyOwner.post("/api/account/signup/options").set("Origin", platformOrigin).set("X-CSRF-Token", sessionResponse.body.csrfToken).send({ adopt: true }).expect(200);
    const signup = await legacyOwner.post("/api/account/signup/verify").set("Origin", platformOrigin).set("X-CSRF-Token", sessionResponse.body.csrfToken).send({ ceremonyId: signupOptions.body.ceremonyId, response: ownerKey.registration(challengeFrom(signupOptions.body.options), platformOrigin) }).expect(200);
    const account = (await legacyDb.query<{ id: string; user_handle: Buffer }>("SELECT id,user_handle FROM organizer_accounts WHERE owner_session_id=$1", [ownerSession]))[0];
    assert(account);
    assert.match(signup.body.recoveryKey, /^pk_recovery_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/i);
    await legacyOwner.post("/api/join/ABCDEF1234567890").set("Origin", platformOrigin).set("X-CSRF-Token", sessionResponse.body.csrfToken).send({ label: "Owner cannot self-join" }).expect(409);
    const preserved = await legacyDb.query<{ room_id: string; owner_id: string; group_id: string; invite_id: string; contract_id: string; app_id: string; recipient_id: string }>(
      `SELECT r.id room_id,r.owner_id,g.id group_id,i.id invite_id,c.id contract_id,a.id app_id,s.session_id recipient_id
       FROM rooms r JOIN credential_groups g ON g.owner_session_id=r.owner_id JOIN credential_group_invites i ON i.group_id=g.id
       JOIN platform_contracts c ON c.owner_session_id=r.owner_id JOIN platform_apps a ON a.owner_session_id=r.owner_id
       JOIN session_recipient_keys s ON s.room_id=r.id WHERE r.id=$1`, [roomId]);
    assert.deepEqual(preserved.map((row) => [row.room_id,row.owner_id,row.group_id,row.invite_id,row.contract_id,row.app_id,row.recipient_id]), [[roomId,ownerSession,groupId,inviteId,contractId,appId,ownerSession]]);

    await legacyDb.query("UPDATE sessions SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", [ownerSession]);
    const anchorState = (await legacyDb.query<{ available: boolean; expires_at: Date | null }>("SELECT available,expires_at FROM owner_authorities WHERE id=$1", [ownerSession]))[0];
    assert.equal(anchorState.available, true);
    assert.equal(anchorState.expires_at, null);

    const foreignOwner = supertest.agent(legacyApp);
    const foreignSession = await foreignOwner.post("/api/session").set("Origin", platformOrigin).expect(200);
    const foreignKey = createPasskey();
    const foreignOptions = await foreignOwner.post("/api/account/signup/options").set("Origin", platformOrigin).set("X-CSRF-Token", foreignSession.body.csrfToken).send({ adopt: true }).expect(200);
    await foreignOwner.post("/api/account/signup/verify").set("Origin", platformOrigin).set("X-CSRF-Token", foreignSession.body.csrfToken).send({ ceremonyId: foreignOptions.body.ceremonyId, response: foreignKey.registration(challengeFrom(foreignOptions.body.options), platformOrigin) }).expect(200);
    await foreignOwner.get(`/api/credential-groups/${groupId}`).expect(404);
    const oldCookieWrite = await supertest(legacyApp).post("/api/credential-groups").set("Origin", platformOrigin).set("X-CSRF-Token", sessionResponse.body.csrfToken).set("Cookie", anonymousCookie).send({ name: "Unauthorized group" });
    assert.equal(oldCookieWrite.status, 401, "the original anonymous cookie must not retain organizer ownership");

    const secondBrowser = supertest.agent(legacyApp);
    const secondSession = await secondBrowser.post("/api/session").set("Origin", platformOrigin).expect(200);
    const loginOptions = await secondBrowser.post("/api/account/login/options").set("Origin", platformOrigin).set("X-CSRF-Token", secondSession.body.csrfToken).send({}).expect(200);
    const loggedIn = await secondBrowser.post("/api/account/login/verify").set("Origin", platformOrigin).set("X-CSRF-Token", secondSession.body.csrfToken).send({ ceremonyId: loginOptions.body.ceremonyId, response: ownerKey.assertion(challengeFrom(loginOptions.body.options), platformOrigin, { userHandle: Buffer.from(account.user_handle).toString("base64url"), counter: 1 }) }).expect(200);
    const accountCookie = [...cookiePairs(secondSession.headers["set-cookie"]), ...cookiePairs(loggedIn.headers["set-cookie"])].join("; ");
    assert.equal((await secondBrowser.get("/api/rooms")).body.some((room: { id: string }) => room.id === roomId), true);
    const inbox = await secondBrowser.get(`/api/rooms/${roomId}/submissions`).expect(200);
    const savedSubmission = inbox.body.submissions.find((item: { id: string }) => item.id === submissionId);
    assert(savedSubmission, "the adopted account must find the legacy owner envelope by stable owner ID");
    const restoredFileKey = await hpkeOpen(restoredKey, savedSubmission.envelope, envelopeInfo);
    const decryptedDescriptor = await decryptDescriptor(savedSubmission.descriptor, restoredFileKey, roomId, submissionId);
    const downloadedChunk = await secondBrowser.get(`/api/rooms/${roomId}/submissions/${submissionId}/chunks/0`).expect(200);
    const decryptedChunk = await decryptChunk(new Uint8Array(downloadedChunk.body), restoredFileKey, decryptedDescriptor.keySalt, decryptedDescriptor.noncePrefix, roomId, submissionId, 0, decryptedDescriptor.chunkSizes[0]);
    assert.deepEqual(Buffer.from(decryptedChunk), Buffer.from(plaintext));
    const groupList = await secondBrowser.get("/api/credential-groups").expect(200);
    assert.equal(groupList.body.groups.some((group: { id: string; availableUntil: string | null; persistent: boolean }) => group.id === groupId && group.availableUntil === null && group.persistent), true);
    assert.equal((await secondBrowser.get("/api/platform/contracts").expect(200)).body.contracts.some((contract: { id: string }) => contract.id === contractId), true);
    assert.equal((await secondBrowser.get("/api/platform/apps").expect(200)).body.apps.some((item: { id: string }) => item.id === appId), true);

    const wallet = supertest.agent(legacyApp);
    const walletSession = await wallet.post("/api/session").set("Origin", platformOrigin).expect(200);
    const enrollResult = await wallet.post(`/api/credentials/${groupId}/enroll`).set("Origin", platformOrigin).set("X-CSRF-Token", walletSession.body.csrfToken).send({ token: enrollmentToken, commitment: proofIdentity.commitment.toString() });
    assert.equal(enrollResult.status, 200, JSON.stringify(enrollResult.body));
    const client = createPortkeyClient({ origin: platformOrigin, apiKey: platformApiKey, appId });
    const proofRequest = await client.createProofRequest({ contractId, contractVersion: 1, redirectUri: `${domain}/callback` });
    const capability = new URLSearchParams(new URL(proofRequest.walletUrl).hash.slice(1)).get("request");
    assert(capability);
    const walletProofOptions = { Origin: platformOrigin, "X-CSRF-Token": walletSession.body.csrfToken };
    const challenge = (await wallet.post(`/api/platform/wallet/proof-requests/${proofRequest.requestId}/challenge`).set(walletProofOptions).send({ capability }).expect(200)).body as { challengeId: string; depth: number; message: string; scope: string; commitments: string[] };
    assert.equal(challenge.depth, 10);
    assert.deepEqual(challenge.commitments, [proofIdentity.commitment.toString()]);
    const { generateProof } = await import("@semaphore-protocol/proof");
    const { resolve } = await import("node:path");
    const proof = await generateProof(proofIdentity, new Group(challenge.commitments.map(BigInt)), challenge.message, challenge.scope, challenge.depth, {
      wasm: resolve("public/zk/semaphore-10.wasm"),
      zkey: resolve("public/zk/semaphore-10.zkey"),
    });
    await wallet.post(`/api/platform/wallet/proof-requests/${proofRequest.requestId}/prove`).set(walletProofOptions).send({ capability, challengeId: challenge.challengeId, proof }).expect(200);
    const returned = (await wallet.post(`/api/platform/wallet/proof-requests/${proofRequest.requestId}/return`).set(walletProofOptions).send({ capability }).expect(200)).body as { redirectUrl: string };
    const code = new URLSearchParams(new URL(returned.redirectUrl).hash.slice(1)).get("code");
    assert(code);
    const exchanged = await client.exchange(proofRequest.requestId, code, proofRequest.codeVerifier, { contractId, contractVersion: 1, contractDigest });
    assert.equal(Object.keys(exchanged.claims).some((key) => /account|owner/i.test(key)), false);
    assert.equal(JSON.stringify(exchanged.claims).includes(account.id), false, "receipts must not disclose organizer account identity");
    assert.equal(JSON.stringify(exchanged.claims).includes(ownerSession), false, "receipts must not disclose the owner anchor");
    const walletToken = cookiePairs(walletSession.headers["set-cookie"])[0].split("=")[1];
    const walletSessionId = (await legacyDb.query<{ id: string }>("SELECT id FROM sessions WHERE token_hash=$1", [createHash("sha256").update(walletToken).digest("hex")]))[0].id;
    const requestBinding = (await legacyDb.query<{ wallet_session_id: string }>("SELECT wallet_session_id FROM platform_requests WHERE id=$1", [proofRequest.requestId]))[0];
    const challengeBinding = (await legacyDb.query<{ wallet_session_id: string }>("SELECT wallet_session_id FROM platform_challenges WHERE request_id=$1", [proofRequest.requestId]))[0];
    assert.equal(requestBinding.wallet_session_id, walletSessionId);
    assert.equal(challengeBinding.wallet_session_id, walletSessionId);

    await new Promise<void>((resolve) => platformServer!.close(() => resolve()));
    platformServer = undefined;
    await legacyDb.close();
    legacyDb = await openDatabase({ dataDir: directory });
    await migrate(legacyDb);
    const reopenedApp = createApp(legacyDb, { origin: platformOrigin, secure: false });
    const roomsAfterReopen = await supertest(reopenedApp).get("/api/rooms").set("Cookie", accountCookie).expect(200);
    assert.equal(roomsAfterReopen.body.some((room: { id: string }) => room.id === roomId), true);
    assert.equal((await supertest(reopenedApp).get("/api/credential-groups").set("Cookie", accountCookie).expect(200)).body.groups.some((group: { id: string }) => group.id === groupId), true);
    assert.equal((await supertest(reopenedApp).get("/api/platform/contracts").set("Cookie", accountCookie).expect(200)).body.contracts.some((contract: { id: string }) => contract.id === contractId), true);
    assert.equal((await supertest(reopenedApp).get("/api/platform/apps").set("Cookie", accountCookie).expect(200)).body.apps.some((item: { id: string }) => item.id === appId), true);
    const keysAfterReopen = await legacyDb.query<{ room_id: string; session_id: string; public_key: Buffer }>("SELECT room_id,session_id,public_key FROM session_recipient_keys WHERE room_id=$1", [roomId]);
    assert.equal(keysAfterReopen[0].session_id, ownerSession);
    assert.deepEqual(Buffer.from(keysAfterReopen[0].public_key), Buffer.from(keyPair.publicKey));
    assert.equal((await supertest(reopenedApp).get("/api/account/status").set("Cookie", accountCookie).expect(200)).body.signedIn, true);
    await legacyDb.close();
    legacyDb = undefined;
  } finally {
    if (platformServer?.listening) await new Promise<void>((resolve) => platformServer!.close(() => resolve()));
    if (legacyDb) await legacyDb.close();
    await rm(directory, { recursive: true, force: true });
  }
});

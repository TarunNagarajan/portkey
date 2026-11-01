import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import supertest from 'supertest';
import type { Express } from 'express';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from './database.js';
import { migrate } from '../server/migrations.js';
import {
  deriveRadius,
  haversineMeters,
  isInside,
  suggestRadiusFromBbox,
} from '../shared/geo.js';
import type { Room } from '../shared/rooms.js';

const origin = 'http://localhost:5173';
let database: Database;
let app: Express;

before(async () => {
  database = await openDatabase();
  await migrate(database);
  // Geocoding is disabled so tests never depend on the public Nominatim service.
  app = createApp(database, { origin, secure: false, rateLimiting: false, geocoding: false });
});
after(async () => {
  await database.close();
});

async function browser() {
  const agent = supertest.agent(app);
  const response = await agent.post('/api/session').set('Origin', origin).expect(200);
  const csrf = response.body.csrfToken as string;
  return {
    agent,
    csrf,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) =>
      agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    patch: (path: string, body: object) =>
      agent.patch(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    delete: (path: string) =>
      agent.delete(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf),
  };
}

type Browser = Awaited<ReturnType<typeof browser>>;
const input = () => ({
  title: 'Geo workshop',
  description: 'nearby only',
  expiresAt: new Date(Date.now() + 3600_000).toISOString(),
});
const fix = (lat: number, lng: number, accuracyM = 10) => ({
  lat,
  lng,
  accuracyM,
  timestamp: new Date().toISOString(),
});

// Warangal, Telangana.
const anchor = { lat: 17.9689, lng: 79.5941 };
const acrossTown = { lat: 18.02, lng: 79.58 };
const hyderabad = { lat: 17.385, lng: 78.4867 };

async function createAreaRoom(owner: Browser, radiusM = 150) {
  const created = (await owner.post('/rooms', input()).expect(201)).body as Room;
  const restricted = (
    await owner
      .post(`/rooms/${created.id}/geo`, {
        ...anchor,
        radiusM,
        label: 'Test area',
        source: 'device',
      })
      .expect(200)
  ).body as Room;
  assert.ok(restricted.geo);
  assert.equal(restricted.geo!.radiusM, radiusM);
  return (await owner.post(`/rooms/${created.id}/open`).expect(200)).body as Room;
}

test('haversine and radius derivation behave at room scale', () => {
  assert.equal(deriveRadius(10), 50);
  assert.equal(deriveRadius(60), 120);
  assert.equal(deriveRadius(5000), 150);
  const nearby = haversineMeters(anchor, { lat: 17.96905, lng: 79.5942 });
  assert.ok(nearby < 150, `expected nearby, got ${nearby}`);
  const far = haversineMeters(anchor, hyderabad);
  assert.ok(far > 100_000, `expected Hyderabad far, got ${far}`);
  assert.equal(isInside({ lat: 17.96905, lng: 79.5942 }, { ...anchor, radiusM: 150 }), true);
  assert.equal(isInside(hyderabad, { ...anchor, radiusM: 150 }), false);
});

test('bounding boxes suggest a usable area radius', () => {
  const small = suggestRadiusFromBbox([17.9639, 17.9739, 79.5891, 79.5991]);
  assert.ok(small >= 50 && small <= 50_000, `small radius out of range: ${small}`);
  const city = suggestRadiusFromBbox([17.7, 18.2, 79.2, 79.9]);
  assert.ok(city > 5_000 && city <= 50_000, `city radius out of range: ${city}`);
});

test('a restricted room requires a location to request access', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createAreaRoom(owner);
  const missing = await participant.post(`/join/${room.joinCode}`, { label: 'Team Cedar' });
  assert.equal(missing.status, 403);
  assert.equal(missing.body.error.code, 'GEO_REQUIRED');
});

test('outside join requests are rejected with distance', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createAreaRoom(owner);
  const response = await participant.post(`/join/${room.joinCode}`, {
    label: 'Far away',
    ...fix(hyderabad.lat, hyderabad.lng),
  });
  assert.equal(response.status, 403);
  assert.equal(response.body.error.code, 'GEO_OUTSIDE');
});

test('large areas accept participants across the city but reject other cities', async () => {
  const owner = await browser();
  const room = await createAreaRoom(owner, 20_000);
  const nearby = await browser();
  await nearby
    .post(`/join/${room.joinCode}`, { label: 'Across town', ...fix(acrossTown.lat, acrossTown.lng) })
    .expect(200);
  const faraway = await browser();
  const rejected = await faraway.post(`/join/${room.joinCode}`, {
    label: 'Hyderabad',
    ...fix(hyderabad.lat, hyderabad.lng),
  });
  assert.equal(rejected.status, 403);
  assert.equal(rejected.body.error.code, 'GEO_OUTSIDE');
});

test('inside join records proximity for the owner', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createAreaRoom(owner);
  await participant
    .post(`/join/${room.joinCode}`, { label: 'Nearby', ...fix(17.96905, 79.5942) })
    .expect(200);
  const members = (await owner.get(`/rooms/${room.id}/members`).expect(200)).body;
  assert.equal(members.length, 1);
  assert.equal(members[0].inside, true);
  assert.ok(members[0].distanceM < 150);
});

test('entry is re-checked after approval', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createAreaRoom(owner);
  const member = (
    await participant
      .post(`/join/${room.joinCode}`, { label: 'Nearby', ...fix(17.96905, 79.5942) })
      .expect(200)
  ).body;
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' }).expect(200);
  await participant.get(`/rooms/${room.id}`).expect(200);
  await participant.post(`/rooms/${room.id}/position`, fix(hyderabad.lat, hyderabad.lng)).expect(200);
  const outside = await participant.get(`/rooms/${room.id}`);
  assert.equal(outside.status, 403);
  assert.equal(outside.body.error.code, 'GEO_OUTSIDE');
  await database.query(
    `UPDATE memberships SET last_lat = $2, last_lng = $3, last_inside = true,
      last_checked_at = clock_timestamp() - interval '10 minutes'
     WHERE room_id = $1`,
    [room.id, anchor.lat, anchor.lng],
  );
  const stale = await participant.get(`/rooms/${room.id}`);
  assert.equal(stale.status, 403);
  assert.equal(stale.body.error.code, 'GEO_STALE');
});

test('low-accuracy and stale fixes are rejected', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createAreaRoom(owner);
  await participant
    .post(`/join/${room.joinCode}`, { label: 'Fuzzy', ...fix(anchor.lat, anchor.lng, 500) })
    .expect(422);
  await participant
    .post(`/join/${room.joinCode}`, {
      label: 'Old',
      lat: anchor.lat,
      lng: anchor.lng,
      accuracyM: 10,
      timestamp: new Date(Date.now() - 10 * 60_000).toISOString(),
    })
    .expect(422);
});

test('rooms without an area are unaffected', async () => {
  const owner = await browser();
  const participant = await browser();
  const created = (await owner.post('/rooms', input()).expect(201)).body as Room;
  assert.equal(created.geo, null);
  const room = (await owner.post(`/rooms/${created.id}/open`).expect(200)).body as Room;
  await participant.post(`/join/${room.joinCode}`, { label: 'Anywhere' }).expect(200);
});

test('an owner can clear the area while the room is a draft', async () => {
  const owner = await browser();
  const created = (await owner.post('/rooms', input()).expect(201)).body as Room;
  await owner
    .post(`/rooms/${created.id}/geo`, { ...anchor, radiusM: 500, label: 'Warehouse' })
    .expect(200);
  const cleared = (await owner.delete(`/rooms/${created.id}/geo`).expect(200)).body as Room;
  assert.equal(cleared.geo, null);
  assert.equal(cleared.geoLabel, null);
});

test('the area can change after opening but locks once a participant is admitted', async () => {
  const owner = await browser();
  const participant = await browser();
  const created = (await owner.post('/rooms', input()).expect(201)).body as Room;
  const room = (await owner.post(`/rooms/${created.id}/open`).expect(200)).body as Room;

  // Still adjustable after opening, while nobody has been admitted.
  await owner
    .post(`/rooms/${created.id}/geo`, {
      ...anchor,
      radiusM: 500,
      label: 'Opening area',
    })
    .expect(200);

  await participant
    .post(`/join/${room.joinCode}`, {
      label: 'Nearby',
      ...fix(anchor.lat, anchor.lng),
    })
    .expect(200);
  const members = await owner.get(`/rooms/${created.id}/members`).expect(200);
  await owner
    .patch(`/rooms/${created.id}/members/${members.body[0].id}`, {
      status: 'approved',
    })
    .expect(200);

  // The fence is fixed for the participant who was admitted under it.
  await owner
    .post(`/rooms/${created.id}/geo`, { ...anchor, radiusM: 600 })
    .expect(409);
  await owner.delete(`/rooms/${created.id}/geo`).expect(409);
});

test('kilometre-scale phone readings get GEO_INACCURATE guidance rather than schema errors', async () => {
  const owner = await browser(), participant = await browser();
  const room = await createAreaRoom(owner);
  for (const accuracyM of [2500, 50_000]) {
    const rejected = await participant.post(`/join/${room.joinCode}`, {
      label: 'Approximate location', ...fix(anchor.lat, anchor.lng, accuracyM),
    }).expect(422);
    assert.equal(rejected.body.error.code, 'GEO_INACCURATE');
    assert.match(rejected.body.error.message, /75 m.*Enable precise location/);
  }
  const joined = (await participant.post(`/join/${room.joinCode}`, {
    label: 'Precise location', ...fix(anchor.lat, anchor.lng),
  }).expect(200)).body;
  await owner.patch(`/rooms/${room.id}/members/${joined.id}`, { status: 'approved' }).expect(200);
  const refresh = await participant.post(`/rooms/${room.id}/position`, fix(anchor.lat, anchor.lng, 2500)).expect(422);
  assert.equal(refresh.body.error.code, 'GEO_INACCURATE');
  await participant.get(`/rooms/${room.id}`).expect(200);
  const members = (await owner.get(`/rooms/${room.id}/members`).expect(200)).body;
  assert.equal(members[0].accuracyM, 10);
});

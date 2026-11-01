import assert from 'node:assert/strict';
import { test } from 'node:test';
import supertest from 'supertest';
import { openDatabase } from './database.js';
import { migrate } from '../server/migrations.js';
import { createApp } from '../server/app.js';
import { runFileCleanupPass } from '../server/cleanup.js';
test('metrics require a separate secret and cleanup clears old proximity data and backlog', async () => {
  const database = await openDatabase();
  try {
    await migrate(database);
    const token = 'operations-secret-'.repeat(3);
    const app = createApp(database, { origin: 'http://localhost', secure: false, rateLimiting: false, metricsToken: token });
    await supertest(app).get('/api/ops/metrics').expect(403);
    await supertest(app).get('/api/ops/metrics').set('Authorization', 'Bearer wrong').expect(403);
    await database.exec(`INSERT INTO sessions(id, token_hash, expires_at) VALUES ('11111111-1111-4111-8111-111111111111', repeat('a',64), clock_timestamp() + interval '30 days');
      INSERT INTO rooms(id, owner_id, join_code, title, created_at, expires_at) VALUES ('22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', 'metrics-test-123', 'Metrics test', clock_timestamp() - interval '2 days', clock_timestamp() - interval '1 hour');
      INSERT INTO memberships(id, room_id, session_id, label, last_lat, last_lng, last_checked_at) VALUES ('33333333-3333-4333-8333-333333333333', '22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', 'Test', 1, 2, clock_timestamp() - interval '25 hours');`);
    const before = await supertest(app).get('/api/ops/metrics').set('Authorization', `Bearer ${token}`).expect(200);
    assert.equal(before.body.cleanup_backlog, 1);
    assert.ok(!JSON.stringify(before.body).includes(token));
    await runFileCleanupPass(database);
    const after = await supertest(app).get('/api/ops/metrics').set('Authorization', `Bearer ${token}`).expect(200);
    assert.equal(after.body.cleanup_backlog, 0);
    const [member] = await database.query<{ last_lat: number | null; last_lng: number | null }>('SELECT last_lat, last_lng FROM memberships');
    assert.equal(member.last_lat, null); assert.equal(member.last_lng, null);
  } finally { await database.close(); }
});

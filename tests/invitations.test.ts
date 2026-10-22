import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildInvitationUrl, configuredPageUrl, isLocalOrigin } from '../client/api.js';

test('invitation URLs use the canonical origin and keep validated fingerprints in the fragment', () => {
  const link = buildInvitationUrl('https://portkey.example', 'Ab_cd-1234567890', 'a'.repeat(64));
  assert.equal(link, `https://portkey.example/join/Ab_cd-1234567890#key=${'a'.repeat(64)}`);
  assert.throws(() => buildInvitationUrl('https://portkey.example', 'abc'), /code/);
  assert.throws(() => buildInvitationUrl('https://portkey.example', 'Ab_cd-1234567890', 'bad'), /fingerprint/);
  assert.throws(() => buildInvitationUrl('https://user:pass@portkey.example/path', 'Ab_cd-1234567890'), /origin/);
});

test('pass links use canonical token fragments alongside the inbox fingerprint', () => {
  const token = Buffer.alloc(32, 1).toString('base64url');
  const link = buildInvitationUrl('https://portkey.example', 'Ab_cd-1234567890', 'a'.repeat(64), token);
  assert.equal(link, `https://portkey.example/join/Ab_cd-1234567890#pass=${token}&key=${'a'.repeat(64)}`);
  assert.throws(() => buildInvitationUrl('https://portkey.example', 'Ab_cd-1234567890', null, `${token.slice(0, 42)}B`), /pass/);
  assert.throws(() => buildInvitationUrl('https://portkey.example', 'Ab_cd-1234567890', null, ''), /pass/);
});

test('mismatch navigation cannot change the configured host with a network-path page URL', () => {
  for (const pathname of ['//attacker.example/path', '\\\\attacker.example\\path']) {
    const target = new URL(configuredPageUrl('https://portkey.onrender.com', pathname, '?from=invite', '#key=secret'));
    assert.equal(target.origin, 'https://portkey.onrender.com');
    assert.equal(target.hash, '#key=secret');
  }
  assert.equal(isLocalOrigin('http://127.0.0.2:5173'), true);
  assert.equal(isLocalOrigin('http://[::1]:5173'), true);
});

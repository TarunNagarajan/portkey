# Portkey completion review - 1 November 2026

This update implements the requested software work from the initial review, excluding participant uploads. It preserves the existing product pivot and adds migration 010 rather than rewriting historical migrations. The initial findings remain in `docs/initial-audit.md` as a historical snapshot.

## Delivered

| Area | Current behavior |
| --- | --- |
| Proof binding | Credential v2 circuit binds a fresh ten-minute random challenge to the holder secret. The server scopes it to the requesting room/session and consumes it on admission. Copied cross-session and consumed proofs fail. |
| Credential lifecycle | Issuer-signed expiry is checked on admission and subsequent access. Issuer-signed, room-scoped revocations invalidate existing access and future joins. CLI issuance/revocation, an institution-side worker/timer for current and future rooms, and rotation procedures are supplied. Worker delivery is idempotent and tested. |
| Setup provenance | Import path verifies external ptau and circuit-specific zkey contributions, exports a matching verifier and emits SHA-256 manifests. Startup verifies assets and blocks development setup/known demo issuer outside explicit demo mode. |
| Earlier files | Every admitted member can read earlier and future files through the invitation receiving key. Existing active rooms upgrade automatically when the organizer opens them. Owner-only shared-envelope registration is immutable and idempotent. |
| Key rotation | Existing file envelopes are rewrapped atomically. Every visible publication must be covered, expected fingerprints must match, and incomplete uploads block rotation. Saved candidate keys recover from lost registration responses. |
| Ownership recovery | One-time high-entropy codes transfer management/file authority to a new browser session. Codes rotate and invalidate after use. Encryption backup restoration remains separate. |
| Durable resume | Plans and immutable encrypted chunks persist in IndexedDB. Immutable source snapshots use OPFS or a 50 MiB ArrayBuffer fallback. Index reservation precedes encryption and ciphertext persistence precedes network transfer. Interrupted reservations require a fresh plan/key. Saved recipient fingerprints are checked against current registrations on resume and metadata acceptance. |
| File management | Client decrypts filenames locally. Owners can delete completed publications. Failed remote attempts can be cleaned up without deleting a completed publication whose response was lost. |
| Browser compatibility | HPKE imports both public coordinates and private scalar. OPFS-unavailable/private contexts fall back safely instead of crashing. Chromium, Firefox and WebKit pass focused crypto/storage and real-proof cases. |
| Shared limits | PostgreSQL stores atomic namespaced rate windows across instances. Reusing a valid session does not consume the new-session IP budget. Exact proxy-hop trust is configurable. |
| Operations | Non-root Docker image, PostgreSQL compose service, HTTPS proxy configuration, health checks, protected metrics, backups, restore exercise and CI workflow are supplied. |
| Privacy / resilience | Coordinates/proximity expire after 24 hours. Offline state and network errors are explicit. Automated cases exercise quota failure, missing OPFS and abandoned nonce reservations. |
| Accessibility | Keyboard entry/skip link and Axe WCAG A/AA checks cover workspace, room controls and ownership recovery. The audit uses reduced motion to assess stable content rather than sampling an entrance fade. |
| Hand-in artifacts | Updated report and 14-slide presentation PDFs, source generator, evidence JSON, README and deployment runbook replace the obsolete inbox narrative. |

## Verification and reproducibility (original completion snapshot)

The machine-readable final result index is `docs/evidence.json`. Supporting transfer, load, restore and container evidence is under `benchmark-results/`.

Verified results: **62/62 API tests on PGlite, 62/62 on PostgreSQL 17, 11/11 main browser scenarios, 9/9 cross-browser cases, 3/3 production HTTPS cases and a passing actual 250 MiB transfer.** Build/type checks, the container smoke, two-instance budget probe and restore exercise passed.

Commands:

```bash
npm test
TEST_DATABASE_URL=<isolated-postgres> npm test
npm run build
npm run test:e2e
npm run test:compat
npm run test:production
npm run test:large
```

The API test helper creates a unique PostgreSQL schema per suite and removes only that test schema. The persistence test deliberately still exercises PGlite filesystem restart behavior. The two-instance load probe checks shared rate budgets, not production content throughput. The restore probe checks migrated application tables and exact ciphertext bytes using fresh, isolated databases.

The compatibility matrix runs Chromium, Firefox and WebKit engines in a Playwright container; it does not establish acceptance on an actual iPhone or shipping Safari installation. The large-file test publishes actual 250 MiB ciphertext through the API and verifies every saved plaintext byte. Timings are machine/backend dependent. Full independent security assurance is not implied by passing tests.

## External actions still required

1. **Independent ceremony and security review.** The committed default proving assets remain development assets. A locally generated setup cannot become an independent institutional ceremony. Supply separately contributed, reviewed artifacts and provenance for the v2 circuit using the documented import path. Cryptographic verification/checksums do not establish destruction of entropy.
2. **Institutional integration and custody.** The software supplies private issuance and signed revocation tooling. The institution must supply a real issuer key, eligibility roster/identity process and authenticated delivery channel. Institution-wide revocation requires its worker to apply separately scoped revocations for every affected current/future room until credential expiry. A credential file remains a transferable bearer secret.
3. **Live production rollout.** Domain, hosting, production secrets and institutional policy were not supplied. The deployment is prepared and locally tested, not published to an external host. The GitHub workflow is supplied but has not run on a remote CI runner in this session.
4. **Real-device and operational acceptance.** Test the institution's actual phones/Safari versions, assistive technology, network/storage constraints, monitoring thresholds and backup policy. Set RPO/RTO through restore/decryption exercises with real protected backups.

These are external organizational/security dependencies, not software work silently marked complete. They do not require reintroducing participant uploads.

## Upgrade and residual boundaries

- Migration 008 from the existing pivot deletes historical participant submissions. Back up before upgrading an older deployment.
- Migration 010 makes approved legacy v1 credential memberships pending; reissue v2 credentials and prove again. Denied/revoked browsers remain blocked.
- Decryption-key backup, ownership recovery code and server database backups have distinct purposes. Store recovery materials separately and protect their passphrases.
- Changing an organizer key changes the invitation fingerprint. Use a fresh trusted invitation and export a new key backup.
- Browser storage can be evicted. Missing source snapshots must be discarded and reselected; interrupted nonce reservations must never be re-encrypted.
- Revocation, deletion and expiry cannot erase downloaded plaintext/ciphertext or private keys already copied.
- The application origin and browser remain trust boundaries. A malicious origin can steal secrets. Location is a browser claim, not cryptographic physical-presence proof.
- Co-host roles, S3/MinIO, push notifications, global moderation and a universal credential revocation accumulator are separate product extensions. The requested ownership recovery and PostgreSQL-backed deployment paths are implemented.
- Existing and new working-tree changes remain uncommitted for review. No original work was reset or discarded.

## Follow-up: phone location and code presentation guide

Phone reports above 1 km now reach the explicit `GEO_INACCURATE` policy error instead of failing with a raw schema-size message. The browser waits for an accurate fresh reading for up to 20 seconds and preserves its coordinates, accuracy and timestamp as one measurement. Watchers stop on success, denial or timeout. Student admission still requires accuracy within 75 m. The owner area-center picker uses a separate 1 km acquisition target.

Validation: 15 focused location/geofence tests, a browser regression that improves a 2.5 km fix to 10 m, and the full typecheck/production frontend build passed. These are follow-up checks beyond the previous complete-suite snapshot. `docs/CODE_GUIDE.md` now inventories all custom source files, configuration, tests, generated artifacts and dependency responsibilities for the presentation.

## Follow-up: automatic access for every admitted member — 2 November 2026

Encryption initializes automatically. Files carry an organizer envelope and a shared room envelope. Trusted invitations hold the private receiving key in their URL fragment; no private key is sent to the API. All admitted members can read earlier files with the organizer offline. Existing files receive shared envelopes automatically when the organizer opens the active room. Fingerprints, backups and organizer key replacement are collapsed under optional security/recovery controls.

Admission, credential, location, revocation and expiry checks remain mandatory. The shared key deliberately gives equal file access: anyone with the invitation secret and separately obtained ciphertext can decrypt it. Revocation cannot erase retained copies; organizer key replacement preserves student access and does not rotate the room secret. Use a new room after a room-secret compromise.

The report/presentation PDFs retain the original completion snapshot; README and CODE_GUIDE describe this follow-up behavior.

Follow-up validation: 68/68 API tests passed on PGlite and PostgreSQL 17. All 12 main browser scenarios passed across the combined run and corrected targeted reruns; sharing/recovery passed again after the P-256 derivation compatibility fix. Four production HTTPS scenarios and the final build passed. All 12 cross-browser cases passed across Chromium, Firefox and WebKit, including late arrival downloading while the organizer browser is closed, deterministic key derivation and encrypted recovery. Actual phone acceptance remains separate.

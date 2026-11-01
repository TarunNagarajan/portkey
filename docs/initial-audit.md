# Portkey implementation audit — 1 November 2026

Scope: current working tree, including the existing room-distribution and ZKP changes. Existing uncommitted work was preserved. This is a code review with automated verification, not an independent cryptographic audit.

## Fixed

| Gap | Change | Evidence |
| --- | --- | --- |
| Geofence applied to the room page but could be bypassed through direct file/key calls | Shared participant authorization checks location freshness/inside status with the database clock on room entry, key registration/retrieval, file listing and every chunk read | Integration regression exercises stale, outside, refreshed and revoked states against each route |
| A gate added after a pending request could be bypassed by manual approval | API refuses unproved admission; organizer approval button explains/disables it | Credential regression attempts the bypass |
| Pending requests could not upgrade to proof admission | Proof submission upgrades the original pending membership transactionally, preserving its ID/label, recording verification/nullifier and activity; join UI exposes the proof form | Real proof regression plus browser regression |
| Revoking all members unlocked admission-rule changes | Approved and revoked memberships freeze area/credential policy; UI also treats revoked members as previous admissions | Credential regression revokes then attempts gate replacement/removal |
| Participant recovery compared its backup with the organizer's fingerprint | Restore uses the registered participant fingerprint | Browser flow exports/deletes/restores a participant key and then decrypts an existing shared file |
| The 120-request general budget prevented 250-chunk file transfers | File GET/PUT chunks use a separate bounded 600/minute/session budget | Real limiter regression sends all 250 chunk writes |
| Fresh cookies reset rate-limit identity | Session creation also has a 30/minute/IP cap | Regression creates fresh sessions and verifies the next request is limited |
| Failed browser uploads accumulated pending slots for 24 hours | Publication supports cancellation; failures/cancellation attempt deletion of the incomplete upload; stale cleanup remains the fallback | Browser regression interrupts metadata storage and checks successful DELETE |
| Upload progress mixed encoded descriptor length with transferred chunk bytes | Progress uses total encrypted chunk bytes | Type/build checks and browser publication workflow |
| Initial file-list failures were silently suppressed | Errors surface through the existing alert | Code review and build |
| Opening a draft could leave file state stale | File/key state reloads when lifecycle changes | Browser create/open/encryption flow |
| Production silently trusted the public demo issuer | Production requires explicit issuer configuration or `ALLOW_DEMO_CREDENTIALS=true`; quick-share intentionally opts into demo mode | Production configuration regression |
| Deployment address was hardcoded | Configurable `HOST`, defaulting to loopback | Type/build checks |
| README described removed inbox routes, retention policies and resumable uploads | Rewritten against current routes, crypto behavior, migration consequences and limits | Route/source comparison |

Added API regressions also verify expiry cleanup/cascades/idempotency, stale-upload byte reclamation, immutable chunk retries, invalid manifests, file-count and room-byte quotas. Quota tests seed accounting records rather than allocating gigabytes of ciphertext.

## Validation

- `npm test`: **56/56 passed** against PGlite, including real Groth16 proofs.
- `npm run build`: passed, including TypeScript checking. Dependency annotation/browser-externalization warnings remain; browser crypto transfer tests pass.
- Browser evidence: the full original suite passed **7/7**; the updated encrypted-sharing scenario (including failed-upload cleanup and participant key recovery) passed in a targeted run; the new pending-admission browser scenario passed separately. All **8 distinct browser scenarios** passed across these runs. The new gate test initially had an incorrect button selector, corrected before the successful rerun.
- `git diff --check`: clean. `node --check scripts/share.mjs`: passed.
- A 250-chunk request sequence is verified, **not** a full 250 MiB performance/memory benchmark.
- No external PostgreSQL deployment, mobile hardware, multi-instance load test or production ceremony validation was performed.

## Remaining before institutional/production use

1. **Replace the demo trust roots and review the cryptography.** The development issuer private key is public, and Groth16 artifacts use a local development setup. Use institution-controlled issuance and a reviewed multi-party setup; publish provenance/checksums and deploy prover/verifier artifacts together. Explicit issuer configuration alone does not solve setup trust.
2. **Bind proofs to a server-issued session challenge.** Current public signals bind room and eligibility but not the requesting browser. A copied/intercepted valid proof can race the holder for the room's nullifier seat. Fixing this requires a circuit/protocol version, fresh proving artifacts and replay/front-running regressions; ordinary HTTPS does not provide cryptographic verifier separation. Credential files are also transferable bearer secrets.
3. **Credential lifecycle.** Implement institutional issuance/delivery, credential expiration and revocation, issuer rotation procedures and an appropriate holder-recovery policy. Never ship a real issuer secret in the repository or browser bundle.
4. **Key distribution and recovery.** Later arrivals cannot decrypt earlier publications. Add organizer-authorized envelopes for already-published file keys or a reviewed group key-management scheme. Add deliberate key rotation/device migration and ownership recovery/co-hosting. Already downloaded content cannot be revoked.
5. **Production operations.** Add shared rate-limit storage for multiple instances, suitable reverse-proxy/client-IP configuration, database/object-store quotas and monitoring, backups plus restore exercises, cleanup backlog metrics and graceful failure handling. Validate the PostgreSQL driver in CI and exercise concurrent transactions against an actual PostgreSQL server. Ciphertext currently lives in database BYTEA columns.
6. **Geofence trust.** Coordinates are browser claims and can be spoofed. Present this as a location convenience/check, not a ZKP or secure physical-presence guarantee. Define location retention/minimization requirements before real student use.

## Remaining for a complete course hand-in

1. **Confirm upload direction against the rubric.** This version is organizer-to-participant distribution. Student-to-organizer submissions are absent; restoring them is a separate feature, not a bug fix. Migration 008 deletes historical submission data, so an old deployment needs an explicit backup/migration decision.
2. **Refresh the report/presentation PDFs.** `../docs` still describes the older submission-inbox design. Update the architecture, migration/data model, ZKP circuit/public signals, feature matrix, current screenshots and test evidence. README and this audit describe the current code.
3. **Large-file and browser compatibility evidence.** Benchmark actual 250 MiB encrypt/decrypt/OPFS transfers, cancellation at every stage, quota exhaustion, low storage, permission denial and browser eviction. Test Safari/Firefox and real phones; current browser automation uses Chromium.
4. **Durable upload resume and file management.** In-memory upload plans do not survive reloads. Add safe resumability without nonce reuse and owner deletion of completed publications if required. UI lists encrypted publications by receipt/time/size rather than decrypting filenames for a richer library.
5. **Accessibility and deployment smoke checks.** Keyboard/screen-reader review, production CSP/HTTPS smoke coverage, offline/API outage handling and a reproducible deployment/CI pipeline remain. Bundler warnings and SnarkJS test worker/listener warnings warrant dependency maintenance.
6. **Review and commit the working tree.** The repository already contained a substantial uncommitted product pivot. Review all modified/untracked files, large ZK artifacts and deleted inbox code; no commit, reset or branch change was performed during this audit.

Optional enhancements, rather than completion blockers: push updates instead of five-second polling, audit export, room moderation/admin tools, S3/MinIO storage and automated visual regression coverage.

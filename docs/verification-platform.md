# Verification platform

Portkey can verify issuer-published eligibility contracts for applications that use separate backends. The platform supports two proof adapters: fixed depth-10 Semaphore membership in any one to four credential groups, and versioned organizer-published Groth16 BN254 verification keys with a fixed challenge/result/nullifier signal layout. For custom Groth16, the issuer chooses the circuit and eligibility rule; Portkey verifies a participant-imported proof against the exact pinned key. Portkey does not run uploaded circuits or witnesses, inspect arbitrary documents, or verify an issuer's real-world identity. Issuer labels and custom rules are self-described.

A relying application explicitly trusts an exact immutable contract version. It can trust a contract published by a different owner. Domain verification proves control of the registered application origin; it does not establish that the issuer or application is legitimate. The proof verifies enrollment in the selected Portkey groups, not the source or accuracy of records used to enroll people.

## Local two-application demo

Run `npm run platform:demo`. The command builds the production client bundle and starts Portkey at `http://localhost:5300`, Northstar Learning at `http://northstar.localhost:5301`, and Fieldnote Community at `http://fieldnote.localhost:5302`. Demo data is isolated in `.data/platform-demo`; it does not read `.env`, connect to `DATABASE_URL`, or alter the normal application database. Stop the process with Ctrl+C.

Open either application, choose **Get the issuer’s demo enrollment link**, and save that one-use credential in Portkey. Return to the app and choose **Continue with Portkey**. On Portkey, inspect the requesting origin, self-described issuer, accepted group, digest, callback and expiry before choosing **Prove membership and continue**. Choose **Return to application** to complete the backend exchange. Repeat in the other app; both apps trust the same contract version and the same browser-local credential can satisfy it. This demo exercises the Semaphore adapter only. The demonstration issuer is fictional, its enrollment link is a sample, and one member makes the public Merkle root equal the enrolled commitment; this demo does not claim anonymity.

The two relying applications run separate backends and use distinct host-only cookies. Portkey uses a third origin and cookie. A relying application's browser receives none of the wallet cookie, credential storage, selected group, private key, or application API key; the relying application's backend must hold its own API key. The callback page clears its fragment and posts code and state to its own backend. It reacquires the `SameSite=Strict` session with a same-origin request after cross-site navigation.

## Setup

Create an issuer-owned credential group and publish a contract version from **Applications** in Portkey. Register the relying application's exact HTTPS origin and one to three same-origin callback URLs. Host the issued `{ "appId": "…", "challenge": "…" }` JSON at the provided `/.well-known/portkey-app.json` address, then ask Portkey to verify it. Verification lasts 24 hours. Pin the exact published contract version in the application settings. Guest-owned apps and contracts remain available for the lifetime of their 30-day browser session. Creating an organizer account explicitly adopts that browser's current workspace, including its apps and contracts; account ownership persists across sign-outs and seven-day organizer sign-ins. Signing into an existing account does not adopt another guest workspace.

The application API key is shown once. Store it in a backend secret manager or environment variable, never in a browser bundle, URL, local storage, log, or source control. Rotating the key increments its generation and immediately invalidates the old key and all requests created under the old generation. Disabling an app is permanent. Removing a trust pin permanently invalidates every unexchanged request created under that pin. Re-adding the same contract version creates a new trust revision and does not revive those requests; unchanged pins keep their revision when another pin is added or removed. Retiring a contract version blocks new requests and invalidates unexchanged results.

## Backend SDK integration

Build the dependency-free SDK with `npm run sdk:pack`, then install the resulting tarball in the application's backend. The package exposes the Node client at `portkey` and the browser callback reader at `portkey/browser`. See [SDK distribution](sdk-integration.md) and the [runnable relying-party example](../examples/relying-party/README.md).

```ts
import { createPortkeyClient } from "portkey";

const portkey = createPortkeyClient({
  origin: process.env.PORTKEY_ORIGIN!,
  apiKey: process.env.PORTKEY_APP_KEY!,
  appId: process.env.PORTKEY_APP_ID!,
});
```

The complete example uses PostgreSQL-backed sessions, exact Origin and CSRF checks, bounded pending requests, a pinned contract, and a unique session/flow claim committed before exchanging a code. A local session-property deletion alone is not an atomic claim across concurrent requests or application instances. Use the example's committed database claim when adapting this flow.

The callback page reads `code` and `state` from the URL **fragment**, immediately removes the fragment from browser history, then posts them to its own backend with the application session and CSRF token. Never put the app API key, PKCE verifier, or wallet capability in a callback URL. Do not persist callback codes or state in browser storage. Reject missing, expired, replayed, or session-mismatched callbacks.

`createProofRequest` generates independent 32-byte random state and PKCE verifier values and returns them to the caller; it does not store them for the application. The app backend stores both in the pending server-side session. It sends this strict JSON body to `POST /v1/proof-requests`:

```json
{
  "contractId": "<contract UUID>",
  "contractVersion": 1,
  "redirectUri": "https://app.example/portkey/callback",
  "state": "<43-character base64url value>",
  "codeChallenge": "<43-character S256 value>"
}
```

The API returns `201` with `{ "requestId": "…", "walletUrl": "https://portkey.example/prove/<request UUID>#request=<capability>", "expiresAt": "…" }`. Requests last up to five minutes and are clipped to any remaining guest-owner expiry; account-owned apps and contracts have no guest-session expiry to clip against. The 24-hour app-domain verification, five-minute request, application API-key generation, and trust-revision checks still apply. The API allows at most 1,000 unexpired pending or verified requests and 10,000 retained requests per app. Rate limits also apply. `GET /v1/proof-requests/:requestId` returns safe status and contract metadata only.

After the user proves membership, the app backend calls `POST /v1/proof-requests/:requestId/exchange` with the returned code and original verifier:

```json
{
  "code": "<43-character base64url value>",
  "codeVerifier": "<43-character base64url value>"
}
```

The endpoint consumes the short-lived code once and returns `{ "receipt": "<compact JWS>", "claims": { … } }`. `client.exchange(requestId, code, codeVerifier, expectation)` validates the PKCE binding, fetches JWKS only from the configured Portkey origin, and verifies the Ed25519 signature plus exact issuer, app audience, request, contract version, and digest. The SDK rejects extra or missing claims, unsupported algorithms, malformed keys, expired receipts, and oversized or slow responses. The claim set contains the Portkey issuer, application audience, random receipt ID, request and contract metadata, `result: true`, and issue/expiry times. It has no stable user identifier, credential ID, commitment, nullifier, name, or raw state. Receipts expire within five minutes. A signed receipt is a service assertion, not a trustless statement about Portkey's honesty.

The wallet routes are session, origin, and CSRF protected under `/api/platform/wallet/proof-requests/:requestId`. A capability is placed in the wallet URL fragment and stored server-side only as a digest. A normal GET or preview does not consent or create a proof. For Semaphore, the browser creates a real membership proof locally. For custom Groth16, the participant generates a proof locally using the issuer's circuit and proving key, imports only its proof and public signals, reviews the declared disclosures, and explicitly approves them. Portkey verifies custom proofs against the pinned verifier key in a bounded isolated process; it never runs the custom circuit or witness. See the [proof adapter guide](proof-adapters.md) for the fixed public-signal contract and trust limits.

## Organizer accounts and ownership

Organizer accounts use discoverable, user-verified passkeys. Creating an account explicitly adopts the current unclaimed browser workspace; signing into an existing account never merges unrelated guest resources. Guest workspaces expire with their 30-day browser session, while adopted ownership persists across seven-day organizer sign-ins. Existing room, group, contract, application, invitation, trust, signing-key and recipient-key identifiers remain attached to the original stable ownership anchor.

Existing passkeys do not work at a changed hostname. Retain the database and recovery key, then use **Recover an account** at the new configured HTTPS origin to register a replacement passkey. Browser-local inbox keys still require the separate encrypted backup.

Recovery requires the recovery key and a replacement passkey. Recovery replaces all old passkeys and revokes every organizer sign-in session. It does not restore browser-local inbox decryption keys or attendee proof credentials; encrypted key backup remains separate.

## Public contract and keys

Each immutable public manifest is available from `GET /v1/contracts/:contractId/versions/:version` and has a shareable HTML page at `/contracts/:contractId/versions/:version`. The manifest includes contract and version IDs, name, self-described issuer label, eligibility statement, adapter-specific metadata, immutable digest, publication time, availability, and Portkey origin. Semaphore metadata includes accepted group names and proof depth. Custom Groth16 metadata includes the verifier-key fingerprint and declared public-signal names. Availability can change when the owner session expires or the version is retired; the published rule and digest do not change.

`GET /v1/.well-known/jwks.json` publishes public Ed25519 signing keys only. The current private signing key is stored in the platform database; restrict database access and protect database backups. Operators can rotate receipt signing keys with the procedure in [signing key rotation](signing-key-rotation.md). Rotation retains the previous public key briefly for verification of recently issued receipts, then removes it from JWKS. App-key rotation and contract version retirement do not retract receipts already issued; app data and downloaded receipts cannot be remotely erased.

## Privacy and deployment limits

Portkey sees wallet sessions, network addresses, and request timing. Proofs hide the credential secret and selected group from the relying app, but this service does not claim anonymity or unlinkability from Portkey. A malicious script served by the Portkey origin can access that origin's browser storage. A relying app learns that the eligibility rule passed and the contract metadata needed to interpret the result.

Production application origins must use HTTPS on port 443. Domain verification resolves every DNS answer, rejects private or special-use addresses, pins the approved address for a dedicated non-pooled fetch while retaining the hostname for TLS and `Host`, rejects redirects, and bounds DNS, response size, time, and concurrency. Local HTTP and the `.localhost` resolver shortcut are enabled only by the explicit non-production server configuration used by the demo.

The Semaphore adapter covers membership in the selected credential groups. The custom Groth16 adapter supports only the bounded verifier-key format and fixed signal layout documented in the [proof adapter guide](proof-adapters.md); it does not make issuer-selected circuits trustworthy. Portkey does not verify arbitrary student documents, run uploaded circuits, implement OAuth, OpenID Connect, or OpenID4VP, or accept every credential wallet. A proof establishes the rule encoded by its issuer's circuit; it does not prove the issuer's identity or truthfulness.

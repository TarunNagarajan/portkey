# Verification platform

Portkey can verify membership in issuer-managed credential groups for applications that use separate backends. The first supported rule is membership in **any one to four groups**. Portkey proves membership with the existing depth-10 Semaphore circuit. It does not inspect arbitrary documents, run application-supplied circuits, or verify an issuer's real-world identity. Issuer labels are self-described.

A relying application explicitly trusts an exact immutable contract version. It can trust a contract published by a different owner. Domain verification proves control of the registered application origin; it does not establish that the issuer or application is legitimate. The proof verifies enrollment in the selected Portkey groups, not the source or accuracy of records used to enroll people.

## Local two-application demo

Run `npm run platform:demo`. The command builds the production client bundle and starts Portkey at `http://127.0.0.1:5300`, Northstar Learning at `http://northstar.localhost:5301`, and Fieldnote Community at `http://fieldnote.localhost:5302`. Demo data is isolated in `.data/platform-demo`; it does not read `.env`, connect to `DATABASE_URL`, or alter the normal application database. Stop the process with Ctrl+C.

Open either application, choose **Get the issuer’s demo enrollment link**, and save that one-use credential in Portkey. Return to the app and choose **Continue with Portkey**. On Portkey, inspect the requesting origin, self-described issuer, accepted group, digest, callback and expiry before choosing **Prove membership and continue**. Choose **Return to application** to complete the backend exchange. Repeat in the other app; both apps trust the same contract version and the same browser-local credential can satisfy it. The demonstration issuer is fictional, its enrollment link is a sample, and one member makes the public Merkle root equal the enrolled commitment; this demo does not claim anonymity.

The two relying applications run separate backends and use distinct host-only cookies. Portkey uses a third origin and cookie. A relying application's browser receives none of the wallet cookie, credential storage, selected group, private key, or application API key; the relying application's backend must hold its own API key. The callback page clears its fragment and posts code and state to its own backend. It reacquires the `SameSite=Strict` session with a same-origin request after cross-site navigation.

## Setup

Create an issuer-owned credential group and publish a contract version from **Applications** in Portkey. Register the relying application's exact HTTPS origin and one to three same-origin callback URLs. Host the issued `{ "appId": "…", "challenge": "…" }` JSON at the provided `/.well-known/portkey-app.json` address, then ask Portkey to verify it. Verification lasts 24 hours. Pin the exact published contract version in the application settings. Guest-owned apps and contracts remain available for the lifetime of their 30-day browser session. Creating an organizer account explicitly adopts that browser's current workspace, including its apps and contracts; account ownership persists across sign-outs and seven-day organizer sign-ins. Signing into an existing account does not adopt another guest workspace.

The application API key is shown once. Store it in a backend secret manager or environment variable, never in a browser bundle, URL, local storage, log, or source control. Rotating the key increments its generation and immediately invalidates the old key and all requests created under the old generation. Disabling an app is permanent. Removing a trust pin permanently invalidates every unexchanged request created under that pin. Re-adding the same contract version creates a new trust revision and does not revive those requests; unchanged pins keep their revision when another pin is added or removed. Retiring a contract version blocks new requests and invalidates unexchanged results.

## Backend SDK integration

The Node SDK is in `sdk/index.ts`. It uses `fetch`, Node's cryptography APIs, and the built-in `crypto` module. Construct it only in a server process with the configured Portkey origin, once-shown app key, and app UUID:

```ts
import { timingSafeEqual } from "node:crypto";
import { createPortkeyClient } from "./sdk/index.js";

const portkey = createPortkeyClient({
  origin: process.env.PORTKEY_ORIGIN!,
  apiKey: process.env.PORTKEY_APP_KEY!,
  appId: process.env.PORTKEY_APP_ID!,
});

// These handlers assume the application already has a server-side session,
// CSRF middleware, a registered callback URL, and an explicit contract pin.
app.post(
  "/auth/portkey/start",
  requireAppSession,
  requireCsrf,
  async (req, res) => {
    const contractId = process.env.PORTKEY_CONTRACT_ID!;
    const contractVersion = Number(process.env.PORTKEY_CONTRACT_VERSION);
    const flow = await portkey.createProofRequest({
      contractId,
      contractVersion,
      redirectUri: "https://app.example/portkey/callback",
    });

    // Store these values in this server-side app session, never in browser storage.
    req.session.portkeyPending = {
      requestId: flow.requestId,
      state: flow.state,
      codeVerifier: flow.codeVerifier,
      expiresAt: flow.expiresAt,
      contractId,
      contractVersion,
    };
    res.redirect(303, flow.walletUrl);
  },
);

app.post(
  "/portkey/callback",
  requireAppSession,
  requireCsrf,
  async (req, res) => {
    const pending = req.session.portkeyPending;
    const { code, state } = req.body as { code?: unknown; state?: unknown };
    if (!pending || typeof code !== "string" || typeof state !== "string") {
      return res.status(400).send("Start a new verification request.");
    }
    const expectedState = Buffer.from(pending.state);
    const returnedState = Buffer.from(state);
    if (
      expectedState.length !== returnedState.length ||
      !timingSafeEqual(expectedState, returnedState)
    ) {
      return res
        .status(403)
        .send("This result belongs to a different application session.");
    }

    // Claim the pending callback atomically in the app's session store before
    // awaiting the network, so a concurrent replay cannot exchange the same code.
    delete req.session.portkeyPending;
    const result = await portkey.exchange(
      pending.requestId,
      code,
      pending.codeVerifier,
      {
        contractId: pending.contractId,
        contractVersion: pending.contractVersion,
        contractDigest: process.env.PORTKEY_CONTRACT_DIGEST!,
      },
    );
    req.session.portkeyReceipt = result.claims;
    res.redirect(303, "/benefit");
  },
);
```

Adapt the session save/claim to the application's session store; the delete must be committed before network exchange. The callback page should read `code` and `state` from the URL **fragment**, immediately remove the fragment from browser history, then POST those values to the app backend with the app's normal session and CSRF protections. Never put the app API key, PKCE verifier, or wallet capability in a URL. The short-lived code and opaque state exist in the callback fragment only; do not persist them in browser storage. Reject a missing, expired, replayed, or session-mismatched callback.

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

The wallet routes are session, origin, and CSRF protected under `/api/platform/wallet/proof-requests/:requestId`. A capability is placed in the wallet URL fragment and stored server-side only as a digest. A normal GET or preview does not consent or create a proof. The browser creates a real Semaphore proof locally, and the server verifies it through the same bounded proof-verification gate used by Portkey rooms.

## Organizer accounts and ownership

Organizer accounts use discoverable, user-verified passkeys. Creating an account explicitly adopts the current unclaimed browser workspace; signing into an existing account never merges unrelated guest resources. Guest workspaces expire with their 30-day browser session, while adopted ownership persists across seven-day organizer sign-ins. Existing room, group, contract, application, invitation, trust, signing-key and recipient-key identifiers remain attached to the original stable ownership anchor.

Passkeys are tied to the configured site hostname. If the hostname changes, enroll a new passkey while signed in when possible. If the database and recovery key are retained, recovery at the new configured origin can also replace the old passkeys with a new one. Recovery does not restore browser-local inbox decryption keys or attendee credentials; encrypted key backup remains separate.

Recovery requires the one-time recovery key and a replacement passkey. Recovery replaces all old passkeys and revokes every organizer sign-in session. It does not restore browser-local inbox decryption keys or attendee proof credentials; encrypted key backup remains separate. Passkeys belong to the configured Portkey hostname, so a changed tunnel or deployment domain requires enrolling a new passkey while account access is available.

## Public contract and keys

Each immutable public manifest is available from `GET /v1/contracts/:contractId/versions/:version` and has a shareable HTML page at `/contracts/:contractId/versions/:version`. The manifest includes contract and version IDs, name, self-described issuer label, eligibility statement, accepted group names, adapter, proof depth, immutable digest, publication time, availability, and Portkey origin. Availability can change when the owner session expires or the version is retired; the published rule and digest do not change.

`GET /v1/.well-known/jwks.json` publishes public Ed25519 signing keys only. The signing key is generated once and stored in the platform database. Back up and restrict database access appropriately. Signing-key rotation is not currently exposed. App-key rotation and contract version retirement do not retract receipts already issued; app data and downloaded receipts cannot be remotely erased.

## Privacy and deployment limits

Portkey sees wallet sessions, network addresses, and request timing. Proofs hide the credential secret and selected group from the relying app, but this service does not claim anonymity or unlinkability from Portkey. A malicious script served by the Portkey origin can access that origin's browser storage. A relying app learns that the eligibility rule passed and the contract metadata needed to interpret the result.

Production application origins must use HTTPS on port 443. Domain verification resolves every DNS answer, rejects private or special-use addresses, pins the approved address for a dedicated non-pooled fetch while retaining the hostname for TLS and `Host`, rejects redirects, and bounds DNS, response size, time, and concurrency. Local HTTP and the `.localhost` resolver shortcut are enabled only by the explicit non-production server configuration used by the demo.

This adapter covers the existing Semaphore membership groups only. Portkey does not verify arbitrary student documents, arbitrary circuits, OAuth, OpenID Connect, OpenID4VP, or all credential wallets. The math proves the rule encoded by an issuer; it does not prove the issuer's identity or truthfulness.

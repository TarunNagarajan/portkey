# Standalone relying party

This small Express application uses Portkey's existing Node SDK to create a proof request and verify a signed receipt. It keeps the API key, PKCE verifier, state, request ID, and contract pin on the server. PostgreSQL stores bounded sessions and a unique callback-claim row prevents replay across concurrent requests.

## Run it

Use Node 22.12 or newer and PostgreSQL. Create a relying-party database, publish a contract, and register your exact `APP_ORIGIN` and `https://your-app.example/portkey/callback` callback URL in Portkey. Configure the app ID, app key, and contract ID/version/digest in `.env`; fetch the app's domain challenge from Portkey and set `PORTKEY_DOMAIN_CHALLENGE`. Start the example, then verify the domain in Portkey. The app serves the required `/.well-known/portkey-app.json` response. The app key is used only by the backend process.

First, from the repository root, create the local SDK tarball with `npm run sdk:pack`. Then from this directory copy `.env.example` to `.env`, fill in the values, generate `SESSION_SECRET` from at least 32 cryptographically random bytes, and install/start:

```sh
npm ci
npm start
```

For local development, use an exact loopback HTTP origin (`http://localhost` or `http://127.0.0.1`) only if the Portkey deployment explicitly permits local HTTP, and configure the same callback URL there. In production, terminate TLS at a trusted reverse proxy, set `APP_ORIGIN` to the HTTPS origin, and set `TRUST_PROXY_HOPS` to the actual number of trusted proxy hops. Do not expose this sample's local listener directly to the internet.

Open the app origin, start a verification, complete the Portkey wallet flow, and return to the callback. The callback helper strips the fragment before posting code and state to the backend. The backend checks Origin and CSRF, compares the session-bound state, inserts a unique session/flow claim, commits it and removes pending session data before exchanging the code. A failed exchange requires a new request.

The SDK tarball is a small package with no runtime dependencies; the root application remains private and retains its own application dependencies. The example uses PostgreSQL for shared server sessions; sessions expire after ten minutes, and callback claims are pruned after one day. `DATABASE_SCHEMA` selects the PostgreSQL schema for its sessions and callback claims; use a dedicated schema or database when sharing PostgreSQL with another application. All responses disable caching; the callback helper is served from the installed package by the backend and has no bare browser package import. Run behind HTTPS in production, rotate the session secret if exposed, and configure database backups/retention for your deployment. The API key must never be placed in browser JavaScript, HTML, a URL, or client storage. This is an integration example; adapt logging, error pages, database access, and deployment controls to your application.

# Operations

## Runtime boundaries

Portkey currently uses process-local rate limiters. Run one application instance per deployment. Multiple application replicas can each admit their own rate-limit allowance until a shared rate-limit store is configured. The database pool does not make the limiter state shared.

Serve the application over HTTPS in production. Configure the canonical public origin and relying-party origins to match the public HTTPS addresses exactly. Browser passkeys, location permission, and secure wallet storage depend on a trustworthy browser origin. Keep application API keys on the server; never place them in browser environment variables or public assets.

The default embedded PGlite database is for local development. Production should set `DATABASE_URL` to PostgreSQL and run `npm run db:migrate` as part of deployment before serving traffic. Back up the database before deploying migrations and retain backups long enough to test restoration. Migrations are transactional and take a PostgreSQL advisory lock; deploy only one migration process at a time.

## Back up and restore

Create a custom-format PostgreSQL backup. In PowerShell, restore it into a newly created, empty database and verify the expected tables and application data:

```powershell
pg_dump --format=custom --no-owner --no-acl --file=portkey.dump $env:DATABASE_URL
createdb --maintenance-db=$env:DATABASE_URL portkey_restore_check
$env:RESTORE_DATABASE_URL = 'postgres://user:password@localhost:5432/portkey_restore_check'
pg_restore --no-owner --no-acl --dbname=$env:RESTORE_DATABASE_URL portkey.dump
psql $env:RESTORE_DATABASE_URL -c '\dt'
```

Replace the restore URL with credentials and connection details for the empty restore database. Keep the dump encrypted and access-controlled according to the sensitivity of the stored data.

A database backup does not contain the plaintext organizer recovery key; the database stores only its verifier. Keep the recovery key separately in a secure offline location. Private inbox keys require a separate encrypted export and its passphrase. Participant credentials are held in the participant’s browser, so a participant who loses that browser credential must enroll again. Restoring the database alone does not restore these materials.

## PostgreSQL driver validation

The ordinary `npm test` suite uses isolated embedded databases and does not connect to a configured PostgreSQL service. The actual `pg` Pool adapter suite is opt-in and refuses non-loopback hosts or database names that do not clearly identify a test database. It creates a random temporary schema, directs the adapter to that schema, and removes only that schema on completion.

Install and start PostgreSQL yourself, create a dedicated local database named `portkey_test`, and provide its URL only for the test command. For PowerShell:

```powershell
$env:PORTKEY_RUN_POSTGRES_TESTS = '1'
$env:PORTKEY_TEST_DATABASE_URL = 'postgres://localhost:5432/portkey_test'
npm run test:postgres
Remove-Item Env:PORTKEY_RUN_POSTGRES_TESTS
Remove-Item Env:PORTKEY_TEST_DATABASE_URL
```

Use credentials appropriate to your local PostgreSQL installation. Do not point this command at production, staging, or a database containing user data. CI runs the same suite against a disposable PostgreSQL service.

## Deployment checks

Before a release, confirm `DATABASE_URL`, the canonical public origin, HTTPS termination, and browser-facing relying-party origins match the deployment. Verify a backup can be restored, then run the serial unit suite and PostgreSQL adapter suite. Keep logs free of application secrets and credential material. Rate-limit behavior across multiple instances remains unsupported until a shared store is configured.

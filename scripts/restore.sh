#!/usr/bin/env bash
set -euo pipefail
: "${RESTORE_DATABASE_URL:?Set RESTORE_DATABASE_URL to a NEW EMPTY database}"
archive="${1:?Pass an archive path}"
# No --clean or drop commands: fail immediately if objects already exist.
pg_restore --exit-on-error --no-owner --dbname="$RESTORE_DATABASE_URL" "$archive"
echo 'Restore completed. Run application migrations and a file decryption smoke test.'

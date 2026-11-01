#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?Set DATABASE_URL}"
output="${1:?Pass a backup destination path}"
umask 077
if [ -e "$output" ]; then echo 'Refusing to overwrite an existing backup.' >&2; exit 1; fi
pg_dump --format=custom --no-owner --file="$output" "$DATABASE_URL"
pg_restore --list "$output" > /dev/null
echo 'Backup created and archive listing verified. Exercise a restore before relying on it.'

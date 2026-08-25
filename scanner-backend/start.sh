#!/bin/sh
set -e

echo "Starting ClamAV..."

freshclam --stdout || true

clamd &
CLAM_PID=$!

echo "Waiting for ClamAV..."

for i in $(seq 1 60); do
  if clamdscan --ping 2>/dev/null; then
    echo "ClamAV is ready."
    break
  fi
  sleep 1
done

if ! clamdscan --ping 2>/dev/null; then
  echo "ERROR: ClamAV did not start."
  kill "$CLAM_PID" 2>/dev/null || true
  exit 1
fi

echo "Starting SecureFileCrypt scanner API..."
exec node server.js

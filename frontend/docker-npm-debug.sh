#!/bin/bash
set -o pipefail

npm ci --no-audit --no-fund --loglevel verbose || true

echo "--- ls /root/.npm/_logs ---"
ls -la /root/.npm/_logs || true

echo "--- cat debug logs (first 400 lines) ---"
for f in /root/.npm/_logs/*-debug-0.log; do
  echo "--- log: $f ---"
  sed -n '1,400p' "$f" || true
  echo "--- end log ---"
done

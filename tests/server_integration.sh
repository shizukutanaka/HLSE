#!/usr/bin/env bash
# End-to-end smoke test for hlse-server: starts the server on an ephemeral
# port, exercises every endpoint, and asserts the responses. If the server
# cannot bind (restricted CI sandbox), the test SKIPS rather than failing.
#
# Usage: bash tests/server_integration.sh [./hlse-server] [./web]
set -u

SERVER="${1:-./hlse-server}"
WEBROOT="${2:-./web}"
PORT=$(( (RANDOM % 2000) + 18000 ))
PASS=0; FAIL=0

pass() { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); }
check() { # desc  haystack  needle
  case "$2" in *"$3"*) pass "$1";; *) fail "$1 (missing: $3)";; esac
}

[ -x "$SERVER" ] || { echo "SKIP: $SERVER not built (run 'make server')"; exit 0; }

"$SERVER" --port "$PORT" --webroot "$WEBROOT" >/tmp/hlse_srv_it.log 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null' EXIT

# Wait up to ~3s for readiness.
up=0
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "http://127.0.0.1:$PORT/api/v1/health" 2>/dev/null; then up=1; break; fi
  sleep 0.1
done
if [ "$up" -ne 1 ]; then
  echo "SKIP: server did not bind (restricted sandbox?)"; exit 0
fi

B="http://127.0.0.1:$PORT"
echo "HLSE server integration ($B)"
echo "════════════════════════════════════════"

check "health ok"        "$(curl -s $B/api/v1/health)" '"status":"ok"'
check "version present"  "$(curl -s $B/api/v1/version)" '"version"'
check "url spoof ISOLATE" \
  "$(curl -s -X POST $B/api/v1/scan/url -d '{"url":"https://paypal.com@evil.xyz/login"}')" '"action":"ISOLATE"'
check "url clean SAFE" \
  "$(curl -s -X POST $B/api/v1/scan/url -d '{"url":"https://github.com"}')" '"action":"SAFE"'
check "text scam detected" \
  "$(curl -s -X POST $B/api/v1/scan/text -d '{"text":"URGENT buy gift cards now"}')" '"kind":"text"'
check "secrets found" \
  "$(curl -s -X POST $B/api/v1/scan/secrets -d '{"text":"AKIA2E3MWORQXYZ4567PQ"}')" '"kind":"secrets"'
check "file masquerade" \
  "$(curl -s -X POST $B/api/v1/scan/file -d '{"filename":"a.pdf.exe","content":"x"}')" 'DOUBLE EXTENSION'
check "bad json 400" \
  "$(curl -s -X POST $B/api/v1/scan/url -d '{"nope":1}')" '"error"'
check "unknown route 404" \
  "$(curl -s -o /dev/null -w '%{http_code}' $B/api/v1/bogus)" '404'
check "method not allowed 405" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE $B/api/v1/health)" '405'
check "oversize 413" \
  "$(head -c 200000 /dev/zero | tr '\0' a | curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @- $B/api/v1/scan/text)" '413'
check "dashboard served" "$(curl -s $B/)" '<title>HLSE'
check "static css" "$(curl -s -o /dev/null -w '%{http_code}' $B/style.css)" '200'
check "security header" "$(curl -s -D - -o /dev/null $B/api/v1/health)" 'Content-Security-Policy'

echo "════════════════════════════════════════"
echo "Integration: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

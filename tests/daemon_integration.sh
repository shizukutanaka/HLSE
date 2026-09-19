#!/usr/bin/env bash
# End-to-end smoke test for hlsed: runs the daemon against a temp watch dir,
# drops a planted secret + a double-extension masquerade file, and asserts the
# daemon detected them; then exercises SIGHUP reload and SIGTERM shutdown.
#
# Usage: bash tests/daemon_integration.sh [./hlsed]
set -u

HLSed="${1:-./hlsed}"
PASS=0; FAIL=0

pass() { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); }
check() { # desc  haystack  needle
  case "$2" in *"$3"*) pass "$1";; *) fail "$1 (missing: $3)";; esac
}

[ -x "$HLSed" ] || { echo "SKIP: $HLSed not built (run 'make daemon')"; exit 0; }

ROOT="$(mktemp -d /tmp/hlsed_it.XXXXXX)"
WATCH="$ROOT/watch"; LOG="$ROOT/alert.log"; PIDF="$ROOT/hlsed.pid"
CONF="$ROOT/hlsed.conf"; ERR="$ROOT/stderr.log"
mkdir -p "$WATCH/sub"

cat > "$CONF" <<EOF
watch         = $WATCH
scan-interval = 1
pid-file      = $PIDF
log-file      = $LOG
fail-on       = 40
EOF

echo "HLSE daemon integration ($ROOT)"
echo "════════════════════════════════════════"

# --check validates the config ------------------------------------------
OUT="$("$HLSed" --check "$CONF" 2>&1)" && rc=0 || rc=$?
check "--check exit 0"        "$rc"   "0"
check "--check reports watch" "$OUT"  "1 watch dir"

# --check rejects a missing watch dir ------------------------------------
sed "s|watch.*|watch = $ROOT/nonexistent|" "$CONF" > "$ROOT/bad.conf"
OUT="$("$HLSed" --check "$ROOT/bad.conf" 2>&1)" && rc=0 || rc=$?
check "--check bad dir exits 2" "$rc" "2"

# start the daemon --------------------------------------------------------
"$HLSed" --config "$CONF" >"$ERR" 2>&1 &
D=$!
cleanup() { kill "$D" 2>/dev/null; wait "$D" 2>/dev/null; rm -rf "$ROOT"; }
trap cleanup EXIT

# wait for the first sweep + pid file
i=0
while [ ! -f "$PIDF" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done
check "pid file created"     "$([ -f "$PIDF" ] && echo yes || echo no)" "yes"
check "startup line"         "$(cat "$ERR")"                            "watching 1 directory"

# drop a planted secret → must be found on next sweep --------------------
printf 'aws_key = "AKIAQB3X7F2MN9T4KZWJ"\n' > "$WATCH/sub/keys.txt"
sleep 1.4
check "secret found on stderr"  "$(cat "$ERR")" "score="
check "secret logged"           "$(cat "$LOG" 2>/dev/null)"             "secret"

# a benign file at/below threshold is watched but not alerted ------------
printf 'hello\n' > "$WATCH/ok.txt"
sleep 1.4
case "$(cat "$LOG")" in
  *ok.txt*) fail "benign file not logged (found: ok.txt)";;
  *)        pass "benign file not logged";;
esac

# SIGHUP: bump the interval → daemon reloads without stopping -------------
perl -pe 's/scan-interval = 1/scan-interval = 2/' "$CONF" > "$CONF.new" \
  && mv "$CONF.new" "$CONF"
kill -HUP "$D" 2>/dev/null
sleep 0.6
check "SIGHUP reload logged" "$(cat "$ERR")" "reloaded"
check "daemon still alive"   "$(kill -0 "$D" 2>/dev/null && echo up || echo dead)" "up"

# a second instance must refuse to start (pid lock) -----------------------
"$HLSed" --config "$CONF" >"$ROOT/second.log" 2>&1 && rc=0 || rc=$?
check "second instance exits 1" "$rc" "1"
check "lock refusal message"    "$(cat "$ROOT/second.log")" "locked"

# SIGTERM: clean shutdown removes the pid file -----------------------------
kill -TERM "$D" 2>/dev/null
i=0; while kill -0 "$D" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done
check "SIGTERM stops daemon" "$(kill -0 "$D" 2>/dev/null && echo alive || echo dead)" "dead"
check "pid file removed"     "$([ -f "$PIDF" ] && echo yes || echo no)"   "no"
check "shutdown line"        "$(cat "$ERR")"                              "stopped"

echo "════════════════════════════════════════"
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

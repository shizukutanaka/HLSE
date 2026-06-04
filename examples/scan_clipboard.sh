#!/bin/bash
# examples/scan_clipboard.sh
#
# Example: scan clipboard contents for scams using HLSE Core.
# Useful as a cron job or hotkey-bound check.
#
# Linux: requires xclip or wl-paste
# macOS: uses pbpaste

set -eu

if command -v pbpaste >/dev/null 2>&1; then
    CLIP_CMD="pbpaste"
elif command -v wl-paste >/dev/null 2>&1; then
    CLIP_CMD="wl-paste"
elif command -v xclip >/dev/null 2>&1; then
    CLIP_CMD="xclip -o -selection clipboard"
else
    echo "No clipboard tool found (need pbpaste/wl-paste/xclip)" >&2
    exit 2
fi

CONTENT=$($CLIP_CMD)

if [ -z "$CONTENT" ]; then
    echo "Clipboard is empty"
    exit 0
fi

# Detect URL vs text
if echo "$CONTENT" | grep -Eq '^https?://'; then
    RESULT=$(./hlse_core --json "$CONTENT")
else
    RESULT=$(./hlse_core --json text "$CONTENT")
fi

# Parse JSON to get score (simple awk; jq optional)
SCORE=$(echo "$RESULT" | grep -oE '"score":[0-9]+' | head -1 | awk -F: '{print $2}')
ACTION=$(echo "$RESULT" | grep -oE '"action":"[A-Z]+"' | head -1 | awk -F'"' '{print $4}')

echo "$RESULT"

if [ "${SCORE:-0}" -ge 60 ]; then
    # Score is BLOCK or ISOLATE — alert via desktop notification
    if command -v notify-send >/dev/null 2>&1; then
        notify-send -u critical "HLSE: Threat in clipboard ($ACTION)" \
            "Score: $SCORE/100"
    elif command -v osascript >/dev/null 2>&1; then
        osascript -e "display notification \"Score: $SCORE/100\" \
            with title \"HLSE: Threat in clipboard ($ACTION)\""
    fi
    exit 1
fi

exit 0

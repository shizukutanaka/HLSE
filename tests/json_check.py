#!/usr/bin/env python3
"""JSON-structural assertion helper for tests/cli_integration.sh.

Reads one `--json` verdict on stdin and evaluates a Python expression
with the verdict bound to `d`. Exits 0 iff the expression is truthy,
1 otherwise — jcheck() in cli_integration.sh turns that into PASS/FAIL.

This is the structured-verdict counterpart to `| grep -q pattern`:
instead of asking "did the wording appear", it asserts the verdict's
score, action band, signal bits, and reasons[]/classes[] content:

    jcheck "paste: rm -rf / flagged" \
        'd["score"] > 0 and "P9:" in str(d["reasons"])' \
        paste "rm -rf /"

    jcheck "paste: benign cat clean" \
        'd["score"] == 0 and d["reasons"] == []' \
        paste "cat /etc/hostname"

Evaluation environment: `d` plus a small builtin allowlist (no __builtins__
exposure beyond the listed functions — the expressions are trusted test
code, but the bound is deliberately minimal).
"""
import json
import sys

SAFE_GLOBALS = {
    '__builtins__': {},
    'len': len, 'str': str, 'repr': repr, 'int': int,
    'any': any, 'all': all, 'set': set, 'list': list,
    'sorted': sorted, 'sum': sum, 'min': min, 'max': max,
    'bool': bool, 'abs': abs,
}


def main():
    if len(sys.argv) != 2:
        sys.stderr.write('usage: json_check.py \'<expr over d>\'  '
                         '(verdict JSON on stdin)\n')
        return 2
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Not a single verdict — try NDJSON (`scan` emits one verdict
        # per line plus a trailing scan_summary record) and bind `d`
        # to the list of per-line objects instead.
        try:
            data = [json.loads(l) for l in raw.splitlines() if l.strip()]
        except json.JSONDecodeError as e:
            sys.stderr.write('json_check: output is not JSON: %s\n' % e)
            return 1
        if not data:
            sys.stderr.write('json_check: no JSON records on stdin\n')
            return 1
    try:
        # `d` is the parsed verdict (dict) or list of per-line records
        # (NDJSON); `L` is the same records normalized to a list even when
        # the output was a single object; `s` is the raw output text —
        # grep-style substring asserts over the JSON serialization use `s`.
        ok = bool(eval(sys.argv[1], SAFE_GLOBALS,
                       {'d': data, 's': raw,
                        'L': data if isinstance(data, list) else [data]}))
    except Exception as e:  # bad expression = failed assertion, not a crash
        sys.stderr.write('json_check: %s: %s\n' %
                         (type(e).__name__, e))
        return 1
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

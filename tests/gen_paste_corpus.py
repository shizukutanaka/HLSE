#!/usr/bin/env python3
"""Generate hlse_paste_corpus_gen.h — a paste-detector benchmark corpus
derived from the cli_integration.sh jcheck stanzas.

Rationale (audit item B3): --benchmark's hand-written paste corpus has
9 entries while the paste detector carries ~22k needles. The suite's
jcheck stanzas already encode the intended verdict for thousands of
inputs — harvest a deterministic sample of them and pin each to the
measured score, so F1/FP actually covers the paste surface and a
needle regression drops recall instead of hiding.

Classification (from the jcheck name + expression):
  flagged  name or expr asserts a positive score / alert band
           (e.g. 'd["score"] > 0', 'ALERT'/'BLOCK'/'ISOLATE' band,
           "flagged"/"detect" in the check name)
  clean    name or expr asserts a zero/low verdict
           ("FP guard", "clean", "stays low", 'd["score"] == 0',
           '"SAFE"' / '"ok" in' assertions)
  anything else (structural asserts like '"(also:" in str(d)') is
  skipped — its class cannot be derived without judging intent.

A "flagged" token that measures score 0 is dropped, not pinned: the
disagreement means the name-based classification lied, and pinning
floor 0 would silently assert the suite's own check to be wrong
(the suite would FAIL on it first — here we just don't trust it).

Sampling: tokens are deduplicated, sorted, and taken at an even stride
so the corpus is stable across regenerations. Regenerate with:

    make gen-corpus        # = python3 tests/gen_paste_corpus.py ...

Usage:
    gen_paste_corpus.py <hlse_core-binary> <cli_integration.sh> <out.h>
"""
import json
import re
import subprocess
import sys

# Cap each side of the corpus so --benchmark stays quick (~2-4s extra).
MAX_MAL = 400
MAX_LEGIT = 150

JCHECK_RE = re.compile(
    r"""jcheck\s+"([^"]+)"\s+'((?:[^'\\]|\\.)*)'\s+paste\s+"""
    r"""(?:'((?:[^'\\]|\\.)*)'|"([^"\\]*)")""")
FOR_RE = re.compile(
    r"""for\s+c\s+in\s+(.*?)\s*;\s*do\s+jcheck\s+"([^"]+)"\s+"""
    r"'((?:[^'\\]|\\.)*)'\s+paste\s+\"\$c\"")
def list_literals(seg):
    """Tokenize a `for c in ...` literal list: single- and
    double-quoted items, allowing the other quote inside."""
    toks, i, n = [], 0, len(seg)
    while i < n:
        if seg[i] in "'\"":
            q, j = seg[i], i + 1
            while j < n and seg[j] != q:
                j += 1
            toks.append(seg[i + 1:j])
            i = j + 1
        else:
            i += 1
    return toks

FLAG_NAME = re.compile(
    r"flagged|detect|catches|fires|alert|block|isolate", re.I)
FLAG_EXPR = re.compile(
    r'd\["score"\]\s*>\s*0|d\["score"\]\s*>=|"ALERT"|"BLOCK"|"ISOLATE"'
    r'|"alert" in|"block" in|"isolate" in')
CLEAN_NAME = re.compile(
    r"fp guard|clean|benign|legit|stays low|not flagged|safe", re.I)
CLEAN_EXPR = re.compile(
    r'd\["score"\]\s*==\s*0|"SAFE"|"ok" in|"log" in'
    r'|d\["score"\]\s*<\s*\d|d\["score"\]\s*<=\s*\d')


def classify(name, expr):
    """'mal' / 'legit' / None. Name wins; expr is the tiebreak."""
    if CLEAN_NAME.search(name) or CLEAN_EXPR.search(expr):
        return "legit"
    if FLAG_NAME.search(name) or FLAG_EXPR.search(expr):
        return "mal"
    return None


def c_escape(s):
    return (s.replace("\\", "\\\\")
             .replace('"', '\\"')
             .replace("\t", "\\t")
             .replace("\n", "\\n"))


def score(binary, token):
    """Measured paste score via --json, or None if unscorable."""
    try:
        out = subprocess.run(
            [binary, "--json", "paste", token],
            capture_output=True, text=True, timeout=20).stdout
        d = json.loads(out.splitlines()[0])
        return d.get("score")
    except (ValueError, IndexError, KeyError, subprocess.TimeoutExpired):
        return None


def logical_lines(path):
    """Yield physical lines with trailing-backslash continuations
    joined, so multi-line `for c in 'a' 'b' \\ ... ; do` loops
    match as one unit."""
    buf = ""
    for raw in open(path, encoding="utf-8", errors="replace"):
        buf += raw
        if buf.endswith("\\\n"):
            continue
        yield buf
        buf = ""
    if buf:
        yield buf


def collect(path):
    """[(cls, token), ...] from jcheck stanzas and for-loops."""
    pairs = []
    for line in logical_lines(path):
        # Try the for-loop shape first: a for-line also matches JCHECK_RE
        # with literal token "$c", which the $ filter would drop silently.
        m = FOR_RE.search(line)
        if m:
            cls = classify(m.group(2), m.group(3))
            if cls:
                for tok in list_literals(m.group(1)):
                    if "$" not in tok:
                        pairs.append((cls, tok))
            continue
        m = JCHECK_RE.search(line)
        if m:
            cls = classify(m.group(1), m.group(2))
            tok = m.group(3) if m.group(3) is not None else m.group(4)
            if cls and "$" not in tok:
                pairs.append((cls, tok))
    return pairs


def sample(items, cap):
    """Deterministic even-stride subsample of a sorted list."""
    items = sorted(items)
    if len(items) <= cap:
        return items
    step = len(items) / cap
    return [items[int(i * step)] for i in range(cap)]


def emit(mal, legit, path):
    """mal/legit: [(token, score), ...] with floors/maxes pinned."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("/* GENERATED by tests/gen_paste_corpus.py — do not edit.\n"
                " * Regenerate: make gen-corpus. Derived from the paste\n"
                " * jcheck stanzas in tests/cli_integration.sh; floors\n"
                " * and maxes pinned to the score measured at regen\n"
                " * time (same convention as the handwritten corpus).\n"
                " */\n"
                "static const char *gen_mal_paste[] = {\n")
        for tok, _ in mal:
            f.write('    "%s",\n' % c_escape(tok))
        f.write("    NULL\n};\n"
                "static const int gen_mal_paste_min[] = {\n    ")
        f.write(", ".join(str(s) for _, s in mal))
        f.write("\n};\n"
                "static const char *gen_legit_paste[] = {\n")
        for tok, _ in legit:
            f.write('    "%s",\n' % c_escape(tok))
        f.write("    NULL\n};\n"
                "static const int gen_legit_paste_max[] = {\n    ")
        f.write(", ".join(str(s) for _, s in legit))
        f.write("\n};\n")


def main():
    binary, suite_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
    pairs = collect(suite_path)
    mal_tokens = sorted({t for c, t in pairs if c == "mal"})
    legit_tokens = sorted({t for c, t in pairs if c == "legit"})
    # A token claimed by both classes is ambiguous — drop it.
    both = set(mal_tokens) & set(legit_tokens)
    mal_tokens = [t for t in mal_tokens if t not in both]
    legit_tokens = [t for t in legit_tokens if t not in both]
    mal_s, legit_s = sample(mal_tokens, MAX_MAL), \
        sample(legit_tokens, MAX_LEGIT)

    mal, legit, dropped = [], [], 0
    for tok in mal_s:
        s = score(binary, tok)
        if s and s > 0:
            mal.append((tok, s))
        else:
            dropped += 1
    for tok in legit_s:
        s = score(binary, tok)
        if s is not None:
            legit.append((tok, s))
        else:
            dropped += 1

    emit(mal, legit, out)
    print("gen_paste_corpus: %d flagged + %d clean sampled from "
          "%d mal/%d legit pool (%d dropped, %d ambiguous) -> %s"
          % (len(mal), len(legit), len(mal_tokens), len(legit_tokens),
             dropped, len(both), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Static lint over the ci_contains paste-needle chain in hlse_supply.c.

ci_contains() lowercases the haystack only, so a needle containing an
uppercase letter can never match — dead code. Other checks are advisory
reports on structural debt the else-if chain accumulates:

  FAIL   needle contains [A-Z]          (dead: never fires)
  FAIL   needle is empty                (ci_contains("") always true)
  REPORT needle in >=2 distinct blocks  (earliest else-if wins -> label
                                         misattribution; never fires in
                                         later blocks)
  REPORT duplicate needle inside one block (redundant disjunct)
  REPORT needle covered by a longer needle in the same block
  REPORT duplicate `what = "..."` label across blocks
  REPORT word-char needle len<=4 without a trailing boundary space
          (substring-collision risk; e.g. 'curse' hit '-Recurse')

Exit 0 = no FAILs. Reports are advisory.
"""
import re
import sys
from collections import Counter, defaultdict

NEEDLE_RE = re.compile(r'ci_contains\(text,\s*"((?:[^"\\]|\\.)*)"')
WHAT_RE = re.compile(r'what\s*=\s*"([^"]+)"')
BLOCK_RE = re.compile(r'\}\s*else\s+if\s*\(|\bif\s*\(')


def gate_only(needle):
    """True for flag/gate strings like ' -', ' --update' —
    shared control-flow predicates, not content needles."""
    return needle.startswith(' -')


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: lint_needles.py <hlse_supply.c>")
    src = open(sys.argv[1], encoding='utf-8', errors='replace').read()

    # Split into else-if blocks; first part is preamble before the chain.
    parts = BLOCK_RE.split(src)
    fails = []
    needle_blocks = defaultdict(set)
    block_intra_dups = Counter()
    block_covers = []
    labels = defaultdict(int)
    risk_short = defaultdict(list)
    n_needles = 0

    for bi, part in enumerate(parts[1:], start=1):
        needles = NEEDLE_RE.findall(part)
        n_needles += len(needles)
        label = WHAT_RE.search(part)
        lname = label.group(1) if label else None
        if lname:
            labels[lname] += 1
        seen = Counter()
        for raw in needles:
            n = raw.replace('\\t', '\t').replace('\\\\', '\\')
            if any(c.isupper() for c in n):
                fails.append(
                    "dead needle (uppercase, never fires): %r (block %d)"
                    % (n, bi))
            if n == "":
                fails.append("empty needle (always true): block %d" % bi)
            needle_blocks[n].add(bi)
            seen[n] += 1
            if (not gate_only(n) and not n.startswith(' ') and
                    not n.endswith(' ') and
                    re.fullmatch(r'[a-z0-9_.+\-/]{2,4}', n)):
                risk_short[n].append(bi)
        for n, c in seen.items():
            if c > 1 and not gate_only(n):
                block_intra_dups[n] += c - 1
        uniq = sorted(set(seen))
        for i, a in enumerate(uniq):
            for b in uniq[i + 1:]:
                if len(a) < len(b) and a in b:
                    block_covers.append(
                        "%r covered by %r (block %d)" % (a, b, bi))

    cross = {n: bs for n, bs in needle_blocks.items()
             if len(bs) > 1 and not gate_only(n)}
    dup_labels = {k: v for k, v in labels.items() if v > 1}

    print("needle lint: %s" % sys.argv[1])
    print("  needles: %d   blocks: %d   labels: %d"
          % (n_needles, len(parts) - 1, len(labels)))
    print()
    for f in fails:
        print("FAIL   %s" % f)
    print("REPORT cross-block duplicate needles: %d" % len(cross))
    for n, bs in sorted(cross.items(), key=lambda kv: -len(kv[1]))[:15]:
        print("       %r in %d blocks %s"
              % (n, len(bs), sorted(bs)[:8]))
    print("REPORT intra-block duplicate disjuncts: %d"
          % sum(block_intra_dups.values()))
    for n, c in sorted(block_intra_dups.items(), key=lambda kv: -kv[1])[:10]:
        print("       %r x%d extra" % (n, c))
    print("REPORT needles covered by longer needle in same block: %d"
          % len(block_covers))
    for c in block_covers[:10]:
        print("       %s" % c)
    for k, v in sorted(dup_labels.items()):
        fails.append("duplicate 'what' label %r used by %d blocks"
                     % (k, v))
    print("REPORT short unbound word needles (boundary risk): %d"
          % len(risk_short))
    for n, bs in sorted(risk_short.items())[:15]:
        print("       %r blocks %s" % (n, sorted(set(bs))[:8]))

    print()
    if fails:
        print("lint-needles: %d FAIL" % len(fails))
        return 1
    print("lint-needles: PASS (advisory reports above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

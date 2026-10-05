#!/usr/bin/env python3
"""Remove cover-dead needles from paste else-if blocks.

Inside ONE '||' run at ONE paren depth, a positive needle that is
a proper substring of another positive needle covers it: every
input matching the longer literal already matches the shorter —
the longer ci_contains() can never add a hit (dead code, same
label, same score, eval-time truth unchanged).

  'install' || 'install-tiktok'   -> 'install-tiktok' is dead
  'a' || 'ab' || 'abc'            -> 'ab', 'abc' dead, 'a' stays

Only positive calls cover / get dropped ('!x' is not 'x'), only
'||' runs ('&&' coverage changes semantics), and gate needles
(' -...' flag predicates) are excluded on both sides.

Runs are contiguous same-connector sequences at one paren depth
(lp pushes a fresh run, rp pops, a different connector ends the
run) — same model as dedup_needles.py.

Usage: cover_needles.py <hlse_supply.c>
"""
import re
import sys

BLOCK_RE = re.compile(r'\}\s*else\s+if\s*\(|\bif\s*\(')
TOKEN_RE = re.compile(
    r'(?P<call>!?\s*ci_contains\(text,\s*"(?:[^"\\]|\\.)*"\))'
    r'|(?P<conn>\|\||&&)'
    r'|(?P<lp>\()|(?P<rp>\))')
NEEDLE_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def gate_only(lit):
    """' -...' flag predicates are control-flow, not content."""
    return lit.startswith(' -')


def runs_of(toks):
    """Yield ('conn', [call-token-index, ...]) per contiguous run.
    A run is a maximal sequence of calls at one depth joined by
    one connector type."""
    out = []
    stack = []
    cur = None

    def close():
        nonlocal cur
        if cur is not None:
            out.append(cur)
            cur = None

    for i, t in enumerate(toks):
        if t.kind == 'lp':
            close()
            stack.append(t)
        elif t.kind == 'rp':
            close()
            if stack:
                stack.pop()
        elif t.kind == 'conn':
            if cur is None:
                cur = [t.text, []]
            elif cur[0] is None:
                cur[0] = t.text            # first conn types the run
            elif cur[0] != t.text:
                close()
                cur = [t.text, []]
        else:                               # call
            if cur is None:
                cur = [None, []]
            cur[1].append(i)
    close()
    return out


class Tok(object):
    __slots__ = ('kind', 'text', 'start', 'end', 'lit', 'neg')

    def __init__(self, m):
        self.kind = m.lastgroup
        self.text = m.group(0)
        self.start = m.start()
        self.end = m.end()
        self.lit = None
        self.neg = False
        if self.kind == 'call':
            self.lit = NEEDLE_RE.search(self.text).group(1)
            self.neg = self.text.lstrip().startswith('!')


def tokenize(part):
    return [Tok(m) for m in TOKEN_RE.finditer(part)]


def find_drops(toks):
    """Spans to remove: covered positive call + one neighbouring
    '||'. Returns (drops, removed_lits)."""
    drops = []
    removed = []
    for conn, idxs in runs_of(toks):
        if conn != '||' or len(idxs) < 2:
            continue
        pos = [i for i in idxs
               if not toks[i].neg and not gate_only(toks[i].lit)]
        covered = set()
        for j in pos:
            lj = toks[j].lit
            for i in pos:
                li = toks[i].lit
                if i != j and li != lj and li in lj:
                    covered.add(j)
                    break
        # run element order: call,conn,call,conn,... — drop dead
        # call with the '||' on its left (first element: right)
        elem = []
        for i in idxs:
            elem.append(i)
        for n, i in enumerate(idxs):
            if i not in covered:
                continue
            dead = toks[i]
            if n > 0:
                # preceding token at same position is the '||'
                bar = toks[i - 1]
                if bar.kind == 'conn' and bar.text == '||':
                    drops.append((bar.start, dead.end))
                    removed.append(dead.lit)
                    continue
            nxt = toks[i + 1]
            if nxt.kind == 'conn' and nxt.text == '||':
                drops.append((dead.start, nxt.end))
                removed.append(dead.lit)
    return drops, removed


def main():
    src = open(sys.argv[1], encoding='utf-8').read()
    parts = BLOCK_RE.split(src)
    delims = BLOCK_RE.findall(src)
    total = 0
    new = [parts[0]]
    for part in parts[1:]:
        toks = tokenize(part)
        drops, removed = find_drops(toks)
        total += len(removed)
        if drops:
            # adjacent covered elements share a '||' — merge
            # overlapping spans before splicing
            merged = []
            for s, e in sorted(drops):
                if merged and s <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], e)
                else:
                    merged.append([s, e])
            out = []
            last = 0
            for s, e in merged:
                out.append(part[last:s])
                last = e
            out.append(part[last:])
            new.append(''.join(out))
        else:
            new.append(part)
    res = new[0]
    for d, p in zip(delims, new[1:]):
        res += d + p
    open(sys.argv[1], 'w', encoding='utf-8').write(res)
    print("removed %d cover-dead needles" % total)


if __name__ == "__main__":
    main()

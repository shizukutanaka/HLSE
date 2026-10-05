#!/usr/bin/env python3
"""Remove duplicate ci_contains(text, "...") disjuncts within each
else-if block of the paste chain, SAFELY.

A 2nd+ identical occurrence is dead only inside a single run of calls
joined by ONE connector type at ONE paren depth:

    A || B || A        ->  A || B        (x || x == x)
    A && B && A        ->  A && B        (x && x == x)

NOT safe elsewhere — `A || B && A` absorbs to A, and `!call` differs
from `call` — so we tokenize each block into
CALL / CONN(||,&&) / LPAREN / RPAREN, track runs per paren depth, key
each call by ('!'-polarity, literal), and drop only 2nd+ occurrences
*within one run*: a trailing dup deletes 'conn call'; a dup that opens
its paren group deletes 'call conn'.

Usage: dedup_needles.py <hlse_supply.c>
"""
import re
import sys

BLOCK_RE = re.compile(r'\}\s*else\s+if\s*\(|\bif\s*\(')
TOKEN_RE = re.compile(
    r'(?P<call>!?\s*ci_contains\(text,\s*"(?:[^"\\]|\\.)*"\))'
    r'|(?P<conn>\|\||&&)'
    r'|(?P<lp>\()|(?P<rp>\))')
NEEDLE_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


class Run(object):
    """Calls joined by one connector type at one paren depth."""
    __slots__ = ('conn', 'seen')

    def __init__(self):
        self.conn = None
        self.seen = set()


def dedup(part):
    tokens = list(TOKEN_RE.finditer(part))
    if len(tokens) < 3:
        return part, 0
    stack = [Run()]
    conn_start = -1        # start offset of pending connector
    conn_text = None
    drops = []             # (start,end) spans to delete
    for t in tokens:
        kind = t.lastgroup
        if kind == 'lp':
            stack.append(Run())
            conn_start, conn_text = -1, None
        elif kind == 'rp':
            if len(stack) > 1:
                stack.pop()
            conn_start, conn_text = -1, None
        elif kind == 'conn':
            run = stack[-1]
            if run.conn is None:
                run.conn = t.group(0)
            elif run.conn != t.group(0):
                # connector type changes -> new run (absorption rules
                # apply across types; never dedupe across them)
                stack[-1] = Run()
                stack[-1].conn = t.group(0)
            conn_start, conn_text = t.start(), t.group(0)
        else:  # call
            run = stack[-1]
            lit = NEEDLE_RE.search(t.group(0)).group(1)
            key = (t.group(0).lstrip().startswith('!'), lit)
            if key in run.seen:
                if conn_text:
                    drops.append((conn_start, t.end()))
                else:
                    drops.append((t.start(), None))  # leading term
            else:
                run.seen.add(key)
            conn_start, conn_text = -1, None
    # resolve leading-term drops: delete 'call conn' when a connector
    # follows; leave sole terms (can't drop safely).
    spans = []
    for s, e in drops:
        if e is None:
            m = TOKEN_RE.match(part, s)
            j = m.end()
            while j < len(part) and part[j] in ' \t\n':
                j += 1
            if part[j:j + 2] in ('||', '&&'):
                spans.append((s, j + 2))
        else:
            spans.append((s, e))
    if not spans:
        return part, 0
    out = []
    last = 0
    for s, e in sorted(spans):
        out.append(part[last:s])
        last = e
    out.append(part[last:])
    return ''.join(out), len(spans)


def main():
    src = open(sys.argv[1], encoding='utf-8').read()
    parts = BLOCK_RE.split(src)
    delims = BLOCK_RE.findall(src)
    total = 0
    new = [parts[0]]
    for part in parts[1:]:
        fixed, c = dedup(part)
        total += c
        new.append(fixed)
    res = new[0]
    for d, p in zip(delims, new[1:]):
        res += d + p
    open(sys.argv[1], 'w', encoding='utf-8').write(res)
    print("removed %d same-run duplicate disjuncts" % total)


if __name__ == "__main__":
    main()

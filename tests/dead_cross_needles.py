#!/usr/bin/env python3
"""Remove unreachable disjuncts from the paste else-if chain.

The chain is first-match-wins: a needle that already fires an
EARLIER pure-OR block (all calls positive, all connectors '||')
is always false when a later block's condition is evaluated —
so any operand made from owned needles is dead.

Deadness grammar (eval-time truth is always preserved):
  or_expr  = and_expr ('||' and_expr)*
  and_expr = term ('&&' term)*
  term     = call | '(' or_expr ')' | other-text

  call        dead iff positive ('!x' is live) and lit in owned
  paren group dead iff every inner operand dead
  and_expr    dead iff ANY term dead (&&-chain short-circuits)
  or-level    dead iff EVERY operand dead

A dead operand with a '||' on either side is removed together
with that connector ('|| op' or 'op ||'). A dead operand with no
'||' neighbour makes its whole level dead — which marks the
enclosing paren group as a dead term at the parent level. A top
level that is fully dead is REPORTED (the whole block never
fires) and left untouched.

Usage: dead_cross_needles.py <hlse_supply.c>
"""
import re
import sys

BLOCK_RE = re.compile(r'\}\s*else\s+if\s*\(|\bif\s*\(')
TOKEN_RE = re.compile(
    r'(?P<call>!?\s*ci_contains\(text,\s*"(?:[^"\\]|\\.)*"\))'
    r'|(?P<conn>\|\||&&)'
    r'|(?P<lp>\()|(?P<rp>\))')
NEEDLE_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
WS = ' \t\n'


class Tok(object):
    __slots__ = ('kind', 'text', 'start', 'end', 'depth', 'lit',
                 'neg', 'match', 'dead')

    def __init__(self, m, depth):
        self.kind = m.lastgroup
        self.text = m.group(0)
        self.start = m.start()
        self.end = m.end()
        self.depth = depth
        self.lit = None
        self.neg = False
        self.match = -1     # for lp: token index of its rp
        self.dead = False
        if self.kind == 'call':
            self.lit = NEEDLE_RE.search(self.text).group(1)
            self.neg = self.text.lstrip().startswith('!')


def tokenize(part):
    toks = []
    depth = 0
    stack = []
    for m in TOKEN_RE.finditer(part):
        kind = m.lastgroup
        if kind == 'lp':
            t = Tok(m, depth)
            toks.append(t)
            stack.append(len(toks) - 1)
            depth += 1
        elif kind == 'rp':
            depth -= 1
            t = Tok(m, depth)
            toks.append(t)
            if stack:
                toks[stack.pop()].match = len(toks) - 1
        else:
            toks.append(Tok(m, depth))
    return toks


def is_pure_or(part):
    """Every term fires the block on presence alone: no negated
    calls, no '! (' groups, every connector '||'."""
    if re.search(r'!\s*\(', part):
        return False
    for m in TOKEN_RE.finditer(part):
        k = m.lastgroup
        if k == 'call' and m.group(0).lstrip().startswith('!'):
            return False
        if k == 'conn' and m.group(0) != '||':
            return False
    return TOKEN_RE.search(part) is not None


class Analyzer(object):
    def __init__(self, part, owned):
        self.part = part
        self.toks = tokenize(part)
        self.owned = owned
        self.gdead = {}      # lp token index -> bool
        self.drops = []      # (start, end) spans
        self.removed = []    # literals dropped

    def term_dead(self, i):
        """Is token i (at this level) a term that's false at eval?"""
        t = self.toks[i]
        if t.kind == 'call':
            return not t.neg and t.lit in self.owned
        if t.kind == 'lp':
            # '!(..)' is a *live* term (dead interior -> true);
            # 'name(' is a call-args group, not a boolean term.
            p = self._prev_nonws(t.start - 1)
            c = self.part[p] if p >= 0 else ''
            if c == '!' or c.isalnum() or c == '_':
                return False
            return self.group_dead(i)
        return False               # conn/rp aren't terms

    def _prev_nonws(self, i):
        while i >= 0 and self.part[i] in WS:
            i -= 1
        return i

    def group_dead(self, lp_idx):
        """'(' or_expr ')' dead iff every inner operand dead."""
        if lp_idx in self.gdead:
            return self.gdead[lp_idx]
        lp = self.toks[lp_idx]
        dead = self.level_dead(lp_idx + 1, lp.match, lp.depth + 1)
        self.gdead[lp_idx] = dead
        return dead

    def split_operands(self, lo, hi, depth):
        """Operand index-ranges + the '||' token index between
        consecutive operands. Operand = maximal run of level-d
        terms (calls, &&-conns, subgroups)."""
        ops, bars = [], []
        cur = lo
        for i in range(lo, hi):
            t = self.toks[i]
            if (t.depth == depth and t.kind == 'conn'
                    and t.text == '||'):
                ops.append((cur, i))
                bars.append(i)
                cur = i + 1
        ops.append((cur, hi))
        return ops, bars

    def op_dead(self, lo, hi, depth):
        """Operand (&&-chain) dead iff ANY of its level-d terms is
        dead — one false term short-circuits the whole &&-chain
        to false at eval time."""
        for i in range(lo, hi):
            t = self.toks[i]
            if t.depth != depth:
                continue
            if t.kind == 'call' or t.kind == 'lp':
                if self.term_dead(i):
                    return True
        return False

    def level_dead(self, lo, hi, depth):
        ops, _ = self.split_operands(lo, hi, depth)
        if not ops:
            return False
        return all(self.op_dead(a, b, depth) for a, b in ops)

    def process_level(self, lo, hi, depth):
        """Emit drops for dead operands with a '||' neighbour;
        recurse into groups for nested levels. Returns True if the
        whole level is dead."""
        ops, bars = self.split_operands(lo, hi, depth)
        dead = [self.op_dead(a, b, depth) for a, b in ops]
        all_dead = bool(ops) and all(dead)
        if all_dead:
            return True      # caller handles (group dead / dead block)
        for k, (a, b) in enumerate(ops):
            if not dead[k]:
                # recurse into groups inside this live operand
                for i in range(a, b):
                    t = self.toks[i]
                    if t.kind == 'lp' and t.depth == depth:
                        inner = self.process_level(i + 1, t.match,
                                                   depth + 1)
                        # group stays live (op was live anyway)
                        _ = inner
                continue
            # dead operand: drop with a neighbouring '||'
            fa = self.toks[a].start
            lb = self.toks[b - 1].end
            # a '!' glued to the operand's first term must drop
            # with it ('x || !dead' would leave a dangling '!')
            p = self._prev_nonws(fa - 1)
            if p >= 0 and self.part[p] == '!':
                fa = p
            if k > 0:
                bar = self.toks[bars[k - 1]]
                self.drops.append((bar.start, lb))
                self.removed.extend(
                    self.toks[i].lit for i in range(a, b)
                    if self.toks[i].kind == 'call')
            else:
                bar = self.toks[bars[k]]
                self.drops.append((fa, bar.end))
                self.removed.extend(
                    self.toks[i].lit for i in range(a, b)
                    if self.toks[i].kind == 'call')
        return False

    def run(self):
        if not self.toks:
            return '', 0, False
        dead = self.process_level(0, len(self.toks), 0)
        if dead:
            return self.part, 0, True   # dead block — report only
        out = []
        last = 0
        for s, e in sorted(self.drops):
            out.append(self.part[last:s])
            last = e
        out.append(self.part[last:])
        return ''.join(out), len(self.drops), False


def dedup(part, owned, removed_lits):
    an = Analyzer(part, owned)
    fixed, c, dead = an.run()
    removed_lits.extend(an.removed)
    return fixed, c, dead


def main():
    src = open(sys.argv[1], encoding='utf-8').read()
    parts = BLOCK_RE.split(src)
    delims = BLOCK_RE.findall(src)
    owned = set()
    total = 0
    removed_lits = []
    dead_blocks = []
    new = [parts[0]]
    for bi, part in enumerate(parts[1:], start=1):
        fixed, c, dead = dedup(part, owned, removed_lits)
        total += c
        if dead:
            dead_blocks.append(bi)
        new.append(fixed)
        if is_pure_or(part):
            for m in TOKEN_RE.finditer(part):
                if m.lastgroup == 'call':
                    owned.add(NEEDLE_RE.search(m.group(0)).group(1))
    res = new[0]
    for d, p in zip(delims, new[1:]):
        res += d + p
    open(sys.argv[1], 'w', encoding='utf-8').write(res)
    print("removed %d unreachable operands (%d distinct needles)"
          % (total, len(set(removed_lits))))
    for b in dead_blocks:
        print("dead block (condition never true): block %d" % b)


if __name__ == "__main__":
    main()

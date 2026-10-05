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

  call        dead iff positive ('!x' is live) and some owned
              needle is a substring of lit — lit's inputs all
              contain an owned needle, so lit is always false
              here (exact match is the o == lit special case)
  paren group dead iff every inner operand dead
  and_expr    dead iff ANY term dead (&&-chain short-circuits)
  or-level    dead iff EVERY operand dead

A dead operand with a '||' on either side is removed together
with that connector ('|| op' or 'op ||'). A dead operand with no
'||' neighbour makes its whole level dead — which marks the
enclosing paren group as a dead term at the parent level. A top
level that is fully dead is REPORTED (the whole block never
fires) and left untouched.

Absorption: at any or-level, the set D of literals carried by
standalone positive-call disjuncts propagates as additional
'owned' context — a positive conjunct lit in D makes its
&&-operand dead ('x || (x && y)' == 'x'), and a negated conjunct
'!x' with x in D is a tautological term ('x || (y && !x)' ==
'x || y') that is dropped with one '&&'. D is position
independent: 'X || (Y && !X)' fires via X whenever X holds, so
'!X' never constrains the result.

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

    def term_dead(self, i, eff):
        """Is token i (at this level) a term that's false at eval?"""
        t = self.toks[i]
        if t.kind == 'call':
            if t.neg or t.lit.startswith(' -'):
                return False
            for o in eff:
                if not o.startswith(' -') and o in t.lit:
                    return True
            return False
        if t.kind == 'lp':
            # '!(..)' is a *live* term (dead interior -> true);
            # 'name(' is a call-args group, not a boolean term.
            p = self._prev_nonws(t.start - 1)
            c = self.part[p] if p >= 0 else ''
            if c == '!' or c.isalnum() or c == '_':
                return False
            return self.group_dead(i, eff)
        return False               # conn/rp aren't terms

    def _prev_nonws(self, i):
        while i >= 0 and self.part[i] in WS:
            i -= 1
        return i

    def group_dead(self, lp_idx, eff):
        """'(' or_expr ')' dead iff every inner operand dead."""
        if lp_idx in self.gdead:
            return self.gdead[lp_idx]
        lp = self.toks[lp_idx]
        dead = self.level_dead(lp_idx + 1, lp.match, lp.depth + 1,
                               eff)
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

    def op_dead(self, lo, hi, depth, eff):
        """Operand (&&-chain) dead iff ANY of its level-d terms is
        dead — one false term short-circuits the whole &&-chain
        to false at eval time."""
        for i in range(lo, hi):
            t = self.toks[i]
            if t.depth != depth:
                continue
            if t.kind == 'call' or t.kind == 'lp':
                if self.term_dead(i, eff):
                    return True
        return False

    def level_dead(self, lo, hi, depth, eff):
        ops, _ = self.split_operands(lo, hi, depth)
        if not ops:
            return False
        return all(self.op_dead(a, b, depth, eff) for a, b in ops)

    def standalone_lit(self, a, b, depth):
        """Operand that is exactly one positive call -> its literal."""
        els = [i for i in range(a, b)
               if self.toks[i].depth == depth]
        if (len(els) == 1 and self.toks[els[0]].kind == 'call'
                and not self.toks[els[0]].neg
                and not self.toks[els[0]].lit.startswith(' -')):
            return self.toks[els[0]].lit
        return None

    def neg_drops(self, a, b, depth, eff):
        """Redundant negated conjuncts at an operand's top level:
        '!x' with x in eff is always true at eval (x's standalone
        disjunct already claims every x-input). Drop '&& !x' (or
        '!x &&' when it is the operand's first term)."""
        els = [i for i in range(a, b)
               if self.toks[i].depth == depth
               and self.toks[i].kind == 'call']
        live = [i for i in els
                if not (self.toks[i].neg
                        and self.toks[i].lit in eff)]
        if not live:
            return   # operand is constant-true — needs a report
        for i in els:        # path, not a rewrite
            t = self.toks[i]
            if not (t.neg and t.lit in eff):
                continue
            prv = self.toks[i - 1] if i > a else None
            if (prv is not None and prv.kind == 'conn'
                    and prv.text == '&&' and prv.depth == depth):
                self.drops.append((prv.start, t.end))
                self.removed.append('!' + t.lit)
                continue
            nxt = self.toks[i + 1] if i + 1 < b else None
            if (nxt is not None and nxt.kind == 'conn'
                    and nxt.text == '&&' and nxt.depth == depth):
                self.drops.append((t.start, nxt.end))
                self.removed.append('!' + t.lit)

    def process_level(self, lo, hi, depth, eff):
        """Emit drops for dead operands with a '||' neighbour and
        for redundant '!x' conjuncts; recurse into groups.
        eff = context-owned needles; this level's standalone
        positive disjuncts extend it (absorption).
        Returns True if the whole level is dead."""
        ops, bars = self.split_operands(lo, hi, depth)
        D = set()
        for a, b in ops:
            lit = self.standalone_lit(a, b, depth)
            if lit is not None:
                D.add(lit)
        eff = eff | D
        dead = []
        for a, b in ops:
            lit = self.standalone_lit(a, b, depth)
            # a disjunct cannot subsume itself — drop its own lit
            op_eff = eff - {lit} if lit is not None else eff
            dead.append(self.op_dead(a, b, depth, op_eff))
        all_dead = bool(ops) and all(dead)
        if all_dead:
            return True      # caller handles (group dead / dead block)
        for k, (a, b) in enumerate(ops):
            if not dead[k]:
                # tautological conjuncts inside a live operand
                # (the operand's own lit is already excluded via
                # standalone_lit check above)
                if self.standalone_lit(a, b, depth) is None:
                    self.neg_drops(a, b, depth, eff)
                # recurse into groups inside this live operand
                for i in range(a, b):
                    t = self.toks[i]
                    if t.kind == 'lp' and t.depth == depth:
                        inner = self.process_level(i + 1, t.match,
                                                   depth + 1, eff)
                        # group stays live (op was live anyway)
                        _ = inner
                continue
            # dead operand: drop with a neighbouring '||'
            # trim edge tokens below this level (the block's own
            # trailing ')' shows depth -1 and must never be eaten)
            aa, bb = a, b - 1
            while self.toks[aa].depth < depth:
                aa += 1
            while self.toks[bb].depth < depth:
                bb -= 1
            fa = self.toks[aa].start
            lb = self.toks[bb].end
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
        dead = self.process_level(0, len(self.toks), 0,
                                  self.owned)
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
    an = Analyzer(part, set(owned))
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

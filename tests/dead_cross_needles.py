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


def _code_depths(src):
    """Brace depth at every source offset, computed on a copy with
    comments and string literals blanked so braces inside them do
    not skew the count."""
    def _blank(m):
        return ''.join('\n' if c == '\n' else ' ' for c in m.group(0))
    s = re.sub(r'//[^\n]*', _blank, src)
    s = re.sub(r'/\*.*?\*/', _blank, s, flags=re.S)
    s = re.sub(r'"(?:[^"\\]|\\.)*"',
               lambda m: '"' + ''.join('\n' if c == '\n' else ' '
                                       for c in m.group(0)[1:-1]) + '"', s)
    s = re.sub(r"'(?:[^'\\]|\\.)*'",
               lambda m: "'" + ''.join('\n' if c == '\n' else ' '
                                       for c in m.group(0)[1:-1]) + "'", s)
    depth = [0] * (len(s) + 1)
    d = 0
    for i, c in enumerate(s):
        if c == '{':
            d += 1
        elif c == '}':
            d -= 1
        depth[i + 1] = d
    return depth


class ChainScope(object):
    """else-if chain scoping for cross-condition ownership.

    A condition's needles are 'owned' (provably absent) only for
    the conditions evaluated AFTER it in the *same* else-if chain
    — first-match-wins. Independent 'if' statements do not gate
    each other (the multi-hold P8 chain is a flat run of 'if's:
    every condition evaluates), and a pure-OR chain nested inside
    a body never ran when its enclosing condition was false.

    Tracking is per brace depth: 'if' opens a fresh chain at its
    depth, '} else if' continues the chain at that depth, and
    chains deeper than the current separator are stale (their
    bodies already closed).
    """

    def __init__(self, src):
        self.depth = _code_depths(src)
        self.seps = list(BLOCK_RE.finditer(src))
        self.owned = {}    # depth -> needles of earlier chain conditions
        self.self_n = {}   # depth -> needles of the enclosing condition
                           # (evaluated TRUE when its body runs — must
                           # be excluded from the inner parts' context)

    def _dpt(self, bi):
        return self.depth[self.seps[bi - 1].end()]

    def _elif(self, bi):
        return 'else' in self.seps[bi - 1].group(0)

    def eff(self, bi):
        """Effective owned-needle context for part bi — call before
        analyzing it; then learn() its pure-OR needles."""
        dpt = self._dpt(bi)
        for k in [k for k in self.owned if k > dpt]:
            del self.owned[k]
            self.self_n.pop(k, None)
        if not self._elif(bi):
            self.owned[dpt] = set()
        self.self_n.pop(dpt, None)
        eff = set()
        for k, s in self.owned.items():
            eff |= s
            if k < dpt:
                eff -= self.self_n.get(k, set())
        return eff, dpt

    def learn(self, dpt, needles):
        """Record part dpt's own needles: earlier siblings' needles
        stay absent for later chain conditions; this condition's
        needles are PRESENT inside its own body, so they are kept
        out of eff via self_n."""
        if needles:
            self.owned.setdefault(dpt, set()).update(needles)
            self.self_n[dpt] = set(needles)


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

    def _drop_term(self, a, b, depth, i, label):
        """Drop term i plus one adjacent '&&' at this level."""
        t = self.toks[i]
        prv = self.toks[i - 1] if i > a else None
        if (prv is not None and prv.kind == 'conn'
                and prv.text == '&&' and prv.depth == depth):
            self.drops.append((prv.start, t.end))
            self.removed.append(label)
            return True
        nxt = self.toks[i + 1] if i + 1 < b else None
        if (nxt is not None and nxt.kind == 'conn'
                and nxt.text == '&&' and nxt.depth == depth):
            self.drops.append((t.start, nxt.end))
            self.removed.append(label)
            return True
        return False

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
            self._drop_term(a, b, depth, i, '!' + t.lit)

    def implied_drops(self, a, b, depth, eff):
        """Implied terms inside an operand (all are dropped only
        when a surviving term keeps the operand non-empty):
          (a) positive conjunct x with x ⊆ a sibling positive
              conjunct's literal — x is implied ('dfs && hdfs'
              ≡ 'hdfs'; ' ' ⊆ 'gau ' → drop ' ');
          (b) a '(…)' group term whose inner standalone disjunct
              il ⊆ a surviving conjunct x — the group is always
              true ('apksigner && (sign || rotate)' ≡ 'apksigner').
        '!(…)' and 'name(' groups are not boolean terms."""
        terms = [i for i in range(a, b)
                 if self.toks[i].depth == depth
                 and self.toks[i].kind in ('call', 'lp')]
        pos = {}
        for i in terms:
            t = self.toks[i]
            if t.kind == 'call' and not t.neg:
                pos[i] = t.lit
        # (a) implied positive conjuncts
        drop_idx = set()
        for i, x in pos.items():
            for j, L in pos.items():
                if i != j and x in L:
                    drop_idx.add(i)
                    break
        # (b) group implied by a surviving conjunct
        surviving = set(l for i, l in pos.items()
                        if i not in drop_idx)
        for i in terms:
            t = self.toks[i]
            if t.kind != 'lp':
                continue
            p = self._prev_nonws(t.start - 1)
            c = self.part[p] if p >= 0 else ''
            if c == '!' or c.isalnum() or c == '_':
                continue    # !(…) or call-args — not a boolean term
            iops, _ = self.split_operands(i + 1, t.match,
                                          depth + 1)
            inner = set()
            for ia, ib in iops:
                lit = self.standalone_lit(ia, ib, depth + 1)
                if lit is not None:
                    inner.add(lit)
            if any(il in x for x in surviving for il in inner):
                drop_idx.add(i)
        if len(terms) - len(drop_idx) < 1:
            return          # would empty the operand — skip
        # consecutive dropped terms share a '&&' — emit one span
        # per maximal run: a leading run drops 't && … && ',
        # every other run drops '&& … && t'.
        def term_end(i):
            t = self.toks[i]
            return self.toks[t.match].end if t.kind == 'lp' \
                else t.end

        pos_in_terms = {t: k for k, t in enumerate(terms)}
        dropped_pos = sorted(pos_in_terms[i] for i in drop_idx)
        runs = []
        for k in dropped_pos:
            if runs and k == runs[-1][-1] + 1:
                runs[-1].append(k)
            else:
                runs.append([k])
        for run in runs:
            first = terms[run[0]]
            last = terms[run[-1]]
            label = ', '.join(
                '(...)' if self.toks[i].kind == 'lp'
                else self.toks[i].lit
                for i in (terms[k] for k in run))
            if run[0] == 0:
                # leading run: drop 't && … && ' — the && is the
                # one immediately before the next surviving term
                if run[-1] + 1 >= len(terms):
                    continue
                conn = self.toks[terms[run[-1] + 1] - 1]
                if (conn.kind == 'conn' and conn.text == '&&'
                        and conn.depth == depth):
                    self.drops.append(
                        (self.toks[first].start, conn.end))
                    self.removed.append(label)
            else:
                prv = self.toks[first - 1]
                if (prv.kind == 'conn' and prv.text == '&&'
                        and prv.depth == depth):
                    self.drops.append(
                        (prv.start, term_end(last)))
                    self.removed.append(label)

    def process_level(self, lo, hi, depth, eff):
        """Emit drops for dead operands with a '||' neighbour and
        for redundant conjuncts; recurse into groups.
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
                    self.implied_drops(a, b, depth, eff)
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


_SELFTEST = """int ci_contains(const char*, const char*);
void t(const char *text) {
    if (ci_contains(text, "aaa") || ci_contains(text, "bbb")) { }
    else if (ci_contains(text, "aaa") && ci_contains(text, "zzz")) { }
    else if (ci_contains(text, "qqq")) { }
}
void u(const char *text) {
    if (ci_contains(text, "ccc")) { }
    if (ci_contains(text, "ccc")) { }
    if (ci_contains(text, "ccc") || ci_contains(text, "ddd")) { }
}
void v(const char *text) {
    if (ci_contains(text, "eee")) {
        if (ci_contains(text, "fff") || ci_contains(text, "ggg")) { }
    } else if (ci_contains(text, "fff") && ci_contains(text, "hhh")) { }
}
"""


def selftest():
    """ChainScope regression: same-chain elif gating must fire;
    independent 'if's and inner-chain needles must not gate."""
    parts = BLOCK_RE.split(_SELFTEST)
    scope = ChainScope(_SELFTEST)
    dead = []
    for bi, part in enumerate(parts[1:], start=1):
        eff, dpt = scope.eff(bi)
        _, _, is_dead = Analyzer(part, eff).run()
        dead.append(is_dead)
        if is_pure_or(part):
            scope.learn(dpt, {
                NEEDLE_RE.search(m.group(0)).group(1)
                for m in TOKEN_RE.finditer(part)
                if m.lastgroup == 'call'})
    # t: 'aaa' owned -> 'aaa && zzz' dead. u: three independent ifs,
    # none dead. v: inner 'fff||ggg' must not own the outer elif.
    want = [False, True, False, False, False, False, False, False, False]
    if dead != want:
        print("selftest: dead-map %s != %s" % (dead, want))
        return 1
    print("selftest: chain-scope semantics OK")
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        return selftest()
    src = open(sys.argv[1], encoding='utf-8').read()
    parts = BLOCK_RE.split(src)
    delims = BLOCK_RE.findall(src)
    scope = ChainScope(src)
    total = 0
    removed_lits = []
    dead_blocks = []
    new = [parts[0]]
    for bi, part in enumerate(parts[1:], start=1):
        eff, dpt = scope.eff(bi)
        fixed, c, dead = dedup(part, eff, removed_lits)
        total += c
        if dead:
            dead_blocks.append(bi)
        new.append(fixed)
        if is_pure_or(part):
            scope.learn(dpt, {
                NEEDLE_RE.search(m.group(0)).group(1)
                for m in TOKEN_RE.finditer(part)
                if m.lastgroup == 'call'})
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

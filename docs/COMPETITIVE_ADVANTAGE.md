# Competitive Advantage — HLSE (2026-11-22)

Method: competitive-advantage programme. Competitor survey (paid and
free), money-flow decomposition, then the Musk method + Socratic
questioning repeated until a premise broke (two full rounds).
Judged from the maker's principles: the maker holds no personal data,
provides software only (no operating cost), and the product itself is
free.

## The market, and where the money goes

HLSE spans five markets. In every one of them, the money pools in the
same four places — and detection itself is none of them.

| Market | Competitors | Revenue model |
|---|---|---|
| Secret scanning | GitGuardian | Free up to 25 developers; paid ≈ $25–45/dev/month. The product is the cloud platform and incident management around the scanner |
| Secret scanning | gitleaks / TruffleHog | OSS free (MIT / AGPL). Revenue is the Enterprise dashboard, central policy, verification. TruffleHog's verification *sends candidate secrets to each provider's API* to test whether they are live |
| Secret scanning | GitHub Secret Protection | $19 per active committer/month, platform-billed |
| Supply chain | Socket | Free tier; Team $25, Business $50 per dev seat/month. Manifests are sent to Socket's cloud for analysis |
| Supply chain | Snyk | From $25/dev/month |
| Email / human layer | Proofpoint | Essentials ≈ $2.75/user/month; median enterprise contract ≈ $73K/year. The threat-intel graph (500B signals/day) is the product's core |
| Email / human layer | Abnormal AI | $20–35/mailbox/year plus a $5K–15K platform fee. Requires API access to the customer's mail |
| Email / human layer | Mimecast / Defender for O365 | $6–10 / $2–5 per user/month; the latter is bundled into M365 E5, driving its marginal price toward zero |
| Human layer (training) | KnowBe4 | $1.63–3.75/seat/month on a 3-year term. Sells the "human layer" as content and a continuing contract |
| Host audit | Lynis | OSS (GPLv3) free; Lynis Enterprise charges for centralised reporting and compliance |
| Host audit | OpenSCAP / Wazuh | Free OSS; Wazuh monetises the managed cloud (per-agent) |

The four pools: (a) per-seat / per-mailbox recurring subscriptions,
(b) the cloud control plane — dashboards, incident management, history
retention, compliance evidence, (c) telemetry network effects, where
detection improves because customer data flows to the vendor
(GitGuardian's public monitoring, Proofpoint's signal graph, Socket's
package intelligence, TruffleHog's verification calls), and
(d) platform bundling.

The load-bearing observation: in almost every paid competitor, the
customer's most sensitive data — the leaked secrets themselves, the
full mail stream, the dependency manifests — must flow to the
security vendor's servers as a precondition of the product working.
The detector itself becomes a new custodian of exactly the data whose
exposure the customer fears.

## The iteration

### Round 1 — question "breadth and F1 are the value"

- Questioned premise: HLSE competes on detection breadth and corpus
  accuracy. Deleted: the pattern-count race (GitGuardian detects
  450+ secret types against HLSE's 61 patterns + 7 structural checks;
  a count race is structurally unwinnable and endless), and
  "F1 = 1.000" as the headline (it is self-graded on HLSE's own
  corpora, a user cannot falsify it, and the repo's own documents
  already disagree about the current test count).
- Survived: the 6-stage evasion-resistant normalisation pipeline;
  coverage of the whole human layer in one binary; and the honesty
  machinery — a `blind_spot` field in every JSON verdict, and the
  rule that "could not read it" never reports as a pass.

### Round 2 — question "a security product needs a cloud" (the premise broke)

- Every paid competitor's detection quality is *rented from a live
  cloud*: intel feeds, verification APIs, behavioural baselines.
  Stop paying and the product degrades or stops. The subscription is
  not just billing; it is a runtime dependency.
- HLSE's invariants — zero network calls enforced by a build-time
  privacy tripwire, determinism, zero dependencies — make the
  opposite property a mechanically checkable structure rather than a
  policy promise. A SaaS vendor cannot copy this without deleting
  both its billing model and its intel flywheel.
- So the form factor is the product. No competitor covers the human
  layer end to end (URL → text → paste → package → secret → file →
  host) in one auditable ~464 KB binary that runs air-gapped, in CI,
  from a rescue USB, or embedded via `libhlse.so`. Assembling
  equivalent coverage from competitors means five-plus vendors,
  five-plus subscriptions, and sending data to all of them.
- Second break: deterministic + offline means the verdict itself is
  reproducible and auditable — normative JSON schemas, stable
  append-only `pattern_id` routing tokens, disclosed blind spots.
  A cloud AI verdict cannot be re-run, appealed, or schema-validated.
  In regulated contexts, "the detector is itself auditable" is a
  property that cannot be bought from a black-box SaaS.

## The structural advantage

HLSE can keep delivering the whole human-layer detection surface as
one deterministic, dependency-free binary that provably sends
nothing anywhere — the zero-network invariant is enforced by a
build-time tripwire, not asserted in a policy page. Every
competitor's revenue rests on a continuing relationship that
requires the customer's most sensitive data to flow to the vendor's
cloud, so a detector that needs no account, no feed, no server and
no telemetry — and returns reproducible, schema-validated,
blind-spot-disclosing verdicts — cannot be copied without breaking
the model that pays them. HLSE has no revenue and no server, so it
can keep that promise permanently.

Supporting facts already true of the product:

- Zero network calls, verified by `make privacy-check`; the analysis
  functions are pure, reentrant and zero-allocation.
- Detection only: HLSE scores and reports, and never blocks,
  quarantines, deletes or modifies anything — the integrating system
  decides, driven by exit codes and the JSON verdict.
- 13 normative JSON Schemas (`schema/`) and OCSF/ECS mappings
  (`docs/SIEM_INTEGRATION.md`) make verdicts consumable by existing
  SIEM/SOAR pipelines without a vendor agent.

## Remaining opportunities (ranked)

1. Re-derive the README's headline numbers from a real run. The
   README claims 1,187 passing tests while `AGENTS.md` records a
   `make test` baseline of 872; `AGENTS.md` itself names doc-number
   drift as a known weakness. One measured run settles which is
   current, and the numbers should then be generated, not hand-kept.
2. Lead with the enforceable invariants, not the corpus score. The
   README's "At a glance" opens with self-graded F1; the
   tripwire-enforced zero-network promise and determinism are the
   claims a user can verify (`--benchmark`, `make privacy-check`)
   and a competitor cannot match.
3. Make the two-minute adoption path the top of the funnel: the
   pre-commit hook and the GitHub Actions YAML already ship under
   `examples/`; surfacing them in the README Quick start turns
   "drop into any repo" into the distribution wedge for a product
   with no marketing budget.
4. macOS parity (named weakness in `AGENTS.md`: FSEvents stub,
   Linux-only checks). The honest-degradation work is done; closing
   the gap widens the embeddable surface.
5. Do not chase the pattern-count race. The
   custom-patterns-without-rebuild mechanism is the sustainable
   answer to long-tail secret formats; document it more prominently
   instead of growing the built-in list toward 450.

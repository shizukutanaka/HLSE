# SIEM / SOAR Integration Guide

HLSE emits structured JSON for every verdict (`--json`). This guide maps HLSE's
fields onto the two dominant open SIEM schemas — **OCSF** (Open Cybersecurity
Schema Framework) and **ECS** (Elastic Common Schema) — so you can ingest HLSE
verdicts without hand-reverse-engineering the field semantics.

> Data normalization is the main bottleneck in most SIEM deployments: every log
> source has its own field names, so teams build and maintain custom parsers.
> This guide is HLSE's parser-spec so you don't have to write one.

All `jq` transforms below are pure field re-mappings — HLSE itself stays
network-free and never emits anything but the JSON documented in `schema/`.

---

## 1. The HLSE verdict envelope

Every verdict kind shares a uniform envelope (see `schema/*.schema.json` for the
13 normative schemas):

| HLSE field      | Type    | Meaning                                              |
|-----------------|---------|------------------------------------------------------|
| `kind`          | string  | Verdict kind (`url`, `text`, `file`, `secret`, …)    |
| `hlse_version`  | string  | Engine version that produced the verdict             |
| `score`         | int     | 0–100 threat score                                   |
| `action`        | string  | `SAFE`/`LOG`/`ALERT`/`BLOCK`/`ISOLATE`               |
| `severity`      | int     | 0–4, monotonic with `score` band                     |
| `pattern`       | string  | Prose attack-pattern label (score-dependent)         |
| `pattern_id`    | string  | Stable `HLSE-*` routing token (see `--list-patterns`) |

Use `pattern_id` (stable, append-only) for routing rules — never `pattern`
(prose we keep refining). Enumerate the full token set with
`hlse_core --json --list-patterns`.

---

## 2. Severity mapping

HLSE's 0–4 `severity` maps cleanly onto both schemas. OCSF's `severity_id` runs
0–6; HLSE never emits `Unknown(0)` or `Fatal(6)`.

| HLSE `action` | HLSE `severity` | Score band | OCSF `severity_id` | OCSF label    | ECS `event.severity` |
|---------------|-----------------|------------|--------------------|---------------|----------------------|
| `SAFE`        | 0               | 0–14       | 1                  | Informational | 1                    |
| `LOG`         | 1               | 15–39      | 2                  | Low           | 21                   |
| `ALERT`       | 2               | 40–59      | 3                  | Medium        | 47                   |
| `BLOCK`       | 3               | 60–79      | 4                  | High          | 73                   |
| `ISOLATE`     | 4               | 80–100     | 5                  | Critical      | 99                   |

(ECS `event.severity` is a free integer; the values above spread HLSE's bands
across 0–99 for dashboards that bucket by quartile.)

---

## 3. OCSF mapping (Detection Finding, class_uid 2004)

HLSE verdicts map most naturally to the OCSF **Detection Finding** class.

| OCSF attribute            | Source from HLSE verdict                                  |
|---------------------------|----------------------------------------------------------|
| `class_uid`               | `2004` (Detection Finding)                                |
| `category_uid`            | `2` (Findings)                                            |
| `severity_id`             | `severity` → table in §2                                  |
| `confidence`              | `confidence` string (when present)                        |
| `message`                 | `pattern` (or first `reasons[]` entry)                    |
| `finding_info.title`      | `pattern`                                                 |
| `finding_info.uid`        | `pattern_id`                                              |
| `finding_info.types[]`    | `[kind]`                                                  |
| `metadata.product.name`   | `"HLSE"`                                                  |
| `metadata.product.version`| `hlse_version`                                            |
| `status` / disposition    | `action` (`BLOCK`/`ISOLATE` → blocked; else observed)     |
| `unmapped.score`          | `score` (HLSE-specific, no OCSF equivalent)               |

### jq: HLSE verdict → OCSF Detection Finding

```bash
hlse_core --json "https://g00gle.com" | jq '
  ($env.HLSE_OCSF_SEV // {"0":1,"1":2,"2":3,"3":4,"4":5}) as $sevmap
  | {
      class_uid: 2004,
      category_uid: 2,
      activity_id: 1,
      severity_id: ($sevmap[(.severity|tostring)] // 0),
      message: (.pattern // (.reasons[0] // "HLSE verdict")),
      confidence: (.confidence // null),
      finding_info: {
        title: (.pattern // .kind),
        uid: (.pattern_id // null),
        types: [.kind]
      },
      metadata: { product: { name: "HLSE", version: .hlse_version } },
      status: (if .severity >= 3 then "blocked" else "observed" end),
      unmapped: { score: .score, action: .action }
    }'
```

---

## 4. ECS mapping (Elastic Common Schema)

| ECS field                | Source from HLSE verdict                                  |
|--------------------------|----------------------------------------------------------|
| `event.kind`             | `"alert"` (score > 0) / `"event"` (score 0)               |
| `event.module`           | `"hlse"`                                                  |
| `event.dataset`          | `"hlse." + kind`                                          |
| `event.severity`         | `severity` → table in §2                                  |
| `event.action`           | `action` (lowercased)                                     |
| `event.outcome`          | `"success"` (detection ran)                               |
| `event.reason`           | `pattern` (or first `reasons[]`)                          |
| `rule.id`                | `pattern_id`                                              |
| `rule.name`              | `pattern`                                                 |
| `threat.indicator.type`  | `kind`                                                    |
| `message`                | first `reasons[]` entry                                   |
| `observer.product`       | `"HLSE"`                                                  |
| `observer.version`       | `hlse_version`                                            |
| `labels.hlse_score`      | `score`                                                   |

### jq: HLSE verdict → ECS document

```bash
hlse_core --json package reqeusts pip | jq '
  ({"0":1,"1":21,"2":47,"3":73,"4":99}) as $sevmap
  | {
      "event": {
        kind: (if .score > 0 then "alert" else "event" end),
        module: "hlse",
        dataset: ("hlse." + .kind),
        severity: ($sevmap[(.severity|tostring)] // 0),
        action: (.action | ascii_downcase),
        outcome: "success",
        reason: (.pattern // (.reasons[0]? // null))
      },
      "rule": { id: (.pattern_id // null), name: (.pattern // null) },
      "observer": { product: "HLSE", version: .hlse_version },
      "labels": { hlse_score: (.score|tostring), hlse_kind: .kind }
    }'
```

---

## 5. CI/CD pipeline integration

`hlse_core scan <dir>` and every single-target subcommand follow a stable
exit-code contract for gating:

| Exit code | Meaning                                                       |
|-----------|---------------------------------------------------------------|
| `0`       | Clean / below `--fail-on` threshold (default `60` = BLOCK)     |
| `1`       | Threat at or above the fail threshold                          |
| `2`       | Usage error (bad arguments)                                   |

```bash
# Fail the build on any BLOCK+ finding (default)
hlse_core scan ./src || exit 1

# Stricter gate: fail on ALERT+ (score >= 40)
hlse_core --fail-on 40 scan ./src

# Emit JSON for the pipeline's SIEM forwarder, still gate on exit code
hlse_core --json scan ./src | tee hlse-report.ndjson
```

The `scan` summary line (`"kind":"scan_summary"`) carries `max_severity` so a
single-line consumer can gate without parsing every per-file verdict:

```bash
hlse_core --json scan ./src \
  | jq -c 'select(.kind=="scan_summary") | {max_severity, threats, gate_hits}'
```

---

## 6. Streaming / ndjson ingestion

Pipe mode emits one JSON object per input line — ready for ndjson-based
forwarders (Elastic `application/x-ndjson`, Splunk HEC, Datadog, OCSF
collectors):

```bash
# One verdict per line, straight into a forwarder
cat urls.txt | hlse_core --stdin --json \
  | curl -s -XPOST "$SPLUNK_HEC_URL" \
         -H "Authorization: Splunk $HEC_TOKEN" \
         -H "Content-Type: application/json" --data-binary @-
```

Each line independently validates against the matching `schema/hlse_<kind>_verdict.schema.json`,
so a streaming validator can reject malformed records before they reach the lake.

---

## 7. Token registry as a routing table

Build SOAR playbook routing directly from the registry — no need to read HLSE
source:

```bash
# All credential-exposure tokens → rotate-secrets playbook
hlse_core --json --list-patterns \
  | jq -r '.patterns[] | select(.kind=="secret") | .id'

# Map every token to a human description for a runbook appendix
hlse_core --json --list-patterns \
  | jq -r '.patterns[] | "\(.id)\t\(.kind)\t\(.description)"'
```

Tokens are **append-only**: once `HLSE-BEC-WIRE` ships it is never reworded or
removed, so a routing rule keyed on it will not silently break across upgrades.

---

## See also

- `schema/` — the 13 normative JSON Schemas (draft 2020-12)
- `hlse_core --json --list-patterns` — the live pattern_id registry
- `examples/hlse-scan.yml` — GitHub Actions integration
- OCSF: <https://ocsf.io/> · ECS: <https://www.elastic.co/guide/en/ecs/current/index.html>

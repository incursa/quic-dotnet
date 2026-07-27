---
title: "Adaptive Runtime Send-Composition Holdout Extension"
---

# Adaptive Runtime Send-Composition Holdout Extension

Status: completed bounded follow-on; decision
`measurement_completed_no_stable_rule`

## Purpose

The first offline campaign proved the measurement chain but produced no
complete eligible four-cell holdout context. This extension changes only the
offline workload contexts. It does not change the reviewed axes, policy
values, proofs, correctness interaction, runtime mechanisms, authorization
flags, practical thresholds, or selector inputs.

## Preserved authority

The extension retains:

- the exact A/B/C/D configured cells;
- the reviewed `single_eligible` and `memory_conservative` proofs;
- the passed send-composition correctness review;
- the four counterbalanced orders;
- one-second warmup, measurement, and cooldown periods;
- two pilot and four full repetitions;
- serial local execution;
- the three-percent practical goodput gate;
- the five-percent P95 regression guardrail;
- the 0.98 fairness floor;
- catalog-derived behavior and outcome materialization;
- immutable raw retention and checksums; and
- false active behavior, performance acceptance, and production activation
  authorization.

The canonical extension campaign has content hash
`21835708e640c57a5bd90ba37632763f62793c0833549cabd5b758c0d785c7b6`
and seed `20260727`.

## Holdout contexts

| Workload ID | Family | Scenario | Payload | Concurrency | Expected activation |
| --- | --- | --- | ---: | ---: | --- |
| `holdout_segment_rich_medium` | segment-rich writes | upload | 12,288 | 10 | batch and upstream buffer |
| `holdout_many_stream_medium` | many-stream saturation | upload | 32,768 | 12 | batch and upstream buffer |
| `holdout_copy_pressure_upload` | copy/memory pressure | upload | 49,152 | 20 | batch and upstream buffer |
| `inactive_control` | inactive control | upload | 2,048 | 1 | none |

These points are not exact duplicates of the training points. Their names and
families remain offline provenance and cannot become runtime selector inputs.
Only activation evidence was inspected during the preflight. Performance
outcomes remained sealed until all predeclared holdout cells finished and
validated.

## Decision rule

After the full extension rebuilds:

- a selector remains prohibited unless the complete training and holdout
  gates pass without retuning;
- failed activation remains retained and produces
  `measurement_completed_more_context_required`;
- inconsistent or guardrail-violating effects produce `no_stable_rule`; and
- only an independently reproducible, compact, legitimate-observation rule
  may become shadow-only.

Production actuation, `active_internal`, another axis, CI modification, and
online learning remain out of scope.

## Completed result

The extension executed 176 serial production-mechanism runs: 16 pilot, 96
training, and 64 holdout. All three activation-expected holdouts produced four
repetitions of A, B, C, and D. A, B, and C were performance-eligible and D was
retained as expected-equivalent to B. The inactive control remained inactive
for every cell. All runs passed correctness and exact owner-release checks.

The retained classification totals are 93 `performance_eligible`, 30
`expected_equivalent`, 40 `inactive_control`, and 13 `activation_missing`.
The remaining exclusions are retained training evidence; no new
activation-expected holdout was excluded.

The sealed holdout estimates were:

| Effect | Median | 95% blocked bootstrap interval | Classification |
| --- | ---: | ---: | --- |
| Batch B versus A | -1.63% | -4.49% to 2.59% | `uncertain` |
| Buffer C versus A | 2.12% | -2.40% to 3.34% | `uncertain` |
| Configured interaction | -2.89% | -6.67% to 1.86% | `uncertain` |
| Expected equivalence D versus B | 0.68% | -4.46% to 3.40% | `expected_equivalent` |

The only evaluated selector inputs were `legal_eligible_write_count` and
`source_segment_count`. The training-only candidate classified its three
labels, but held-out accuracy was 2/3. No main effect or interaction cleared
the predeclared practical and confidence gates. The canonical outcome is
therefore `measurement_completed_no_stable_rule`; no selector or runtime rule
was emitted.

The deterministic projection content hash is
`578067eca23c8af10c4560f2ef265a8c64a1beeb9f15be125c3e984df2008c7e`.
The deterministic analysis content hash is
`c558895ea812fe99d2df9dca5930aca40468b17f6c198a36510bbc436bfb49a2`.

---
title: "Adaptive Runtime Send-Composition Holdout Extension"
---

# Adaptive Runtime Send-Composition Holdout Extension

Status: predeclared bounded follow-on to
`measurement_completed_more_context_required`

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

## Predeclared holdout contexts

| Workload ID | Family | Scenario | Payload | Concurrency | Expected activation |
| --- | --- | --- | ---: | ---: | --- |
| `holdout_segment_rich_medium` | segment-rich writes | upload | 12,288 | 10 | batch and upstream buffer |
| `holdout_many_stream_medium` | many-stream saturation | upload | 32,768 | 12 | batch and upstream buffer |
| `holdout_copy_pressure_upload` | copy/memory pressure | upload | 49,152 | 20 | batch and upstream buffer |
| `inactive_control` | inactive control | upload | 2,048 | 1 | none |

These points are not exact duplicates of the training points. Their names and
families remain offline provenance and cannot become runtime selector inputs.
Only activation evidence may be inspected during the preflight. Performance
outcomes remain sealed until all predeclared holdout cells finish and validate.

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

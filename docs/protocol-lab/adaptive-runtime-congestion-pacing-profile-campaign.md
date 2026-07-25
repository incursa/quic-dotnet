---
title: "Adaptive Runtime Congestion and Pacing Profile Campaign Contract"
---

# Adaptive Runtime Congestion and Pacing Profile Campaign Contract

Status: contract ready; execution frozen

This contract is preparation only. It does not authorize a campaign,
performance measurement, threshold derivation, or activation.

## Treatments

Each counterfactual cell forces exactly one
`congestion_pacing_profile` value:

- `legacy_current`;
- `cubic`.

All adjacent axes, including `receive_credit_publication`, remain applied as
`legacy_current`. Observe-only and shadow cells apply legacy. Shadow
recommendation is research-only and must not change the controller.

## Required correctness preflight

Before any performance cell, a focused committed-source smoke must prove:

- exact forced, selected, applied, controller, reason, and binary identity;
- one immutable construction decision in every unified epoch;
- stable identity across path reset and migration;
- force-legacy parity with the default NewReno runtime;
- one and only one behavior-distinct forced axis;
- loss, PTO, ECN, anti-amplification, recovery, pacing, flow-control, packet,
  ownership, cancellation, disposal, close, and shutdown correctness;
- schema-valid v13 raw evidence and v14 manifest with exact checksums.

Any failure is retained as `failed_correctness`; it is never rerun away.

## Later main-effect design

After the user releases the measurement freeze, use round-robin ABBA/BAAB
treatment order and host rotation. Screen the one-axis main effect across
bounded network regimes covering clean path, controlled loss, reordering,
delay, bandwidth limits, ECN, PTO pressure, and validated migration. Include
reference-flow competition so fairness and recovery are outcomes rather than
throughput-only claims.

Record exact target and generator physical hosts, VMs, architectures, CPU,
memory, OS, timer frequency, network path, peer implementation, repository
commit, binary hash, tool versions, requested/effective workload, and health.
Do not pool unmatched host or network regimes.

## Eligibility and analysis

Correctness and progress dominate latency, fairness, memory, recovery/loss,
and throughput/CPU. A throughput winner violating any higher guardrail is
ineligible. Raw, normalized, curated, excluded, invalid, negative, and failed
rows remain append-only.

No model training may begin without complete host-fingerprint and
workload-family holdouts and no connection, run, repetition, or binary
leakage. At least three independent host fingerprints are expected for a
normal split. Any eventual runtime proposal must be reviewed deterministic
integer/fixed-point code or an immutable rule table; no model file enters the
runtime.

## Completion criteria

A later campaign is complete only when forced identity joins applied identity,
all adjacent axes remain legacy, host/workload holdouts are honest, network
safety and fairness outcomes are reviewed, negative evidence is retained, and
force-legacy rollback is reproven. The result may recommend remaining
`legacy_current`; it cannot authorize active behavior.

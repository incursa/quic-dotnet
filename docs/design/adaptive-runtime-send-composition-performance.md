---
title: "Adaptive Runtime Send-Composition Offline Performance"
---

# Adaptive Runtime Send-Composition Offline Performance

Status: implemented bounded offline measurement authority; production
activation remains unauthorized

This checkpoint releases measurement only for the reviewed
`send_composition` family. It does not release `active_internal`, performance
acceptance, public configuration, or automatic policy actuation.

## Configured and effective cells

| Cell | Batch | Buffer | Expected primary effective signature |
| --- | --- | --- | --- |
| A | `legacy_current` | `legacy_current` | legal batch prefix; exact combined prefix |
| B | `single_eligible` | `legacy_current` | single eligible prefix; buffer inactive |
| C | `legacy_current` | `memory_conservative` | legal batch prefix; two-source cap where reachable |
| D | `single_eligible` | `memory_conservative` | single eligible prefix; buffer inactive |

The production scheduler selects the batch prefix before it considers combined
buffer construction. `single_eligible` supplies one selected write. Combined
buffer construction requires more than one selected write. Consequently, D
cannot apply the buffer two-source cap on the same send opportunity and is
expected-equivalent to B at the primary mechanism layer. The campaign retains
all four configured cells and tests that equivalence. It does not label D as a
both-distinct performance treatment.

## Authorization boundary

The offline runner creates an internal fixed-field authorization bound to:

- campaign and manifest content hash;
- exact cell ID and enum values;
- both reviewed single-axis proof hashes;
- the passed correctness interaction review;
- false active behavior authorization;
- false performance acceptance authorization; and
- offline measurement purpose.

The token is unavailable through public connection options. Missing, stale, or
mismatched fields deny the D cell before runtime configuration. Existing
single-axis paths remain valid.

## Measurement design

The campaign is serial and block-randomized. A committed canonical definition
owns the seed, warmup, duration, repetitions, workload contexts, activation
gates, practical thresholds, train/holdout split, retention, and early-stop
rules. The runner freezes source and binaries and records host and runtime
identity before executing.

The custom loopback harness uses actual `QuicConnection` instances and the
production scheduler, batch policy, buffer policy, buffer owner, and terminal
release seams. Thread-safe bounded sinks capture mechanism counts and bytes.
The harness does not retain an unbounded operation stream.

Every completed run is one of:

- `performance_eligible`;
- `expected_equivalent`;
- `inactive_control`;
- `activation_missing`; or
- `failed_correctness`.

Identity and environment mismatches fail validation before analysis and remain
in command and validation logs. All completed runs remain in immutable raw
evidence. Only performance-eligible or explicit expected-equivalent runs can
support the corresponding conclusion.

## Analysis and selection boundary

The predeclared practical gate is a median useful-goodput improvement of at
least three percent with a 95 percent blocked bootstrap interval excluding
zero, no more than five percent P95 latency regression, no fairness regression
below 0.98, no correctness or ownership failure, and required mechanism
activation.

Training and holdout workload contexts are fixed before final execution.
Candidate selector inputs are limited to bounded runtime observations such as
legal eligible count and bytes, source-segment count, queue depth, retained
bytes, backpressure, and recent mechanism rates. Workload name, scenario,
requested concurrency, host, peer, URL, and application identity are excluded.

If training evidence does not support a compact rule, or held-out validation
fails, the milestone records `no_stable_rule` or `more_context_required`.
There is no speculative selector. A justified selector remains shadow-only:
its recommendation cannot change configured or applied behavior.

## Evidence authority

The authority chain is:

```text
committed campaign definition
  -> exact source and binary identity
  -> host fingerprint
  -> immutable raw run documents and logs
  -> checksum inventory and classifications
  -> catalog-derived behavior and outcome aggregates
  -> deterministic projection and compact analysis
  -> frozen selector or no-rule decision
  -> untouched holdout validation
```

Large raw output stays outside Git. Schemas, scripts, compact summaries,
traceability, and the final review package are committed.

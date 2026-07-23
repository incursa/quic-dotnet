---
title: "Adaptive Runtime Policy Evidence Review Checkpoint - 2026-07-23"
---

# Adaptive Runtime Policy Evidence Review Checkpoint - 2026-07-23

Status: `receive_credit_publication` review checkpoint; non-promoting;
`active_internal` blocked

## Scope and authority

This is an append-only review checkpoint for the user-approved
[`Adaptive Runtime Policy Axis Roadmap`](../design/adaptive-runtime-policy-axis-roadmap.md).
It reconciles the roadmap with the implemented receive-credit shadow
foundation, permanent campaign tooling, retained evidence, and stream-capacity
correctness closure at `8b0ee750821f815e59ffcac37dc11ada8d6e25b5`.

It does not activate a policy, modify a selector, reinterpret an excluded
row, or authorize the next send-path axis. `legacy_current` remains the
applied behavior. Forced modes bypass selection only and retain all existing
correctness guards.

The associated trace homes remain `REQ-QUIC-CRT-0164` through
`REQ-QUIC-CRT-0172`, `ARC-QUIC-CRT-0059`, `ARC-QUIC-CRT-0062`,
`WI-QUIC-CRT-0060`, `WI-QUIC-CRT-0063`, `VER-QUIC-CRT-0061`, and
`VER-QUIC-CRT-0064`.

## Current execution map

| Item | Decision |
| --- | --- |
| Active axis | `receive_credit_publication`, evidence-review only |
| First incomplete gate | Complete a reviewed, leakage-resistant offline cohort decision; the current corpus is not a rule or activation gate |
| Next portfolio axis | `application_send_turn_planning`, only after this axis has a reviewed non-promoting or shadow-only decision |
| Frozen adjacent axes | `application_send_turn_planning`, `application_send_batch_formation`, `queued_send_burst_budget`, and `oversized_write_admission_quantum` stay `legacy_current` / inventory-only |
| Prohibited paths | `active_internal`, selector widening, stress expansion, online learning, runtime model use, production exploration, and threshold tuning |

## Checkpoint classification ledger

| Candidate or evidence set | Classification | Preserved disposition |
| --- | --- | --- |
| Sticky read-dominant receive-credit selector at `1b2611e1` | accepted legacy behavior | Remains the exact `legacy_current` authority and rollback target; it is not widened or silently moved under a new controller |
| Oversized-write bounded selector | accepted, separate axis | Preserved as a distinct logical-operation policy; not combined with receive-credit evidence |
| Universal, duplex-reactivating, non-sticky, and lock-based receive-credit variants | retained negative | Remain excluded from implementation inputs and visible in the planning/evidence records |
| x4/s16 stream-capacity failures before `ac20fd67` | failed correctness / diagnostic root-cause evidence | Remain retained; the lost-wakeup correction is a liveness fix, not a receive-credit policy result |
| Instrumented stream-capacity confirmation with excess within-treatment range | invalid environment | Retained outside policy-effect claims |
| Pre-counter ARM64 guardrail | invalid contract | Retained provisioning evidence; the later counter-qualified rows do not replace it |
| Bounded high-count extension | stress only | Retained outside the normal acceptance envelope |
| Remote rows with buffer regression or saturation | retained negative | Kept in curated evidence with their original rejection reasons |

## Correctness and implementation confirmation

The connection-local observation, deterministic shadow replay, internal forced
modes, versioned snapshots, epoch export, permanent local runners, dataset
pipeline, and append-only provenance validation are implemented. The shadow
path applies `legacy_current` and records only the recommendation. It has no
consumer that can activate policy behavior.

The stream-capacity wakeup fix at `ac20fd67` is separately preserved. The
append-only record shows that the former x4 boundary passed eight of eight
normal-instrumentation samples across two physical hosts after the correction;
the range classifications remain unchanged.

Current local verification was rerun from the clean worktree at `8b0ee750`:

- `dotnet build src/Incursa.Quic/Incursa.Quic.csproj -c Release --nologo`
  passed with zero warnings and zero errors.
- The `REQ-QUIC-CRT-0164` through `REQ-QUIC-CRT-0169` requirement-home filter
  passed 46 of 46 tests.
- The focused stream-capacity, MAX_STREAMS, congestion-retry, and wakeup test
  band passed 64 of 64 tests.
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release
  --no-restore --nologo --logger "console;verbosity=minimal"` passed 9,780
  tests with four expected skips and zero failures in 12 minutes 43 seconds.

BenchmarkDotNet results are retained in
[`adaptive-runtime-policy-shadow-foundation-evidence-2026-07-21.md`](adaptive-runtime-policy-shadow-foundation-evidence-2026-07-21.md): the
existing observation and shadow mechanism cases reported no managed allocation.
Those microbenchmarks establish local mechanism cost only, not a policy rule.

## Evidence and dataset state

The remote round-robin materialization retained 20 result documents and
82,753 joined epoch rows: 40,478 `invalid_environment`, 4,260
`failed_correctness`, 18,728 `neutral_local`, and 19,287
`negative_retained`. Default curation includes 25,981 rows and excludes 56,772
without deleting the excluded evidence.

The prior two-host materialization correctly reported
`insufficient_group_diversity` and assigned all 82,753 rows
`holdout_blocked`. Later counter-qualified runs establish three host
fingerprints, but the complete host and workload holdout rule is still not
automatically satisfied because workload families overlap between hosts. The
documented seed-17 non-overlapping review cohort is:

| Host | Held-out workload family | Status |
| --- | --- | --- |
| Debian ARM64 | `duplex-64kb-x4-s16` | `neutral_local`, 2,215 epoch rows |
| x64-02 | `multiplex-1kb-x1-s100` | `neutral_local`, 557 epoch rows |
| x64-03 | `upload-1mb-x1-s1` | Existing contract-complete remote cohort |

This is a review cohort, not an automatically eligible model split. No model,
rule table, or runtime input is derived from it here. Missing outcomes,
environment-invalid rows, failed-correctness rows, warmup, saturation, and
partial-terminal exclusions remain explicit and queryable.

## Required next review decision

Review the non-overlapping cohort against the dataset provenance contract and
record one of these outcomes before collecting or implementing anything else:

1. `remain_legacy_current` because the cohort cannot support a safe
   deterministic proposal;
2. `continue_evidence_generation` with one exactly scoped host/workload cell
   under the existing forced-policy and epoch contract; or
3. `accept_shadow_only` with a separately reviewed deterministic proposal.

No evidence currently authorizes `active_internal`. If the cohort is
insufficient, the next collection must preserve the current binary cohort,
round-robin order, and frozen adjacent axes; it must not sample until a desired
outcome appears.

## Evidence locations

- `docs/testing/adaptive-runtime-policy-local-campaign-evidence-2026-07-22.md`
  records local, x64, ARM64, correctness, stress-only, and dataset outcomes.
- `docs/testing/adaptive-runtime-policy-shadow-foundation-evidence-2026-07-21.md`
  records the shadow foundation and BenchmarkDotNet mechanism costs.
- `docs/testing/adaptive-runtime-policy-offline-dataset-quality-2026-07-22.md`
  records the earlier local materialization and split block.
- `eng/adaptive-runtime/` contains the permanent schedule, local-cell,
  evidence-validation, catalog, and append-only dataset pipeline commands.

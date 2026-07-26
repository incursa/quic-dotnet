---
title: "Adaptive Runtime Experiment-Control Hardening Review - 2026-07-25"
---

# Adaptive Runtime Experiment-Control Hardening Review - 2026-07-25

Status: bounded correctness-only hardening complete; measurement, CI, push,
`active_internal`, production activation, another-axis migration, and runtime
mechanism changes remain unauthorized.

## 1. Recovery

Work began from committed `c7076b191f6f0b3f3d3ee94b477746fc286f4144` in
`C:\shared\src\incursa\.worktrees\quic-experiment-hardening-20260725` on
`codex/adaptive-runtime-experiment-hardening-20260725`. The dirty primary
worktree and the older staged runtime-evidence worktree were not changed.

## 2. Four original confirmed issues

All four are corrected:

1. behavior derives from exact v2 catalog mechanism rules, not a second map;
2. warnings derive from evidence and linked plan-validation content;
3. decisions and operations reconcile every configured-through-applied field;
4. epoch, release, classification identity, target, ordering, retention, and
   contradiction rules validate before materialization.

## 3. Six design decisions

The canonical decision is
[`adaptive-runtime-experiment-control-hardening.md`](../design/adaptive-runtime-experiment-control-hardening.md).
It records catalog authority, content-derived warnings, independent outcome
aggregates, set-valued expected behavior, expanded relationship/family
semantics, reviewed interaction proof, and immutable-input projection.

## 4. Canonical ownership

Axis contracts own seam authority and safety. Effective-behavior catalog v2
owns exact mechanism derivation and value behavior sets. Relationship graph v2
owns directed axis/behavior topology. Combination constraints own legality.
Family catalog v2 owns membership, fixed axes, contexts, workloads, metrics,
guardrails, and proof readiness. Source plans own treatment intent. Raw
evidence owns actual decisions and mechanisms. Behavior and outcome
materializations own their separate aggregates. Projection owns rebuildable
joins only.

## 5. V1/V2 compatibility

No v1 schema, catalog, fixture, expected output, or retained evidence was
deleted or relabeled. V2 is used when semantics changed incompatibly. The v1
policy-catalog generator remains a historical compatibility producer.

## 6. Corrected behavior authority

`Resolve-AdaptiveRuntimeEffectiveBehavior` matches axis, exact mechanism event,
operation kind, and scope version. Zero matches are explicit; multiple
non-composable matches are ambiguous. A test changes only a catalog behavior
ID and proves derivation changes without changing evidence.

## 7. Warning derivation

The four warning families are computed from aggregates, retained operation
classifications, and the linked validation classification. A renamed duplicate
produces identical warnings; a suggestive filename without matching content
does not.

## 8. Decision/operation reconciliation

The validator compares run, connection, epoch, axis, decision ID, configured,
forced, shadow, candidate, eligibility, reason, and applied value. Forced input
cannot bypass eligibility, and shadow cannot alter applied behavior.

## 9. Epoch, release, and classification joins

Top, result, decision, operation, and release epochs must exist. Epoch and
classification IDs are unique. Release cannot precede decision. Classification
targets must exist, contradictions fail, and inactive/fallback/clamped/invalid/
negative/unclassifiable operations retain matching target-aware classification.

## 10. Behavior and outcome accounting

Effective behaviors are catalog-derived mechanisms. Inactive, fallback,
clamped, invalid, negative, error, unclassifiable, diagnostic, and terminal
release results are separate outcome aggregates. Operations may contribute to
one behavior and one applicable outcome kind, but never twice within one kind.

## 11. Expected-behavior sets and equivalence

Plan-validation v2 records primary expected behaviors, all possible effective
behaviors, non-behavior outcomes, and activation signatures. Equivalence uses
primary behavior plus activation signature. Shared fallback outcomes do not
collapse distinct treatments.

## 12. Send-planning equivalence

`legacy_current` and `conservative` remain two configured cells and one
expected effective cell, classified `verification_only`. No performance
comparison is authorized.

## 13. Relationship graph v2

The closed taxonomy is `authority_overlap`, `structural_constraint`,
`supplies_work`, `changes_observed_state`, `feedback_loop`,
`shared_outcome_only`, and `context_effect`. Edges declare explicit axis or
behavior node kinds. The first canonical edge is the batch-to-buffer
`supplies_work` relation.

## 14. Experiment-family v2

The catalog separates included axes, fixed-axis requirements, outer contexts,
workload archetypes, primary metrics, guardrails, predicates, relationships,
constraints, history resets, and actuation-proof references. `contexts` is no
longer overloaded as axis membership.

## 15. Interaction actuation proof

Each forced varied axis/value in an interaction requires one family-referenced,
reviewed, passed proof at version 1. No proof record was invented. The current
interaction emits two `interaction_actuation_proof_missing` warnings and is
`blocked_for_measurement`.

## 16. General projection builder

`New-AdaptiveRuntimeExperimentEvidenceProjection.ps1` requires fifteen
explicit immutable paths. It checks root hashes, plan/validation/manifest/
evidence/materialization references, authorization, epoch joins,
classification targets, and aggregate identities. It contains no fixed fixture
paths or placeholder authority hashes.

## 17. Schemas and catalogs

Evolved schemas cover behavior catalog v2, relationship graph v2, family
catalog v2, plan validation v2, operation evidence v2, behavior
materialization v2, operation outcome materialization v1, and projection v2.
The three canonical planning catalogs validate and hash against the same tree.

## 18. Fixtures

The hardening corpus contains 9 valid evidence fixtures, 6 warning fixtures,
20 expected-invalid evidence fixtures, 5 expected-invalid projection fixtures,
2 linked validations, explicit projection inputs, and checked-in behavior,
outcome, and projection outputs.

## 19. Determinism

Fifteen behavior/outcome materialization pairs reproduce byte-for-byte.
Projection rebuild reproduces the checked-in canonical bytes and SHA-256
`58cc760c76300060a1e73b130cfb78f3ff6193bb796278b0d02eccee1678bf12`.

## 20. Verification

Focused commands:

```powershell
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentControl.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentPlanCompiler.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentHardening.ps1
dotnet build .\src\Incursa.Quic\Incursa.Quic.csproj -c Release
dotnet build .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release
dotnet test .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build --filter "REQ_QUIC_CRT_0210|REQ_QUIC_CRT_0211|REQ_QUIC_CRT_0212|REQ_QUIC_CRT_0213"
```

The foundation remained 8 schemas, 5 canonical documents, 12 valid, and 15
invalid. Compiler regression remained 7 valid, 5 warning, 21 invalid plans,
and 6 invalid manifest/link cases. Runtime evidence remained 3 schemas, 16
valid, 5 warning, and 24 invalid. Hardening passed 8 schemas, 3 canonical
catalogs, 9 valid, 6 warning, 20 invalid evidence, and 5 invalid projection
fixtures.

Direct model-schema validation passed for the touched specification,
architecture, work-item, and verification artifacts. The repository-wide
`Validate-SpecTraceJson.ps1 -Profiles core` command remained red with 2,693
pre-existing/sparse-checkout schema and unresolved-reference errors across
unrelated families; the failure was preserved and no unrelated trace artifact
was repaired in this checkpoint.

## 21. Traceability and commits

Requirements `REQ-QUIC-CRT-0210` through `0213` trace through
`ARC-QUIC-CRT-0098`, `WI-QUIC-CRT-0099`, and `VER-QUIC-CRT-0100`.
Checkpoint commits through fixture completion are:

- `0160de62` reproduce defects;
- `8d722667` record decisions;
- `5268cee4` harden v1 catalog warnings and joins;
- `6d559ab8` add v2 planning catalogs;
- `03cb120c` compile set-valued behavior signatures;
- `13353f0c` require interaction actuation proof;
- `a7036926` add hardened evidence and materialization;
- `f5918867` add projection and hardening regression;
- `2d3a8749` add the generated fixture corpus.

## 22. Stop boundary and next action

No runtime mechanism changed, no axis was migrated, no performance or
ProtocolLab campaign ran, no dataset transform or ML work ran, CI was not
touched, nothing was pushed, and active behavior remains unauthorized. The
recommended next action is external review of this hardening package before a
separately approved correctness-only interaction execution or another-axis
migration.

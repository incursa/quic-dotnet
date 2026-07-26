---
title: "Independent Adaptive-Runtime Actuation-Proof Candidate Review Package"
---

# Independent Adaptive-Runtime Actuation-Proof Candidate Review Package

Status: correctness-only candidate evidence complete; external review pending.
Measurement, interaction execution, active behavior, CI changes, and push
remain unauthorized.

## 1. Recovery And Isolation

This checkpoint was created directly from
`b56545913569dc8d9caf08656a654ac4b6e077b6` in:

```text
branch: codex/adaptive-runtime-independent-actuation-proof-20260726
worktree: C:\shared\src\incursa\.worktrees\quic-independent-actuation-proof-20260726
```

The dirty primary worktree and every prior linked worktree were inspected and
left unchanged. No reset, clean, stash, unstage, merge, repair, CI mutation, or
push occurred. No campaign or transform process was used.

## 2. Release-Identity Correction

Commit `35c9c9bd` changes the offline v3 evidence validator so its first release
lookup uses the complete `operation_identity_v1`:

```text
run_id
+ connection_key
+ operation_epoch_sequence
+ axis_id
+ decision_instance_id
+ operation_id
```

Only after exactly one operation resolves does validation resolve the linked
decision and verify the copied decision epoch, release epoch existence,
ordering, and exactly-once terminal release. Two operations may therefore
reuse a numeric operation ID under different decision IDs without collision.
The evidence-integrity regression reports
`complete_release_identity_reuse_cases = 2`. A mismatched decision and a
forged copied decision epoch fail deterministically.

## 3. Live Correctness-Evidence Bridge

The focused harness in `REQ-QUIC-CRT-0219.cs` calls the existing production
batch and buffer policy evidence seams. It records the production evidence
structs and buffer lifetime-token release observations; it does not construct
mechanism facts from expected fixture values.

`New-AdaptiveRuntimeIndependentActuationProof.ps1` is reusable offline tooling
for either independent axis. It validates the capture, source plan,
plan-validation result, manifest, binary hash, host identity, and catalog;
enforces exactly one varied and forced behavior-distinct axis; resolves
mechanism event IDs; assembles the immutable evidence chain; recomputes both
materializations; and rebuilds projection v3 twice.

The bridge adds no runtime catalog lookup, hot-path dictionary, boxing, global
lock, unbounded retention, generic runtime profile, scheduling change,
buffering change, packetization change, or ownership change.

## 4. Batch Candidate Proof

Candidate:

```text
axis: application_send_batch_formation
value: single_eligible
review_status: candidate
review_outcome: null
```

The five captured operations prove:

- positive activation with more than one legal eligible write;
- pre-safety candidate and applied value `single_eligible`;
- operation eligibility under authoritative guards;
- runtime event `mechanism_event.batch_single_eligible`;
- one selected write from the legal prefix, without widening or reordering;
- priority and same-stream sequence preservation;
- one-write structural inactivity retained;
- an ineligible forced candidate replaced by the safe legacy mechanism;
- a behavior-distinct shadow recommendation with legacy applied behavior;
- rollback to `legacy_current` with the exact legal prefix.

The materializer derives five operation behavior aggregates and two applicable
outcome aggregates. No performance observation is used.

## 5. Buffer Candidate Proof

Candidate:

```text
axis: buffer_copy_coalescing
value: memory_conservative
review_status: candidate
review_outcome: null
```

The five captured operations prove:

- positive activation with more than two legal source segments;
- pre-safety candidate and applied value `memory_conservative`;
- operation eligibility under authoritative guards;
- runtime event `mechanism_event.buffer_two_source_cap`;
- exactly two applied source segments from the legal prefix;
- owner rent after the policy decision;
- complete decision and operation identity through the owner token;
- one exact terminal release for each materialized owner;
- inactive/no-owner, safe replacement, shadow-neutral, and rollback paths;
- cancellation or disposal terminal ownership safety;
- rollback to the exact legacy prefix.

Five exact terminal releases join to the five buffer operations. The
materializer derives five operation behavior aggregates and two applicable
outcome aggregates.

## 6. Activation, Fallback, Shadow, And Rollback Matrix

| Axis | Positive | Inactive | Forced fallback | Shadow neutrality | Rollback |
| --- | --- | --- | --- | --- | --- |
| batch formation | more than one legal write; shortened to one | one legal write | terminal guard retains legacy prefix | recommendation is non-actuating | exact legal legacy prefix |
| buffer coalescing | more than two legal segments; capped to two | no-owner/within-cap path | stale-input guard retains exact legacy prefix | recommendation is non-actuating | exact legal legacy prefix and terminal release |

Each row is backed by a distinct captured operation identity. At most one
behavior-distinct axis is forced in each capture.

## 7. Owner-Release Proof

Every buffer operation that materializes a combined owner has exactly one
terminal release. Release identity includes run, connection, operation epoch,
axis, decision instance, and operation ID. Release epoch exists and does not
precede decision/owner creation. Missing, duplicate, wrong-decision, and
forged-order releases are expected-invalid cases.

## 8. Immutable Authority Chain

Each candidate projection validates these 15 explicit immutable inputs:

| Input | Identity/link proof |
| --- | --- |
| experiment plan | exact source plan hash |
| plan validation | exact validated-plan reference |
| compiled manifest | exact plan and validation references |
| experiment run | manifest and run identity |
| host fingerprint | manifest resolved host |
| binary cohort | manifest binary path and SHA-256 |
| workload instance | exact run |
| requested workload shape | exact workload instance |
| effective workload shape | exact workload instance |
| operation evidence v3 | run, binary, connection, decision, operation, release |
| behavior materialization v3 | exact evidence and catalog |
| outcome materialization v2 | exact evidence, catalog, and classifications |
| correctness metric observations | real run and epoch; no performance metrics |
| artifact inventory | hashes for every immutable input |
| classification set | exact composite evidence targets |

Projection construction recomputes behavior and outcome materializations before
acceptance. Repeated builds are canonical-byte and hash identical.

## 9. Materialization And Projection Hashes

| Artifact | Batch | Buffer |
| --- | --- | --- |
| mechanism capture | `e067e89c584a34b50d9983010da86bcc29575f88e08ec094259e2cfa006a3fc0` | `34cd7c85cf9ea6a0c04787c6706fcc7f5ad915aedf8aed49734211f7254faaf8` |
| operation evidence | `76f42043918cf99d41dfa97d50083b028c27dc460e0494979281116bfc50f3c7` | `fe5626f5bcb543eae612289ddaee171a9e3d9f8116e1278344bb0629b24cb2b9` |
| behavior materialization | `6a2cbafc27ee98e833c3c73b5d308da2e17dcf39d3a317a132e48841df52052a` | `bd6b17696d4c1e4efb3eb768ea076b210159fca9703aa3a7c4bf4a0ed7688ed7` |
| outcome materialization | `b55c03a4e82717868dcae6227db06127c0e5dabff9c052d43990e9d042dd9c3e` | `55bff657b1b8f3590c4ad4dd362f03d7fab9f6bf9cef105139b1f45449a5fa26` |
| analytical projection | `e1c2e7144a2e1f55e65c294268967ede7e111469345f68be3be2e435aed25712` | `7e925302bf5ad341359abaab1ed994f0563c5cbc273c1caa53a18a6b01982ea5` |
| proof candidate | `9b8930dfe177f028bae00ea61e1f23389f77a2f4cce5c624d5838c7318a1b5e1` | `8830a37735e7cb8cd361dacfc69da9824dfe6916e29686192a46ea144d4d1760` |

Both manifests use source commit
`cc1aaaf06cf31010f5039416d287e2c06b89f905`, binary SHA-256
`70ba4f61700199d2193ce3c952e8fdb38bd704c030dfbc99748564a182521916`,
and host fingerprint `host.0080d5b929520780449ad8cd`.

## 10. Fixtures And Closed Negative Results

The checked-in candidate corpus contains:

- 36 schema- and content-hash-validated immutable documents;
- two candidate proof documents;
- 10 captured operation records;
- five exact release records;
- two deterministic 15-input projections;
- 17 expected-negative cases using 14 unique closed codes.

Negative coverage includes activation not reached, positive operation
ineligible, wrong mechanism event, missing decision, missing operation,
missing release, duplicate release, stale catalog, stale manifest, stale
binary, wrong run, wrong connection, inactive operation claimed as positive,
performance metric used as proof, reviewed self-classification, passed
self-classification, and two behavior-distinct axes forced simultaneously.
The last case fails in offline validation before any runtime execution.

## 11. Correctness Commands And Results

The following commands ran from the isolated worktree:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentPlanCompiler.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentHardening.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentEvidenceIntegrityCloseout.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeIndependentActuationProof.ps1
dotnet build src/Incursa.Quic/Incursa.Quic.csproj -c Release --no-restore
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --filter "FullyQualifiedName~REQ_QUIC_CRT_0219|FullyQualifiedName~REQ_QUIC_CRT_0222"
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --filter "FullyQualifiedName~REQ_QUIC_CRT_0190|FullyQualifiedName~REQ_QUIC_CRT_0206"
```

Results:

- foundation: 8 schemas, 5 canonical documents, 12 valid fixtures, and
  15 expected-invalid fixtures clean;
- compiler/manifest: 7 valid plans, 5 warning plans, 21 invalid plans, and
  6 invalid validation/manifest documents clean;
- runtime evidence: 3 schemas, 16 valid, 5 warning, and 24 invalid fixtures
  clean;
- hardening: 8 schemas, 3 catalogs, 9 valid, 6 warning, and 20 invalid fixtures
  clean; interaction remains `blocked_for_measurement`;
- evidence-integrity closeout: 6 schemas, all 15 immutable inputs, 9 catalog
  outcome mappings, 10 invalid evidence, 8 invalid classifications, all
  66 classification pairs, and 7 invalid projections clean;
- independent proof: 36 documents, 2 candidates, 10 operations, 5 releases,
  and 17 expected-negative cases clean;
- both Release builds: 0 warnings and 0 errors;
- new proof requirement homes: 2 of 2 passed;
- focused batch/buffer mechanism and ownership band: 25 of 25 passed.

No benchmark, performance campaign, ProtocolLab campaign, interaction
workload, large matrix, transform, normalization, curation, split generation,
threshold derivation, or ML work ran.

## 12. Traceability

The checkpoint is allocated without inventing IDs:

- requirements `REQ-QUIC-CRT-0218` through `REQ-QUIC-CRT-0222`;
- architecture `ARC-QUIC-CRT-0104`;
- work item `WI-QUIC-CRT-0105`;
- verification `VER-QUIC-CRT-0106`;
- focused tests `REQ-QUIC-CRT-0219.cs` and `REQ-QUIC-CRT-0222.cs`.

The four touched SpecTrace JSON documents validate directly against
`model/model.schema.json`. The unrelated repository-wide SpecTrace baseline is
not changed or repaired by this checkpoint. The repository-wide command
preserved its existing failure with 2,693 errors; the touched specification,
architecture, work item, and verification artifacts are not among the direct
schema failures.

## 13. Local Commits

```text
aeaf0584 docs: allocate independent actuation proof checkpoint
35c9c9bd fix: resolve releases by complete operation identity
fca9615a feat: add independent actuation proof contracts
cc1aaaf0 feat: add live correctness evidence bridge
64c860a4 test: add batch actuation proof candidate
1e2aad3f test: add buffer actuation proof candidate
1a1f8f4f test: validate independent actuation proof candidates
```

The documentation/trace closeout is the commit containing this review package;
its hash is intentionally not embedded in its own content.

## 14. Worktree And Push State

The checkpoint ends in its dedicated linked worktree. No existing worktree was
mutated, no remote ref was changed, and nothing was pushed.

## 15. Remaining Capability Blocker

The runtime remains limited to one behavior-distinct forced axis. The
canonical v2 family catalog still has no externally reviewed actuation-proof
records, so interaction execution and measurement release remain blocked.
The retained v1 actuation plans also fix the other send-composition axis;
current v2 family validation requires exact fixed-axis equality. This
checkpoint deliberately uses the retained v1 planning contract rather than
redesigning that family rule.

## 16. Unapplied Promotion Patch

`adaptive-runtime-independent-actuation-proof-promotion.json-patch` shows the
candidate metadata that external review could add to the canonical v2 family
catalog. It first tests the exact current catalog hash. It is not applied, and
its proposed `review_outcome = passed` values are not present in canonical
state. An external reviewer must decide whether to apply an updated patch and
recompute the catalog content hash.

## 17. Mandatory Boundary

Both records remain external-review candidates. Neither is reviewed or passed.
No multi-axis interaction ran. Performance measurement remains frozen.
`active_internal` and production policy behavior remain unauthorized. No
runtime policy mechanism changed, no other axis was migrated, CI was untouched,
and nothing was pushed.

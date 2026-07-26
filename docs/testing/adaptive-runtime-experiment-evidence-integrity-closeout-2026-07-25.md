# Adaptive-runtime experiment evidence-integrity closeout

Status: correctness-only closeout complete
Source checkpoint: `e6830c909b11f337d53421ec5e5c24d749eda1bb`
Runtime mechanisms changed: none
Measurement and active behavior: unauthorized

## Recovery and isolation

The dirty primary worktree at
`C:\shared\src\incursa\quic-dotnet` and every prior linked worktree were left
untouched. Work ran in the clean linked worktree:

```text
C:\shared\src\incursa\.worktrees\quic-experiment-evidence-integrity-closeout-20260725
```

on branch `codex/adaptive-runtime-evidence-integrity-closeout-20260725`, created
from the accepted hardening commit. The accepted commit was not silently
merged into the primary worktree, and nothing was pushed.

## Additive contract decisions

Existing v1 and v2 schemas and documents keep their original meaning. The
closeout adds:

| Contract | Version | Purpose |
| --- | --- | --- |
| operation evidence | v3 | Exact decisions, operations, releases, and classification reference |
| behavior materialization | v3 | Composite aggregate source identities |
| outcome materialization | v2 | Catalog-owned outcome and retention derivation |
| experiment evidence projection | v3 | Complete fifteen-input authority chain |
| classification compatibility catalog | v1 | Closed roles, outcome mappings, and compatible pairs |
| projection immutable input | v1 | Strict schemas for the seven supporting input document kinds |

The architectural decision is
`docs/design/adaptive-runtime-experiment-evidence-integrity-closeout.md`.

## Outcome catalog derivation proof

`Resolve-AdaptiveRuntimeOperationOutcome` compares `operation.result` with
every `result_kinds` entry in the exact referenced effective-behavior catalog.
One match supplies both `outcome_id` and
`requires_retained_classification`; zero and multiple matches fail with
`outcome_derivation_no_match` and `outcome_derivation_ambiguous`.

The fixture corpus covers all nine mappings. A catalog-only fixture swaps the
inactive and fallback mappings while keeping evidence and source code
unchanged, and the materialized outcome changes accordingly. The v2 catalog
schema requires retention to be true, so a no-retention definition is
deliberately schema-invalid rather than silently accepted. Successful
mechanism results remain behavior-only and do not fabricate a non-behavior
outcome aggregate.

## Release correlation proof

Each release resolves exactly one operation using run, connection, axis, and
operation epoch and operation ID, then verifies the linked decision identity.
Ordering uses the linked decision's actual epoch, never the release's copied
assertion. The corpus proves deterministic failures for:

- `release_operation_identity_mismatch`;
- `release_decision_identity_mismatch`;
- `release_decision_epoch_mismatch`;
- `release_epoch_missing`;
- `release_precedes_decision`;
- `duplicate_owner_release`; and
- `missing_terminal_release_evidence`.

The forged-epoch fixture changes only the copied release decision epoch and
still fails, proving the assertion cannot bypass ordering authority.

## Classification identity and compatibility

Classification targets are structured identities for operation, release,
epoch, or artifact targets. Exact operation targets include run, connection,
epoch, axis, decision, and operation. Missing targets fail
`classification_target_missing`; duplicate exact evidence targets fail
`classification_target_ambiguous`; legacy scalar targets remain invalid under
the new schema and are not reinterpreted.

The classification-compatibility catalog is the sole owner of definition
roles and pairwise rules. The regression generates all 66 unordered pairs of
the 12 closed classification kinds. Unlisted same-target pairs fail
`classification_contradiction`. Supplemental `diagnostic_context` may
accompany a primary classification but cannot satisfy a required retained
outcome.

## Composite operation accounting

Operation identity v1 is:

```text
run_id + connection_key + epoch_sequence + axis_id
       + decision_instance_id + operation_id
```

Canonical JSON for those components is SHA-256 hashed into a stable
`operation_identity_v1:` key. Structured components and the key travel
together through decisions, releases, classifications, materializations,
aggregate sources, accounting, and projection. Valid evidence deliberately
reuses numeric operation ID `1` across two axes and two connections; four
operations still produce four distinct keys.

An operation contributes at most once within each aggregate kind. A behavior
operation may also have one applicable non-behavior outcome without being
double-counted inside either kind. Catalog-declared composable behavior remains
supported.

## Projection authority chain

| Input | Schema and hash | Required join |
| --- | --- | --- |
| experiment plan | validated | plan-validation plan reference |
| plan validation | validated | source plan hash and identity |
| compiled manifest | validated | plan and validation references |
| experiment run | validated | manifest, host, and binary references |
| host fingerprint | validated | resolved manifest host identity |
| binary cohort | validated | commit, binary, and runner identity |
| workload instance | validated | experiment run |
| requested workload shape | validated | workload instance |
| effective workload shape | validated | workload instance |
| operation evidence | validated | run, binary cohort, validation, and catalog |
| behavior materialization | validated and recomputed | exact evidence and catalog |
| outcome materialization | validated and recomputed | exact evidence, catalog, and classifications |
| metric observations | validated | real run, connection, and epoch |
| artifact inventory | validated | exact hashes for the other fourteen inputs |
| classifications | validated | exact operation-evidence targets |

All fifteen immutable document references are emitted in the projection
authority chain. The builder accepts explicit paths only; it performs no
fixture discovery and has no placeholder identity or mutable database
authority. Self-hashed but unrelated host, binary, workload, metric,
materialization, classification, and inventory inputs are rejected.

## Deterministic aggregate and projection proof

The supplied behavior and outcome materializations are recomputed before
projection. Their canonical bytes, hashes, counts, byte/work totals, and
composite source identities must match exactly. Repeated closeout runs produce:

| Artifact | SHA-256 |
| --- | --- |
| behavior materialization v3 | `6b740d2847204eed394a666fa2c3460723f725c06ea7f7af78cd700d38a6eaf2` |
| outcome materialization v2 | `e1708e38e2281c80688f8e142f584e174a6295465a7077c7c25b4d6cd852b755` |
| projection v3 | `fdd5f135e3b0f384b66d0fcb638090fa940759dcb05f374aa9d5126c7b87a16f` |

## Fixtures and closed validation

The corpus contains 44 files: 18 valid, 25 invalid, and one expectation
catalog. The closeout regression validates:

| Classification | Count |
| --- | ---: |
| additive schemas | 6 |
| immutable projection inputs | 15 |
| result-to-outcome mappings | 9 |
| invalid evidence fixtures | 9 |
| invalid classification fixtures | 8 |
| generated pairwise compatibility cases | 66 |
| invalid projection substitutions | 7 |

Projection errors include schema, plan/validation/manifest, run/host/binary,
workload, metric/epoch, artifact-inventory, classification/evidence,
materialization/catalog, aggregate-source, and behavior/outcome recomputation
mismatches. Invalid documents remain retained fixtures.

## Verification results

```powershell
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentControl.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentPlanCompiler.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentHardening.ps1
.\eng\adaptive-runtime\Test-AdaptiveRuntimeExperimentEvidenceIntegrityCloseout.ps1
dotnet build .\src\Incursa.Quic\Incursa.Quic.csproj -c Release
dotnet build .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-restore -m:1 -p:UseSharedCompilation=false -nodeReuse:false
dotnet test .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --filter "REQ_QUIC_CRT_0214|REQ_QUIC_CRT_0215|REQ_QUIC_CRT_0216|REQ_QUIC_CRT_0217" -m:1
git diff --check
```

Results:

- foundation: 8 schemas, 5 canonical documents, 12 valid and 15 invalid;
- compiler/manifest: 7 valid, 5 warning, 21 invalid plans, and 6 invalid
  manifest/link cases;
- runtime evidence: 3 schemas, 16 valid, 5 warning, 24 invalid, and 16
  deterministic runs;
- hardening: 8 schemas, 3 catalogs, 9 valid, 6 warning, 20 invalid, and 15
  materializations;
- closeout: every count in the fixture table passed;
- `Incursa.Quic` Release build: zero warnings and zero errors;
- `Incursa.Quic.Tests` Release build: zero warnings and zero errors;
- focused requirement homes: 4 passed, zero failed, zero skipped;
- direct SpecTrace model validation: 4 of 4 touched artifacts valid;
- reciprocal trace check: all four requirements point to the architecture,
  work item, and verification, and each artifact points back to all four
  requirements;
- `git diff --check`: clean.

One retained diagnostic run loaded the pre-update test assembly and reported
3 passed and 1 failed because the assembly still expected four invalid evidence
fixtures while the regenerated corpus reported nine. No evidence or worktree
content was deleted. The focused test project was rebuilt normally, after
which the exact four-test command passed 4/4 in 24.96 seconds.

The repository-wide SpecTrace baseline remains unrelated and was not repaired;
the accepted hardening review recorded 2,693 existing errors. Direct validation
and focused CRT homes are the closeout proof.

## Traceability

Requirements `REQ-QUIC-CRT-0214` through `REQ-QUIC-CRT-0217` trace through
`ARC-QUIC-CRT-0101`, `WI-QUIC-CRT-0102`, and `VER-QUIC-CRT-0103`.

Reviewable implementation commits are:

- `3048b38f` record the architecture decision and trace allocation;
- `0c8fa5f9` enforce the additive schemas, catalog, materializers, validation,
  and projection;
- `e8a67256` add the deterministic fixture and focused test corpus.

The documentation and trace closeout is a final separate local commit reported
in the handoff. The first signed-commit attempt was preserved as a 1Password
agent failure; commits were then created with signing disabled per command,
without changing Git configuration. Nothing is pushed.

## Remaining limitations and stopping point

The closeout does not create actuation proof, release interaction execution,
migrate an additional axis, or release measurement. The general builder is a
schema/hash/reference/aggregate correctness surface, not a performance
analysis or mutable database.

Stop here. Measurement remains frozen; `active_internal` and production policy
behavior remain unauthorized. No interaction workload, campaign, transform,
threshold, model, CI change, axis migration, or push follows from this
checkpoint.

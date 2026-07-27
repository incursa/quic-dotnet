# Adaptive-runtime implemented-factor onboarding review package

Status: complete for external review; proof promotion, multi-axis execution,
and measurement remain blocked.

Date: 2026-07-26

## Recovery and scope

- source commit: `1aa03c6b7d7bd73f1dedc9867f1e11c8f6c4f70c`
- branch: `codex/adaptive-runtime-factor-onboarding-20260726`
- linked worktree:
  `C:\shared\src\incursa\.worktrees\quic-factor-onboarding-20260726`
- primary and prior linked worktrees were not modified
- selected axes: `oversized_write_admission_quantum` and
  `queued_send_burst_budget`
- audited and deferred axis: `packet_flush_cadence`
- runtime mechanism changes: none
- performance, campaign, transform, CI, push, and activation work: none

The prior send-composition holdout result remains
`measurement_completed_no_stable_rule`. Actuation proof, correctness
eligibility, completed experiment result, and rule promotion remain distinct.

## Axis audit and selection

| Axis | Decision | Reason |
| --- | --- | --- |
| `oversized_write_admission_quantum` | selected | implemented fixed-field logical-write latch; two truthfully distinct nonlegacy mechanisms; existing production evidence seam |
| `queued_send_burst_budget` | selected | implemented lower-only actor-turn cap; direct live evidence; bounded single-axis family |
| `packet_flush_cadence` | deferred | implementation exists, but prose omits queued-work activation and the timer/send transition needs its own proof bridge |

The admission family contains the proven directed chain:

```text
oversized_write_admission_quantum
    -> application_send_batch_formation
        -> buffer_copy_coalescing
```

Both edges are `supplies_work`. No direct oversized-to-buffer edge is claimed.
The queued-send family is single-axis and therefore has no fabricated
relationship edge.

## Additive contracts

New versions preserve all earlier versions:

- policy-axis contract v2
- effective-behavior catalog v3
- relationship graph v3
- combination-constraint catalog v2
- experiment-family catalog v3
- actuation mechanism capture v2
- actuation proof evidence v2
- operation evidence v4
- compiled execution manifest v2
- plan-validation result v3
- factor-cell-space v1

All canonical documents prohibit active behavior and performance acceptance.
The existing compiler selects the new catalog suite only when explicitly
invoked with `-CatalogContractVersion v3`.

## Candidate proof inventory

Each proof has five composite-keyed operations: positive actuation,
structurally inactive, safety fallback or clamp, shadow neutrality, and
rollback. Each contains all 15 immutable projection inputs and no release row
because neither selected axis rents the buffer owner.

| Axis/value | Proof SHA-256 | Behavior SHA-256 | Outcome SHA-256 | Projection SHA-256 |
| --- | --- | --- | --- | --- |
| oversized `single_fragment` | `b122ef13836eb5968a1aadb98dbce9ab3e4d1a92a0c6f97b9a57afcfc58dbf09` | `cdb4c76d99add2e1fd6e3892bb9b9fd7c070e2ba80268ba72c230e1f23c0d565` | `dadd96e3c03f27a1fab1fc90cfb4ea8295a818e9f04dd0b825425abcb96172ed` | `cb1632c708b6d9977cbe9b221583480b60c896d33783a3c566d10f57c0aecddb` |
| oversized `bounded_multi_fragment` | `182a03420cbcb013819343a09756a1f522c54aee64b8bcf4c5085bc15d1781b1` | `78099acccd7babbf9394df027783167ee2fd3c3053d81413971fd7102291220a` | `593a1bcc6bce3f1680b6aa38dff631490aacce513123a408aced125d6ec8e93b` | `2127ccefeafb9298b8d38bc41699eb620dea8d734511c95b2ea89dbca0b04ec9` |
| queued `single_datagram` | `597f55caf3dc1d3091df24a27de040b78032f1e249531f633348b4373f00b158` | `fc789dba1489428f5534c1fcba689e27037528070baf48c4a02a295274118c53` | `9143b9b614131ae9c36acaea83460eaef25c37fbfa0c4dfe3c5d06a6d2fef240` | `1997aecffa00d8c3899aba109cab5ddab56d9e0e30c3083b664d8169c22fbe62` |

The exact source commit bound by all three manifests is
`eb698e669ca9b38ba569ca56639fa65718891143`; the focused test binary SHA-256
is `2993843869c0e09b3a829eb12276e5ddc2b358b2fa6cd352743a82cd573e2ad5`.

`REQ-QUIC-CRT-0238` replays the production policy methods against the checked-in
positive captures. The oversized proofs use different retained-selector
bands: legacy selects two for `single_fragment`, while legacy selects one for
`bounded_multi_fragment`. The queued proof applies the production lower-only
budget to a legal cap greater than one. Fixture names and expected result
metadata are not used to select the mechanism result.

All three documents remain:

```text
review_status = candidate
review_outcome = null
active_behavior_authorization = false
performance_acceptance_authorization = false
```

The canonical reviewed-proof list has no entry for either selected axis. The
unapplied template is
`docs/testing/adaptive-runtime-factor-onboarding-proof-promotion.json-patch`;
its external-review placeholders make accidental application invalid.

## Cell-space and covering-array decision

| Family | Raw cells | Legal cells | Nominal single-axis correctness cells | Behavior-distinct effective cells | Measurement-blocked cells |
| --- | ---: | ---: | ---: | ---: | ---: |
| `send_admission_composition` | 12 | 12 | 5 including baseline | 4 | 12 |
| `queued_send_burst_correctness` | 2 | 2 | 2 | 2 | 2 |

All 14 configured cells are explicit `planned_cells`. The 12-cell admission
space is `3 × 2 × 2`; the queued space is two cells. Both are below the
reviewed 65-effective-cell trigger, so exhaustive enumeration is clearer and
stronger than a covering array. No covering-array generator, placeholder, or
runtime capability was added.

Admission cells with more than one behavior-distinct value remain
`capability_pending`. The plan validates architecturally as
`blocked_for_measurement`; it is not silently executable. The queued family
blocks interaction screens.

## Validation results

Focused script regressions:

| Regression | Result |
| --- | --- |
| foundation | 8 schemas, 5 canonical documents, 12 valid and 15 invalid fixtures; passed |
| plan compiler and manifest | 7 valid, 5 warning, 21 invalid plans plus 6 invalid manifest/validation cases; passed |
| runtime evidence | 3 schemas, 16 valid, 5 warning, 24 invalid fixtures; passed |
| hardening | 8 schemas, 3 canonical catalogs, 9 valid, 6 warning, 20 invalid fixtures; passed |
| evidence-integrity closeout | 6 schemas, 15 immutable inputs, 66 classification pairs, 7 projection substitutions; passed |
| retained independent proofs | 36 documents, 2 candidates, 17 negative cases; passed |
| factor onboarding | 6 canonical documents, 14 planned cells, 3 candidates, 22 closed negative cases; passed |

Focused mechanism tests:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-build --no-restore `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0179|FullyQualifiedName~REQ_QUIC_CRT_0180|FullyQualifiedName~REQ_QUIC_CRT_0238"
```

Result: 70 passed, 0 failed, 0 skipped. The new proof-binding home contributed
4 passes.

Focused Release builds:

- `Incursa.Quic`: passed, 0 warnings, 0 errors, 15.67 seconds
- `Incursa.Quic.Tests`: passed, 0 warnings, 0 errors, 72.08 seconds

Direct SpecTrace model validation passed for all four touched artifacts:

- `SPEC-QUIC-CRT-FACTOR-ONBOARDING`
- `ARC-QUIC-CRT-0113`
- `WI-QUIC-CRT-0114`
- `VER-QUIC-CRT-0115`

`git diff --check` passed. The unrelated repository-wide SpecTrace baseline
was not relabeled or repaired.

Retained diagnostics:

- the initial `--no-restore` build correctly failed because the new worktree
  had no assets file; the restored build passed;
- one signed commit attempt failed when 1Password could not fill its buffer;
  the same staged content was committed locally with signing disabled;
- proof generation exposed and corrected additive schema routing, null-field
  serialization, safety-clamp classification, the unrelated queued-family
  edge, and the inconsistent admission executable count.

## Traceability

- requirements: `REQ-QUIC-CRT-0235` through `REQ-QUIC-CRT-0240`
- architecture: `ARC-QUIC-CRT-0113`
- work item: `WI-QUIC-CRT-0114`
- verification: `VER-QUIC-CRT-0115`
- production mechanism homes: `REQ-QUIC-CRT-0179` and
  `REQ-QUIC-CRT-0180`
- proof binding home: `REQ-QUIC-CRT-0238`

## Review disposition

This checkpoint is ready for external review of three candidate proofs and the
two additive family contracts. It is not authorization to:

- mark a proof passed;
- apply the promotion template;
- execute an admission-family interaction involving the new axis;
- execute performance measurement;
- migrate packet flush or another axis;
- activate shadow selection, `active_internal`, or production behavior.

Measurement remains frozen. Active behavior remains unauthorized. CI was not
touched and nothing was pushed.

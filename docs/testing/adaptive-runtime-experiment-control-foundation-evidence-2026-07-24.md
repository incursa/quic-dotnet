---
title: "Adaptive Runtime Experiment-Control Foundation Evidence"
---

# Adaptive Runtime Experiment-Control Foundation Evidence

Date: 2026-07-24

Trace: `REQ-QUIC-CRT-0198` through `REQ-QUIC-CRT-0201`,
`ARC-QUIC-CRT-0089`, `WI-QUIC-CRT-0090`, and `VER-QUIC-CRT-0091`

## Recovery and preservation

The primary worktree was on `main` and its tracking snapshot was 104 commits
ahead and 0 behind. It contained a coherent unfinished Stage 5 ACK-profile
slice: 16 modified files and 5 untracked files, including
`QuicAckBehaviorProfilePolicy.cs`, `REQ-QUIC-CRT-0197.cs`, and the next unified
schema versions. That slice was not completed, staged, stashed, reset, cleaned,
or mixed into this checkpoint.

This checkpoint used the linked worktree
`C:\shared\src\incursa\.worktrees\quic-experiment-control-foundation-20260724`
on branch `codex/adaptive-runtime-experiment-control-20260724`, created from
committed source
`2c234bc92ed67fb7aa49f1e5ea6271b11c918ac8`.

Recovery found no active `dotnet`, PowerShell build/test, campaign, or
transform process associated with this repository. No BenchmarkDotNet,
performance campaign, ProtocolLab campaign, dataset transform, normalization,
curation, split generation, ML analysis, CI action, push, `active_internal`,
or production activation was run.

## Contract validation

Command:

```powershell
./eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1
```

Result:

- 8 schemas passed;
- 5 canonical documents passed;
- 12 valid fixtures passed;
- 15 invalid fixtures produced their exact expected stable codes;
- 0 invalid-fixture code mismatches;
- unknown-field rejection passed;
- canonical content hashes passed;
- deterministic reference resolution passed;
- repeated canonical serialization passed; and
- repeated hashing passed.

Two complete validator invocations returned exit code 0 and byte-identical
UTF-8 output. The validator also canonicalized every document twice in-process
and reproduced every lowercase SHA-256 digest exactly.

Canonical instance hashes:

| Document | `content_sha256` |
| --- | --- |
| Axis contracts | `1e76affbbb0c62d3bd02309dcdbe176c1203444777a1fda718e4d626126a35d0` |
| Effective-behavior catalog | `51e05af776ff564fe5076acf42b5cf78beaaefec1d15933f93f7cc1f35d27936` |
| Relationship graph | `c1bcd321c87960af85a167a8fa34328f65d57ea1393b40acccf6e52eb1c7da63` |
| Combination-constraint catalog | `def6f94b641fec2ee42762fd83509c438e81f5fd501e9fd3982821412a642e4c` |
| Experiment-family catalog | `97f60f047aa12dd28acb9b4992d9d9bb4e814c93ba138c70d12c399ad2dd9f16` |

## Focused build and tests

The first `--no-restore` build attempt stopped before compilation with
`NETSDK1004` because the new linked worktree had no
`tests/Incursa.Quic.Tests/obj/project.assets.json`. The project-scoped restore
completed successfully.

Commands:

```powershell
dotnet restore tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~REQ_QUIC_CRT_0198|FullyQualifiedName~REQ_QUIC_CRT_0199|FullyQualifiedName~REQ_QUIC_CRT_0200|FullyQualifiedName~REQ_QUIC_CRT_0201" --logger "console;verbosity=minimal"
```

Final result:

- Release build: 0 warnings, 0 errors;
- focused requirement-home tests: 4 passed, 0 failed, 0 skipped; and
- no complete Release suite or performance test ran.

## Trace validation

Each new trace artifact passed direct validation against
`model/model.schema.json`:

- `SPEC-QUIC-CRT-EXPERIMENT-CONTROL`;
- `ARC-QUIC-CRT-0089`;
- `WI-QUIC-CRT-0090`; and
- `VER-QUIC-CRT-0091`.

Their requirement, architecture, work-item, verification, and focused xUnit
links are reciprocal and resolve within the checkpoint.

The repository-wide command below was also attempted:

```powershell
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
```

It failed with 2,693 baseline-wide errors beginning in unchanged
`SPEC-QUIC-API.json`, `SPEC-QUIC-CRT.json`, and RFC artifacts, including
published-schema mismatches and cascading unresolved references. Those
unrelated artifacts were not changed to manufacture a clean result. The four
checkpoint trace documents continue to pass the repository model directly.

## Catalog v1 compatibility

The new contract suite supersedes the old catalog only for new
experiment-control planning. The old generator remains the historical
compatibility producer; no companion compiler or generator was introduced.
Existing catalog-v1 fixtures and retained evidence remain valid.

The source and checkpoint Git blob IDs are identical:

| Preserved path | Git blob |
| --- | --- |
| `schemas/adaptive-runtime-policy-catalog-v1.schema.json` | `a1f961462767cef3fe16da957d1d118ac1d1f4fb` |
| `eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1` | `47d9fc5cf5f6a8960ff18b3d8c0583a834c335ce` |

## Stopping point

The architecture/schema checkpoint stops here. It does not implement the
generic plan validator or compiler, execution-manifest compilation, runtime
operation correlation, effective-behavior materialization, analytical
projection, or performance measurement. Measurement remains frozen, nothing
was pushed, and active behavior remains unauthorized.

# RFC 9000 Chunk Closeout: `9000-03-flow-control`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S4`, `S4P1`, `S4P2`, `S4P4`, `S4P5`, `S4P6`

Selection rule: include only requirements whose IDs match RFC `9000` and whose section token is exactly one of the selected tokens.

## Audit Result

- The scoped helper-layer flow-control slice now proves 46 requirements directly, with no requirements remaining partial and four remaining explicit blockers.
- The current repository state was reconciled against the helper layer, the requirement-home tests, and the generated chunk traces.
- No stale requirement IDs remain in the scoped tests.
- No requirement-tagged source refs were found under `src/Incursa.Quic`.
- No silent gaps remain in scope.

## Requirements Covered

- `REQ-QUIC-RFC9000-S4-0001` through `REQ-QUIC-RFC9000-S4-0005`
- `REQ-QUIC-RFC9000-S4P1-0001` through `REQ-QUIC-RFC9000-S4P1-0014`
- `REQ-QUIC-RFC9000-S4P2-0001`
- `REQ-QUIC-RFC9000-S4P2-0005`
- `REQ-QUIC-RFC9000-S4P4-0001` through `REQ-QUIC-RFC9000-S4P4-0004`
- `REQ-QUIC-RFC9000-S4P5-0001` through `REQ-QUIC-RFC9000-S4P5-0008`
- `REQ-QUIC-RFC9000-S4P6-0001` through `REQ-QUIC-RFC9000-S4P6-0012`
- `REQ-QUIC-RFC9000-S4P6-0013`

## Requirements Partial

- None.

## Requirements Deferred

- `REQ-QUIC-RFC9000-S4P1-0015`
- `REQ-QUIC-RFC9000-S4P2-0002` through `REQ-QUIC-RFC9000-S4P2-0004`

## Reference Audit

- Source requirement refs found: none.
- Test requirement refs found: `REQ-QUIC-RFC9000-S4-0001` through `REQ-QUIC-RFC9000-S4-0005`, `REQ-QUIC-RFC9000-S4P1-0001` through `REQ-QUIC-RFC9000-S4P1-0014`, `REQ-QUIC-RFC9000-S4P2-0001`, `REQ-QUIC-RFC9000-S4P2-0005`, `REQ-QUIC-RFC9000-S4P4-0001` through `REQ-QUIC-RFC9000-S4P4-0004`, `REQ-QUIC-RFC9000-S4P5-0001` through `REQ-QUIC-RFC9000-S4P5-0008`, and `REQ-QUIC-RFC9000-S4P6-0001` through `REQ-QUIC-RFC9000-S4P6-0013`.
- Stale requirement refs found: none.
- The accidental RFC 9001 tags in `QuicFrameCodecPart3Tests.cs` and `QuicFrameCodecFuzzTests.cs` were corrected to `REQ-QUIC-RFC9000-S4-0004`.

## Files Changed

- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- `specs/architecture/quic/ARC-QUIC-RFC9000-0001.json`
- `specs/work-items/quic/WI-QUIC-RFC9000-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9000-0001.json`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0002.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0011.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P1-0014.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P2-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P4-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P5-0001.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P5-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P6-0003.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P6-0004.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P6-0005.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4P6-0007.cs`

## Tests Run

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0012|FullyQualifiedName~REQ_QUIC_RFC9000_S13P3_0036"`
- Result: `13 passed, 0 failed, 0 skipped`
- Full unfiltered project run on 2026-04-23: `3102 passed, 33 failed, 0 skipped`; failures were outside the touched S4P5 requirement-home and trace files and are not used as closing evidence for this slice.

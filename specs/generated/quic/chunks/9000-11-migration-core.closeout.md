# RFC 9000 Chunk Closeout: `9000-11-migration-core`

## Scope

- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- RFC: `9000`
- Section tokens: `S9`, `S9P1`, `S9P2`, `S9P3`, `S9P3P1`, `S9P3P2`, `S9P3P3`
- Reconciliation artifact: not present for this chunk
- Implementation summary reviewed: `./specs/generated/quic/chunks/9000-11-migration-core.implementation-summary.json`

## Audit Result

- Audit result: `clean_with_explicit_blockers`
- No stale requirement IDs remain in scope.
- No requirement-tagged source refs were found under `src/Incursa.Quic`.
- The in-scope requirement now lives in the requirement-home proof for `REQ-QUIC-RFC9000-S9P3P1-0001`.
- The 39 remaining open requirements all carry explicit blocker notes; there are no silent gaps.
- The spec and implementation summary are aligned: 40 in-scope requirement IDs, 0 missing, 0 extra.

## Requirements In Scope

- `S9`: 12 requirements
- `S9P1`: 2 requirements
- `S9P2`: 5 requirements
- `S9P3`: 11 requirements
- `S9P3P1`: 1 requirement
- `S9P3P2`: 5 requirements
- `S9P3P3`: 4 requirements
- Total in scope: **40**
- Covered: **1**
- Blocked / deferred: **39**
- Partial: **0**
- Needs review: **0**

## Requirements Completed

- `REQ-QUIC-RFC9000-S9P3P1-0001`
  - Evidence: [SPEC-QUIC-RFC9000.json](/C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json#L8635), [REQ-QUIC-RFC9000-S9P3P1-0001.cs](/C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S9P3P1-0001.cs#L1), [QuicAntiAmplificationBudget.cs](/C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicAntiAmplificationBudget.cs#L1), [QuicPathValidation.cs](/C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPathValidation.cs#L1)
  - Test cases: `CanSend_TracksTheThreeTimesAmplificationCapBeforeValidation`, `CanSend_AllowsUnlimitedSendingAfterAddressValidation`, `TryConsumeSendBudget_RejectsPayloadsThatExceedThePreValidationBudget`, `TryRegisterReceivedDatagramPayloadBytes_RejectsNegativePayloadLengths`
  - Direct refs updated: `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S9P3P1-0001.cs`

## Remaining Open Requirements

- `S9`: `REQ-QUIC-RFC9000-S9-0001`, `REQ-QUIC-RFC9000-S9-0002`, `REQ-QUIC-RFC9000-S9-0003`, `REQ-QUIC-RFC9000-S9-0004`, `REQ-QUIC-RFC9000-S9-0005`, `REQ-QUIC-RFC9000-S9-0006`, `REQ-QUIC-RFC9000-S9-0007`, `REQ-QUIC-RFC9000-S9-0008`, `REQ-QUIC-RFC9000-S9-0009`, `REQ-QUIC-RFC9000-S9-0010`, `REQ-QUIC-RFC9000-S9-0011`, `REQ-QUIC-RFC9000-S9-0012`
  - Blocker: This behavior needs a connection-migration state machine that can gate handshake confirmation, peer-address changes, and local-address selection before the rule can be enforced.
- `S9P1`: `REQ-QUIC-RFC9000-S9P1-0001`, `REQ-QUIC-RFC9000-S9P1-0002`
  - Blocker: This behavior needs a migration-aware send path that can probe a new local address before moving traffic.
- `S9P2`: `REQ-QUIC-RFC9000-S9P2-0001`, `REQ-QUIC-RFC9000-S9P2-0002`, `REQ-QUIC-RFC9000-S9P2-0003`, `REQ-QUIC-RFC9000-S9P2-0004`, `REQ-QUIC-RFC9000-S9P2-0005`
  - Blocker: This behavior needs migration-aware congestion, RTT, and ECN reset state on the new path.
- `S9P3`: `REQ-QUIC-RFC9000-S9P3-0001`, `REQ-QUIC-RFC9000-S9P3-0002`, `REQ-QUIC-RFC9000-S9P3-0003`, `REQ-QUIC-RFC9000-S9P3-0004`, `REQ-QUIC-RFC9000-S9P3-0005`, `REQ-QUIC-RFC9000-S9P3-0006`, `REQ-QUIC-RFC9000-S9P3-0007`, `REQ-QUIC-RFC9000-S9P3-0008`, `REQ-QUIC-RFC9000-S9P3-0009`, `REQ-QUIC-RFC9000-S9P3-0010`, `REQ-QUIC-RFC9000-S9P3-0011`
  - Blocker: Blocked by the missing connection-migration state machine and send-path orchestration.
- `S9P3P2`: `REQ-QUIC-RFC9000-S9P3P2-0001`, `REQ-QUIC-RFC9000-S9P3P2-0002`, `REQ-QUIC-RFC9000-S9P3P2-0003`, `REQ-QUIC-RFC9000-S9P3P2-0004`, `REQ-QUIC-RFC9000-S9P3P2-0005`
  - Blocker: This fallback behavior needs a connection-state machine with last-validated-address tracking and a silent-close/stateless-reset decision point.
- `S9P3P3`: `REQ-QUIC-RFC9000-S9P3P3-0001`, `REQ-QUIC-RFC9000-S9P3P3-0002`, `REQ-QUIC-RFC9000-S9P3P3-0003`, `REQ-QUIC-RFC9000-S9P3P3-0004`
  - Blocker: This behavior needs apparent-migration detection and previous-path validation orchestration.

## Reference Audit

- Source roots searched: `C:/src/incursa/quic-dotnet/src/Incursa.Quic`
- Test roots searched: `C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests`
- In-scope source requirement refs found: none
- In-scope test requirement refs found: `REQ-QUIC-RFC9000-S9P3P1-0001`, `REQ-QUIC-RFC9000-S9P3-0007`
- Stale or wrong refs found: none
- Current in-scope test files: `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S9P3P1-0001.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S9P3-0007.cs`

## Tests Reviewed

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P3P1_0001"`
  - Result: `4 passed, 0 failed, 0 skipped`
- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
  - Result: `1362 passed, 0 failed, 0 skipped`

## Risks / Follow-up Notes

- The only expressible slice in the current helper layer is the anti-amplification budget for unvalidated addresses.
- The remaining S9, S9P1, S9P2, S9P3, S9P3P2, and S9P3P3 requirements depend on missing connection-migration state, path-selection, and validation orchestration surfaces.
- No reconciliation artifact existed for this chunk, so it was treated as greenfield.

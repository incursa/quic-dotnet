# 9000-20-datagram-and-mtu Closeout

## Scope

- RFC: `9000`
- Section tokens: `S13P4`, `S13P4P1`, `S13P4P2`, `S13P4P2P1`, `S13P4P2P2`, `S14`, `S14P1`, `S14P2`, `S14P2P1`, `S14P3`, `S14P4`
- Canonical spec: [`SPEC-QUIC-RFC9000.json`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json)
- Implementation summary: [`9000-20-datagram-and-mtu.implementation-summary.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-20-datagram-and-mtu.implementation-summary.json)
- Reconciliation artifact: not present at `C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-20-datagram-and-mtu.reconciliation.json`

## Summary

- Requirements in scope: 70
- Implemented and test-covered: 25
- Explicitly deferred: 1
- Explicitly blocked: 44
- Silent gaps: 0
- Stale IDs in scope: 0
- Wrong IDs in tests or source refs: 0
- Reconciliation artifact present: no

## Scope Inventory

- `S13P4`: `REQ-QUIC-RFC9000-S13P4-0001`, `REQ-QUIC-RFC9000-S13P4-0002`
- `S13P4P1`: `REQ-QUIC-RFC9000-S13P4P1-0001`, `REQ-QUIC-RFC9000-S13P4P1-0002`, `REQ-QUIC-RFC9000-S13P4P1-0003`, `REQ-QUIC-RFC9000-S13P4P1-0004`, `REQ-QUIC-RFC9000-S13P4P1-0005`, `REQ-QUIC-RFC9000-S13P4P1-0006`, `REQ-QUIC-RFC9000-S13P4P1-0007`, `REQ-QUIC-RFC9000-S13P4P1-0008`, `REQ-QUIC-RFC9000-S13P4P1-0009`
- `S13P4P2`: `REQ-QUIC-RFC9000-S13P4P2-0001`, `REQ-QUIC-RFC9000-S13P4P2-0002`, `REQ-QUIC-RFC9000-S13P4P2-0003`, `REQ-QUIC-RFC9000-S13P4P2-0004`, `REQ-QUIC-RFC9000-S13P4P2-0005`, `REQ-QUIC-RFC9000-S13P4P2-0006`
- `S13P4P2P1`: `REQ-QUIC-RFC9000-S13P4P2P1-0001`, `REQ-QUIC-RFC9000-S13P4P2P1-0002`, `REQ-QUIC-RFC9000-S13P4P2P1-0003`, `REQ-QUIC-RFC9000-S13P4P2P1-0004`, `REQ-QUIC-RFC9000-S13P4P2P1-0005`, `REQ-QUIC-RFC9000-S13P4P2P1-0006`, `REQ-QUIC-RFC9000-S13P4P2P1-0007`, `REQ-QUIC-RFC9000-S13P4P2P1-0008`
- `S13P4P2P2`: `REQ-QUIC-RFC9000-S13P4P2P2-0001`, `REQ-QUIC-RFC9000-S13P4P2P2-0002`, `REQ-QUIC-RFC9000-S13P4P2P2-0003`, `REQ-QUIC-RFC9000-S13P4P2P2-0004`, `REQ-QUIC-RFC9000-S13P4P2P2-0005`
- `S14`: `REQ-QUIC-RFC9000-S14-0001`, `REQ-QUIC-RFC9000-S14-0002`, `REQ-QUIC-RFC9000-S14-0003`, `REQ-QUIC-RFC9000-S14-0004`, `REQ-QUIC-RFC9000-S14-0005`, `REQ-QUIC-RFC9000-S14-0006`, `REQ-QUIC-RFC9000-S14-0007`, `REQ-QUIC-RFC9000-S14-0008`, `REQ-QUIC-RFC9000-S14-0009`
- `S14P1`: `REQ-QUIC-RFC9000-S14P1-0001`, `REQ-QUIC-RFC9000-S14P1-0002`, `REQ-QUIC-RFC9000-S14P1-0003`, `REQ-QUIC-RFC9000-S14P1-0004`, `REQ-QUIC-RFC9000-S14P1-0005`, `REQ-QUIC-RFC9000-S14P1-0006`, `REQ-QUIC-RFC9000-S14P1-0007`, `REQ-QUIC-RFC9000-S14P1-0008`
- `S14P2`: `REQ-QUIC-RFC9000-S14P2-0001`, `REQ-QUIC-RFC9000-S14P2-0002`, `REQ-QUIC-RFC9000-S14P2-0003`, `REQ-QUIC-RFC9000-S14P2-0004`, `REQ-QUIC-RFC9000-S14P2-0005`, `REQ-QUIC-RFC9000-S14P2-0006`, `REQ-QUIC-RFC9000-S14P2-0007`, `REQ-QUIC-RFC9000-S14P2-0008`, `REQ-QUIC-RFC9000-S14P2-0009`, `REQ-QUIC-RFC9000-S14P2-0010`
- `S14P2P1`: `REQ-QUIC-RFC9000-S14P2P1-0001`, `REQ-QUIC-RFC9000-S14P2P1-0002`, `REQ-QUIC-RFC9000-S14P2P1-0003`, `REQ-QUIC-RFC9000-S14P2P1-0004`, `REQ-QUIC-RFC9000-S14P2P1-0005`, `REQ-QUIC-RFC9000-S14P2P1-0006`, `REQ-QUIC-RFC9000-S14P2P1-0007`
- `S14P3`: `REQ-QUIC-RFC9000-S14P3-0001`, `REQ-QUIC-RFC9000-S14P3-0002`, `REQ-QUIC-RFC9000-S14P3-0003`, `REQ-QUIC-RFC9000-S14P3-0004`
- `S14P4`: `REQ-QUIC-RFC9000-S14P4-0001`, `REQ-QUIC-RFC9000-S14P4-0002`

## Evidence

- `REQ-QUIC-RFC9000-S13P4-0001` is implemented and test-covered in [`src/Incursa.Quic/QuicEcnValidationState.cs`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicEcnValidationState.cs), [`tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs), [`tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs), and [`tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs).
- `REQ-QUIC-RFC9000-S13P4P1-0004`, `REQ-QUIC-RFC9000-S13P4P1-0005`, and `REQ-QUIC-RFC9000-S13P4P1-0006` are implemented and test-covered in the ECN validation and ACK-generation helper tests.
- `REQ-QUIC-RFC9000-S13P4P2-0001` and `REQ-QUIC-RFC9000-S13P4P2-0006` are implemented and test-covered in the ECN validation helper and congestion-control tests.
- `REQ-QUIC-RFC9000-S13P4P2P1-0001` through `REQ-QUIC-RFC9000-S13P4P2P1-0008` are now directly traced by the ECN validation helper tests, including the negative path for zeroed-or-missing ECN counts.
- `REQ-QUIC-RFC9000-S13P4P2P2-0001`, `REQ-QUIC-RFC9000-S13P4P2P2-0003`, `REQ-QUIC-RFC9000-S13P4P2P2-0004`, and `REQ-QUIC-RFC9000-S13P4P2P2-0005` are implemented and test-covered in the ECN validation helper tests.
- `REQ-QUIC-RFC9000-S14P4-0001` is implemented and test-covered in [`src/Incursa.Quic/QuicConnectionSendRuntime.cs`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicConnectionSendRuntime.cs) and [`tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S14P4-0001.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S14P4-0001.cs).
- `REQ-QUIC-RFC9000-S14-0003`, `REQ-QUIC-RFC9000-S14-0004`, `REQ-QUIC-RFC9000-S14P1-0001`, `REQ-QUIC-RFC9000-S14P1-0003`, `REQ-QUIC-RFC9000-S14P1-0008`, and `REQ-QUIC-RFC9000-S14P4-0002` are implemented and test-covered by the address-validation, anti-amplification, version-negotiation, and congestion-control tests.
- `REQ-QUIC-RFC9000-S13P4P2-0005` remains an explicit deferred item because the helper slice does not need a no-op path for the permissive guidance.

## Blocked Requirements

- `REQ-QUIC-RFC9000-S13P4-0002` is blocked until the sender/path layer can determine ECN support before enabling ECN.
- `REQ-QUIC-RFC9000-S13P4P1-0001`, `REQ-QUIC-RFC9000-S13P4P1-0002`, `REQ-QUIC-RFC9000-S13P4P1-0003`, `REQ-QUIC-RFC9000-S13P4P1-0007`, `REQ-QUIC-RFC9000-S13P4P1-0008`, and `REQ-QUIC-RFC9000-S13P4P1-0009` remain blocked because the helper slice does not yet model the fuller packet/path/ECN negotiation surface.
- `REQ-QUIC-RFC9000-S13P4P2-0002`, `REQ-QUIC-RFC9000-S13P4P2-0003`, and `REQ-QUIC-RFC9000-S13P4P2-0004` remain blocked by the missing path-management surface.
- `REQ-QUIC-RFC9000-S13P4P2P2-0002` remains blocked because the helper slice does not model the send-side ECN disable path at packet emission time.
- `REQ-QUIC-RFC9000-S14-0001`, `REQ-QUIC-RFC9000-S14-0002`, `REQ-QUIC-RFC9000-S14-0005`, `REQ-QUIC-RFC9000-S14-0006`, `REQ-QUIC-RFC9000-S14-0007`, `REQ-QUIC-RFC9000-S14-0008`, and `REQ-QUIC-RFC9000-S14-0009` remain blocked because datagram assembly, PMTU discovery, and fragmentation control are not wired into packet management.
- `REQ-QUIC-RFC9000-S14P1-0002`, `REQ-QUIC-RFC9000-S14P1-0004`, `REQ-QUIC-RFC9000-S14P1-0005`, `REQ-QUIC-RFC9000-S14P1-0006`, and `REQ-QUIC-RFC9000-S14P1-0007` remain blocked by the missing remaining Initial-path and anti-amplification behaviors.
- `REQ-QUIC-RFC9000-S14P2-0001` through `REQ-QUIC-RFC9000-S14P2-0010`, `REQ-QUIC-RFC9000-S14P2P1-0001` through `REQ-QUIC-RFC9000-S14P2P1-0007`, and `REQ-QUIC-RFC9000-S14P3-0001` through `REQ-QUIC-RFC9000-S14P3-0004` remain blocked because PMTU discovery, ICMP validation, and DPLPMTUD assembly are still absent.
## Reference Audit

- In-scope source requirement refs found: none.
- In-scope test requirement refs found:
  - [`tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs) - `REQ-QUIC-RFC9000-S13P4-0001`, `REQ-QUIC-RFC9000-S13P4P2-0001`, `REQ-QUIC-RFC9000-S13P4P2-0006`, `REQ-QUIC-RFC9000-S13P4P1-0006`, `REQ-QUIC-RFC9000-S13P4P2P1-0001`, `REQ-QUIC-RFC9000-S13P4P2P1-0002`, `REQ-QUIC-RFC9000-S13P4P2P1-0003`, `REQ-QUIC-RFC9000-S13P4P2P1-0004`, `REQ-QUIC-RFC9000-S13P4P2P1-0005`, `REQ-QUIC-RFC9000-S13P4P2P2-0001`, `REQ-QUIC-RFC9000-S13P4P2P2-0004`
  - [`tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs) - `REQ-QUIC-RFC9000-S13P4P1-0004`, `REQ-QUIC-RFC9000-S13P4P1-0005`, `REQ-QUIC-RFC9000-S13P4P1-0006`
  - [`tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs) - `REQ-QUIC-RFC9000-S13P4P1-0004`, `REQ-QUIC-RFC9000-S13P4P1-0005`
  - [`tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs) - `REQ-QUIC-RFC9000-S13P4-0001`, `REQ-QUIC-RFC9000-S13P4P2-0001`, `REQ-QUIC-RFC9000-S14P4-0002`
  - [`tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S14P4-0001.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S14P4-0001.cs) - `REQ-QUIC-RFC9000-S14P4-0001`
  - [`tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs) - `REQ-QUIC-RFC9000-S14P1-0001`, `REQ-QUIC-RFC9000-S14P1-0003`
  - [`tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs) - `REQ-QUIC-RFC9000-S14P1-0008`
  - [`tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs) - `REQ-QUIC-RFC9000-S14-0003`, `REQ-QUIC-RFC9000-S14-0004`
- Stale or wrong in-scope requirement refs found: none.

## Conclusion

Trace is internally consistent. `REQ-QUIC-RFC9000-S14P4-0001` is now closed by the requirement-home proof and canonical x_test_refs, the remaining open items are explicit blockers and one deferred permissive guidance item, and no silent gaps remain in the scoped requirement set.

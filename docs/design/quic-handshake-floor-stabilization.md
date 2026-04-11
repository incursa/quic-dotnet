# Incursa.Quic Handshake-Floor Stabilization

This note scopes the narrow managed handshake-floor slice under active work. It does not widen the supported public promise, and it does not claim the remaining red tail is closed yet.

## In Scope

- `REQ-QUIC-CRT-0108`
- `REQ-QUIC-CRT-0112`
- `REQ-QUIC-CRT-0113`
- `REQ-QUIC-CRT-0114`
- `REQ-QUIC-CRT-0115`
- `REQ-QUIC-CRT-0116`
- `REQ-QUIC-CRT-0118`

## Supported Boundary

- Keep the current narrow managed loopback subset unchanged.
- Keep the public API promise narrow: connection establishment, basic stream usage, write/read/EOF, narrow `RESET_STREAM` / `STOP_SENDING`, narrow stream-capacity callback behavior, and narrow `IsSupported`.
- Keep the handshake-floor proof focused on the existing managed bridge/runtime seam:
  - `QuicTlsTransportBridgeDriver`
  - `QuicTransportTlsBridgeState`
  - `QuicTlsKeySchedule`
  - `QuicTlsTranscriptProgress`
  - `QuicConnectionRuntime`

## Out Of Scope

- `REQ-QUIC-CRT-0106`
- `REQ-QUIC-CRT-0109`
- `REQ-QUIC-CRT-0111`
- `REQ-QUIC-CRT-0117`
- `REQ-QUIC-CRT-0119`
- `Abort(Both, ...)`
- Hostname validation
- Trust-store validation
- Certificate-path validation
- Revocation
- Broader client-auth
- `0-RTT`
- Key update
- Interop-runner testcase support
- Any wider claim that `handshake`, `transfer`, or `retry` is enabled in the interop harness
- Any broader public-promise widening beyond the current narrow loopback subset

## Final Seam To Change

The current stabilization seam is the bridge-driver transcript drain path plus the server/client key-schedule publication edges:

- `QuicTlsTransportBridgeDriver.AdvanceHandshakeTranscript(...)`
- `QuicTlsKeySchedule.ProcessClientHello(...)`
- `QuicTlsKeySchedule.ProcessFinished(...)`

Those seams feed the transcript-progress owner, the key schedule, and the bridge-state gates. If they are wrong, the handshake-floor cluster looks red even when the downstream proof and policy gates are already present.

## Proof Expected

- Positive and negative requirement-home coverage in:
  - `tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0108.cs`
  - `tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0112.cs`
  - `tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0113.cs`
  - `tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0114.cs`
  - `tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0115.cs`
  - `tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0116.cs`
  - `tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0118.cs`
- A broader API+CRT confirmation pass that exercises the same handshake-floor lane without claiming interop testcase enablement.

## Slice Goal

Reduce the red handshake-floor cluster to a stable proof floor without expanding any TLS, client-auth, or interop promise.

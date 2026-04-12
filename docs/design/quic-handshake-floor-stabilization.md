# Incursa.Quic Handshake-Floor Stabilization

This note scopes the narrow managed handshake-floor slice under active work. It does not widen the supported public promise, and it does not claim the remaining red tail is closed yet.

## In Scope

- `REQ-QUIC-CRT-0106`
- `REQ-QUIC-CRT-0108`
- `REQ-QUIC-CRT-0112`
- `REQ-QUIC-CRT-0113`
- `REQ-QUIC-CRT-0114`
- `REQ-QUIC-CRT-0115`
- `REQ-QUIC-CRT-0116`
- `REQ-QUIC-CRT-0117`
- `REQ-QUIC-CRT-0118`
- `REQ-QUIC-CRT-0119`

## Supported Boundary

- Keep the current narrow managed loopback subset unchanged.
- Keep the public API promise narrow: connection establishment, basic stream usage, write/read/EOF, narrow `RESET_STREAM` / `STOP_SENDING`, narrow stream-capacity callback behavior, and narrow `IsSupported`.
- The runtime coordinator proof for `REQ-QUIC-CRT-0106` still depends on explicit handshake destination/source connection IDs being seeded by the existing internal host/runtime seam before protected Handshake packets can be built or opened; that does not widen the public boundary.
- Keep the handshake-floor proof focused on the existing managed bridge/runtime seam:
  - `QuicTlsTransportBridgeDriver`
  - `QuicTransportTlsBridgeState`
  - `QuicTlsKeySchedule`
  - `QuicTlsTranscriptProgress`
  - `QuicConnectionRuntime`

## Out Of Scope

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

## Client Policy / Commit Lane

The client-side policy / commit slice is intentionally narrow and remains separate from the server-floor work:

- `REQ-QUIC-CRT-0109`
- `REQ-QUIC-CRT-0111`

The final client seam must keep the local `ClientHello` published to transport without counting it in the managed proof transcript. The proof transcript for this slice begins at the peer `ServerHello`, which keeps the client `CertificateVerify` and `Finished` proof hashes aligned with the requirement-home tests.

## Final Seam To Change

The current stabilization seam is the bridge-driver transcript drain path plus the server proof-tail publication edge:

- `QuicTlsTransportBridgeDriver.AdvanceHandshakeTranscript(...)`
- `QuicTlsKeySchedule.ProcessFinished(...)`
- `QuicTransportTlsBridgeState.TryMarkPeerFinishedVerified(...)`
- `QuicTransportTlsBridgeState.TryStoreOneRttOpenPacketProtectionMaterial(...)`
- `QuicTransportTlsBridgeState.TryStoreOneRttProtectPacketProtectionMaterial(...)`

Those seams feed the transcript-progress owner, the key schedule, and the bridge-state gates. If they are wrong, the handshake-floor cluster looks red even when the downstream proof and policy gates are already present.

For the server tail slice, the proof boundary stops at `PeerFinishedVerified` plus the narrow transcript-completed milestone. It must not widen to generic `OneRttKeysAvailable` publication because 1-RTT data-path support is still out of scope.

## Proof Expected

- Positive and negative requirement-home coverage in:
  - `tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0106.cs`
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

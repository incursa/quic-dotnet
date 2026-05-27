# RFC 9308 / RFC 9312 Coverage Report

This report records the final RFC 9308 and RFC 9312 coverage state for the
current branch. Both RFCs are informational, so this report separates behavior
that is testable in this implementation from guidance that belongs in public
API comments, developer documentation, operational documentation, diagnostics,
or future feature planning.

Source material:

- [RFC 9308 text](https://www.rfc-editor.org/rfc/rfc9308.html)
- [RFC 9312 text](https://www.rfc-editor.org/rfc/rfc9312.html)
- [`SPEC-QUIC-RFC9308`](../specs/requirements/quic/SPEC-QUIC-RFC9308.json)
- [`SPEC-QUIC-RFC9312`](../specs/requirements/quic/SPEC-QUIC-RFC9312.json)
- [`RFC 9308 / RFC 9312 classification`](design/rfc9308-rfc9312-spectrace-classification.md)
- [`RFC 9308 / RFC 9312 test matrix`](design/rfc9308-rfc9312-test-matrix.md)

## 1. Executive Summary

### What Was Added

RFC 9308 applicability hardening added:

- canonical informational SpecTrace artifacts for RFC 9308:
  [`SPEC-QUIC-RFC9308`](../specs/requirements/quic/SPEC-QUIC-RFC9308.json),
  [`ARC-QUIC-RFC9308-0001`](../specs/architecture/quic/ARC-QUIC-RFC9308-0001.json),
  [`WI-QUIC-RFC9308-0001`](../specs/work-items/quic/WI-QUIC-RFC9308-0001.json),
  and [`VER-QUIC-RFC9308-0001`](../specs/verification/quic/VER-QUIC-RFC9308-0001.json)
- application-facing comments for 0-RTT replay-safety boundaries, keep-alive
  versus resumption, stream mapping, stream priority, stream-capacity
  backpressure, DATAGRAM scope, and application close codes
- flow-control blocked and stream-limit blocked diagnostics plus qlog mapping
- focused requirement-home tests for public 0-RTT absence, guidance boundaries,
  flow-control blocked behavior, stream-limit blocked behavior, application
  close-code propagation, NAT rebinding non-promotion, and qlog mapping
- developer-facing guidance in
  [`application-protocol-guidance.md`](application-protocol-guidance.md)

RFC 9312 manageability hardening added:

- canonical informational SpecTrace artifacts for RFC 9312:
  [`SPEC-QUIC-RFC9312`](../specs/requirements/quic/SPEC-QUIC-RFC9312.json),
  [`ARC-QUIC-RFC9312-0001`](../specs/architecture/quic/ARC-QUIC-RFC9312-0001.json),
  [`WI-QUIC-RFC9312-0001`](../specs/work-items/quic/WI-QUIC-RFC9312-0001.json),
  and [`VER-QUIC-RFC9312-0001`](../specs/verification/quic/VER-QUIC-RFC9312-0001.json)
- safe structured diagnostics for packet header observation, coalesced datagram
  processing, connection ID lifecycle, path validation, migration promotion,
  spin-bit state, ICMP Packet Too Big, PMTU updates, connection close state,
  UDP receive/send errors, anti-amplification blocking, and accepted stateless
  reset visibility
- qlog mappings for the new diagnostics in
  [`QuicQlogDiagnosticsMapper.cs`](../src/Incursa.Quic.Qlog/QuicQlogDiagnosticsMapper.cs)
- focused requirement-home tests for diagnostic payload shape, qlog event
  mapping, NAT rebinding/path validation emission, and local close emission
- operator and troubleshooting documentation in
  [`operations-and-manageability.md`](operations-and-manageability.md) and
  [`troubleshooting-quic.md`](troubleshooting-quic.md)

Generated coverage reports:

| RFC family | Requirements | Trace-clean | Open generated coverage gaps |
| --- | ---: | ---: | ---: |
| RFC 9308 | 10 | 10 | 0 |
| RFC 9312 | 5 | 5 | 0 |

### What Was Only Documented

The following RFC 9308 and RFC 9312 guidance is documented rather than turned
into new runtime behavior:

- fallback policy and endpoint discovery
- 0-RTT replay safety and the absence of a public application 0-RTT profile
- stream mapping responsibility for application protocols
- keep-alive versus reconnect/resumption tradeoffs
- connection ID privacy and timing-linkability support boundaries
- version deployment policy for future versions
- QUIC over UDP operational expectations
- load-balancer and NAT routing considerations
- packet capture and qlog collection workflow
- passive measurement limitations and safe production logging defaults

### What Was Explicitly Deferred

The following items remain future-feature work:

- public application 0-RTT enablement and replay-safe application profiles
- automatic fallback to TCP/TLS or another application transport
- Alt-Svc, SVCB, or HTTPS endpoint discovery
- HTTP/3 priority signaling beyond local stream scheduling hints
- HTTP Datagrams, CONNECT-UDP, MASQUE, and QUIC-LB
- public DSCP/QoS controls and ECMP/load-balancer cooperation features
- QUIC loss bit support
- broader managed-network policy controls

### What Was Not Applicable

RFC 9308 and RFC 9312 text that describes general deployment policy, passive
network measurement outside the endpoint, or features not implemented by this
stack is classified as not applicable or future extension. It is not represented
as a fake transport requirement.

## 2. RFC 9308 Coverage

### Section-By-Section Coverage

| RFC 9308 section | Classification | Current coverage |
| --- | --- | --- |
| §1 Introduction | Documentation only | Informational scope recorded in `SPEC-QUIC-RFC9308` and developer docs. |
| §2 Necessity of Fallback | Documentation only | Application/deployment owned; no automatic fallback added. Covered by `application-protocol-guidance.md` and `operations-and-manageability.md`. |
| §3 0-RTT | Guidance - application API | Public application 0-RTT remains unavailable until a replay-safe profile exists. |
| §3.1 Replay Attacks | Guidance - application API / testable boundary | `REQ-QUIC-RFC9308-S3P1-0001`; public API absence tested by `PublicConnectApi_DoesNotExposeApplicationZeroRttToggle`. |
| §3.2 Session Resumption versus Keep-Alive | Guidance - application API / docs | `REQ-QUIC-RFC9308-S3P2-0001`; docs and comments distinguish keep-alive from resumption and 0-RTT. |
| §4 Use of Streams | Guidance - application API | Application stream mapping is documented; stream behavior remains owned by RFC 9000 and HTTP/3/QPACK specs. |
| §4.1 Stream versus Flow Multiplexing | Guidance - application API | `REQ-QUIC-RFC9308-S4P1-0001`; docs state stream roles and message boundaries are application owned. |
| §4.2 Prioritization | Guidance - application API / no new protocol feature | Current `QuicStream.Priority` is local scheduling only; no HTTP/3 priority signaling added. |
| §4.3 Ordered and Reliable Delivery | Normative dependency | Already owned by RFC 9000 stream behavior. No new RFC 9308 requirement created. |
| §4.4 Flow Control Deadlocks | Testable behavior / diagnostics | `REQ-QUIC-RFC9308-S4P4-0001`; blocked writes preserve state and emit qlog-visible diagnostics. |
| §4.5 Stream Limit Commitments | Testable behavior / diagnostics | `REQ-QUIC-RFC9308-S4P5-0001`; blocked stream opens preserve state and emit qlog-visible diagnostics. |
| §5 Packetization and Latency | Documentation only / future API | No public packetization or latency knob added. Low-latency send policy remains future API/design work. |
| §6 Error Handling | Testable behavior | `REQ-QUIC-RFC9308-S6-0001`; application close codes remain separate from QUIC transport errors. |
| §7 Acknowledgment Efficiency | Normative dependency | ACK policy remains RFC 9000/RFC 9002-owned. No new RFC 9308 requirement. |
| §8 Port Selection and Endpoint Discovery | Documentation only | Endpoint discovery is application/operator owned; no Alt-Svc/SVCB/HTTPS behavior added. |
| §8.1 Source Port Selection | Not applicable / operational | No source-port selection API added in this slice. |
| §9 Connection Migration | Normative dependency / testable regression | `REQ-QUIC-RFC9308-S9-0001`; NAT rebinding candidates are not promoted before validation succeeds. |
| §10 Connection Termination | Normative dependency / diagnostics | Closing/draining behavior remains RFC 9000-owned; RFC 9312 diagnostics expose close state. |
| §11 Information Exposure and Connection ID | Documentation only / diagnostics | `REQ-QUIC-RFC9308-S11-0001`; docs state CID privacy boundary and avoid broader linkability claims. |
| §11.1 Server-Generated Connection ID | Normative dependency | CID generation/lifecycle remains RFC 9000-owned; RFC 9312 adds safe lifecycle diagnostics. |
| §11.2 Timing Linkability | Documentation only | No broad timing-linkability mitigation is claimed. |
| §11.3 Retry for Redirection | Future extension | No server-redirection or QUIC-LB feature added. |
| §12 QoS and DSCP | Future extension | No public DSCP/QoS API added. |
| §13 Versions and Cryptographic Handshake | Documentation only / normative dependency | Existing version and handshake behavior stays with RFC 8999/9000/9001/9368/9369. |
| §14 Deployment of New Versions | Documentation only | `REQ-QUIC-RFC9308-S13-0001`; rollout policy remains operator owned. |
| §15 Unreliable Datagram Service | Documentation only / normative dependency | `REQ-QUIC-RFC9308-S15-0001`; current support is RFC 9221 QUIC DATAGRAM transport floor only. |

### SpecTrace Item Status

| SpecTrace item | Status | Evidence |
| --- | --- | --- |
| `REQ-QUIC-RFC9308-S3P1-0001` | Satisfied; public application 0-RTT remains gated | [`QuicConnection.cs`](../src/Incursa.Quic/QuicConnection.cs), [`QuicConnectionOptions.cs`](../src/Incursa.Quic/QuicConnectionOptions.cs), `PublicConnectApi_DoesNotExposeApplicationZeroRttToggle`, [`application-protocol-guidance.md`](application-protocol-guidance.md) |
| `REQ-QUIC-RFC9308-S3P2-0001` | Satisfied by docs/comments | [`QuicConnectionOptions.cs`](../src/Incursa.Quic/QuicConnectionOptions.cs), `Guidance_DistinguishesKeepAliveFromSessionResumption`, [`application-protocol-guidance.md`](application-protocol-guidance.md) |
| `REQ-QUIC-RFC9308-S4P1-0001` | Satisfied by docs/comments and local-priority test | [`QuicStream.cs`](../src/Incursa.Quic/QuicStream.cs), `StreamPriority_IsLocalSchedulingOnly`, [`application-protocol-guidance.md`](application-protocol-guidance.md) |
| `REQ-QUIC-RFC9308-S4P4-0001` | Satisfied by runtime and qlog tests | [`QuicConnectionRuntime.Streams.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Streams.cs), [`QuicDiagnostics.cs`](../src/Incursa.Quic/QuicDiagnostics.cs), `FlowControlBlockedWrite_DoesNotAdvanceStreamSendState`, `FlowControlBlockedDiagnostic_MapsToQlog` |
| `REQ-QUIC-RFC9308-S4P5-0001` | Satisfied by runtime and qlog tests | [`QuicConnectionRuntime.Streams.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Streams.cs), [`QuicDiagnostics.cs`](../src/Incursa.Quic/QuicDiagnostics.cs), `StreamLimitBlockedOpen_DoesNotCreateAStream`, `StreamLimitBlockedDiagnostic_MapsToQlog` |
| `REQ-QUIC-RFC9308-S6-0001` | Satisfied by close-code test and docs | [`QuicConnection.cs`](../src/Incursa.Quic/QuicConnection.cs), [`QuicConnectionRuntime.Routing.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Routing.cs), `CloseAsync_ProjectsApplicationErrorWithoutTransportError`, [`troubleshooting-quic.md`](troubleshooting-quic.md) |
| `REQ-QUIC-RFC9308-S9-0001` | Satisfied as RFC 9000 dependency plus regression | [`QuicConnectionRuntime.Paths.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Paths.cs), `NatRebindingCandidate_RemainsUnpromotedUntilPathValidationSucceeds`, `NatRebindingPathValidation_EmitsChallengeSuccessAndPromotionDiagnostics` |
| `REQ-QUIC-RFC9308-S11-0001` | Satisfied by docs | `Guidance_DocumentsConnectionIdPrivacyBoundary`, [`application-protocol-guidance.md`](application-protocol-guidance.md), [`operations-and-manageability.md`](operations-and-manageability.md) |
| `REQ-QUIC-RFC9308-S13-0001` | Satisfied by docs | `Guidance_DistinguishesVersionMechanismsFromRolloutPolicy`, [`application-protocol-guidance.md`](application-protocol-guidance.md) |
| `REQ-QUIC-RFC9308-S15-0001` | Satisfied by docs | `Guidance_DistinguishesQuicDatagramFromHttpDatagramsAndMasque`, [`application-protocol-guidance.md`](application-protocol-guidance.md), [`SPEC-QUIC-RFC9221`](../specs/requirements/quic/SPEC-QUIC-RFC9221.json) |

## 3. RFC 9312 Coverage

### Section-By-Section Coverage

| RFC 9312 section | Classification | Current coverage |
| --- | --- | --- |
| §1 Introduction | Documentation only | Informational manageability scope recorded in `SPEC-QUIC-RFC9312` and operator docs. |
| §2 Wire Image | Observable diagnostic opportunity | `REQ-QUIC-RFC9312-S2-0001`; safe packet header metadata diagnostics added. |
| §2.1 Coalesced Packets | Observable diagnostic opportunity | `REQ-QUIC-RFC9312-S2-0002`; coalesced packet-count diagnostics added. |
| §3.1 QUIC Version Identification | Normative dependency / diagnostics | Version/header parsing remains RFC 8999/9000-owned; header observation diagnostics added. |
| §3.2 Handshake Packet Flights | Diagnostics | Packet header and coalesced datagram diagnostics help correlate handshake flights. |
| §3.3 Version Negotiation and Retry | Diagnostics / normative dependency | VN and Retry behavior remains RFC 9000-owned; packet/qlog visibility is documented. |
| §3.4 Coalesced Packets | Testable diagnostics | `PacketHeaderAndCoalescedDiagnostics_MapToQlogWithoutPacketBytes`. |
| §3.5 Packet Number Visibility | Normative dependency / documentation | Packet number protection remains RFC 9000/9001-owned; wire observability documented. |
| §3.6 Connection ID Handling | Diagnostics | `REQ-QUIC-RFC9312-S3-0001`; CID lifecycle diagnostics avoid raw CID bytes and reset tokens. |
| §3.7 Flow Association and Teardown | Operational guidance | Docs explain UDP tuple/CID limits and lack of network-visible end-of-flow signal. |
| §3.8 RTT Measurement and Spin Bit | Diagnostics / documentation | `REQ-QUIC-RFC9312-S4-0001`; spin-bit state can be diagnosed, passive RTT limits documented. |
| §4.1 Passive Measurement | Documentation only | Passive loss measurement and RTT caveats documented; no loss bit added. |
| §4.2 Stateful Treatment | Deployment documentation | UDP timeout and stateful middlebox guidance documented. |
| §4.3 Address Rewriting / Routing Stability | Diagnostics and deployment docs | CID and path diagnostics plus NAT/load-balancer guidance. |
| §4.4 ICMP | Diagnostics | `REQ-QUIC-RFC9312-S4-0001`; ICMP Packet Too Big diagnostics added. |
| §4.5 DDoS Detection and Mitigation | Operational / future extension | Anti-amplification diagnostics added; broader DDoS policy remains deployment owned. |
| §4.6 Flow Teardown | Diagnostics | Close/draining and stateless reset diagnostics added; no network-visible end-of-flow claim. |
| §4.7 Load Balancer Cooperation | Deployment documentation / future extension | QUIC-LB/load-balancer cooperation not implemented; routing caveats documented. |
| §4.8 UDP Blocking, Throttling, and NAT Binding | Diagnostics and docs | UDP socket errors, NAT rebinding, and keep-alive implications documented. |
| §4.9 QoS / ECMP | Future extension | No DSCP/QoS or ECMP feature added. |
| §4.10 PMTU Discovery | Diagnostics | PMTU update and ICMP Packet Too Big diagnostics added; black-hole troubleshooting documented. |

### SpecTrace Item Status

| SpecTrace item | Status | Evidence |
| --- | --- | --- |
| `REQ-QUIC-RFC9312-S2-0001` | Satisfied by safe packet header diagnostics and qlog mapping | [`QuicDiagnostics.cs`](../src/Incursa.Quic/QuicDiagnostics.cs), [`QuicConnectionRuntime.Routing.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Routing.cs), [`QuicQlogDiagnosticsMapper.cs`](../src/Incursa.Quic.Qlog/QuicQlogDiagnosticsMapper.cs), `PacketHeaderAndCoalescedDiagnostics_MapToQlogWithoutPacketBytes` |
| `REQ-QUIC-RFC9312-S2-0002` | Satisfied by coalesced datagram diagnostics and qlog mapping | [`QuicConnectionRuntime.Routing.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Routing.cs), `PacketHeaderAndCoalescedDiagnostics_MapToQlogWithoutPacketBytes` |
| `REQ-QUIC-RFC9312-S3-0001` | Satisfied by safe CID lifecycle diagnostics | [`QuicConnectionRuntime.Routing.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Routing.cs), `ConnectionIdDiagnostics_MapToQlogWithoutSensitiveConnectionMetadata`, [`operations-and-manageability.md`](operations-and-manageability.md) |
| `REQ-QUIC-RFC9312-S3-0002` | Satisfied by migration/path-validation diagnostics and tests | [`QuicConnectionRuntime.Paths.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Paths.cs), `PathValidationDiagnostics_MapToQlog`, `NatRebindingPathValidation_EmitsChallengeSuccessAndPromotionDiagnostics`, [`troubleshooting-quic.md`](troubleshooting-quic.md) |
| `REQ-QUIC-RFC9312-S4-0001` | Satisfied by operational diagnostics and docs | [`QuicConnectionRuntime.Paths.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Paths.cs), [`QuicConnectionEndpointHost.cs`](../src/Incursa.Quic/QuicConnectionEndpointHost.cs), `PmtuIcmpUdpCloseAndSpinDiagnostics_MapToQlog`, `CloseAsync_EmitsConnectionCloseStateDiagnostic`, [`operations-and-manageability.md`](operations-and-manageability.md), [`troubleshooting-quic.md`](troubleshooting-quic.md) |

## 4. Remaining Gaps

### Code Gaps

No code gaps remain for the current RFC 9308 or RFC 9312 SpecTrace items.
Deferred feature families are listed below and should not be implemented without
their own requirements.

### Test Gaps

No generated SpecTrace coverage gaps remain for the current RFC 9308/RFC 9312
items. The test matrix still identifies useful future hardening tests that are
either RFC 9000-owned, dependent on future public surfaces, or integration-heavy:

- `ZeroRttApplicationData_IsRejectedWhenEarlyDataAdmissionIsClosed`
- `FlowControlBlockedStream_ResumesAfterCreditIsReleased`
- `RemoteConnectionClose_EntersDrainingAndEmitsDiagnostic`
- `VersionNegotiation_DiagnosticAndQlogAreEmitted`
- `RetryReceived_DiagnosticAndQlogAreEmitted`
- `ConnectionIdRetirement_RemovesRouteAndToken`
- `SpinBitUpdated_IsEmittedOnlyWhenSpinStateChanges`
- PMTU/ICMP positive and negative runtime-integration tests from the test matrix
- `UnknownFutureVersion_InvariantHeaderParsingDoesNotBreak` fuzz/property proof

### Documentation Gaps

No documentation gaps remain for this slice. The new top-level docs cover:

- application protocol design:
  [`application-protocol-guidance.md`](application-protocol-guidance.md)
- operations and manageability:
  [`operations-and-manageability.md`](operations-and-manageability.md)
- troubleshooting:
  [`troubleshooting-quic.md`](troubleshooting-quic.md)

### Observability Gaps

No observability gaps remain for the current RFC 9312 SpecTrace items. External
packet capture integration, passive RTT/loss tooling, QUIC-LB cooperation, DSCP
policy, and DDoS detection policy remain deployment or future-feature work.

## 5. Deferred Items

| Item | Rationale | Future dependency |
| --- | --- | --- |
| Public application 0-RTT | Requires replay-safe application profile and anti-replay policy. | New application-profile requirement and verification plan. |
| Automatic fallback | RFC 9308 makes fallback an application/deployment decision; fallback can weaken security if done incorrectly. | Product/API decision for fallback transport policy. |
| Endpoint discovery | Alt-Svc, SVCB, and HTTPS records are not part of the current transport facade. | Discovery feature requirements. |
| HTTP/3 priority signaling | Current priority is a local scheduling hint only. | HTTP/3 priority feature requirement. |
| HTTP Datagrams / CONNECT-UDP / MASQUE | RFC 9221 transport DATAGRAM floor is separate from these application layers. | RFC 9297 / RFC 9298 / MASQUE requirements. |
| QUIC-LB / server redirection | Requires deployment and load-balancer cooperation design. | QUIC-LB or load-balancer integration requirements. |
| Public DSCP/QoS controls | Deployment-specific and not required by RFC 9308/9312. | QoS API/design requirement. |
| Loss bit | Not implemented by design in this runtime. | Explicit loss-bit feature requirement. |
| ECMP and managed-network policy controls | Network deployment behavior outside current transport API. | Operator integration requirements. |
| Passive RTT/loss observability beyond endpoint qlog | RFC 9312 describes passive limitations; endpoint diagnostics do not make passive measurement complete. | External tooling or packet-capture integration work. |

## 6. Verification Commands

### Unit Tests

Focused RFC 9308 and RFC 9312 requirement-home tests:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-build --filter "FullyQualifiedName~RFC9308|FullyQualifiedName~RFC9312"
```

Expected result for this branch: 18/18 tests pass.

Focused qlog/diagnostic smoke coverage:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-build --filter "FullyQualifiedName~REQ_QUIC_CRT_0136|FullyQualifiedName~REQ_QUIC_CRT_0138"
```

Expected result for this branch: 7/7 tests pass.

### Integration Tests

The focused RFC filters include runtime-style tests for NAT rebinding candidate
non-promotion, path-validation diagnostics, and public close-state diagnostics.
Broader migration, Retry, Version Negotiation, PMTU, and ICMP integration cases
remain owned by their RFC 9000/9001 requirement homes unless the matrix item is
promoted into a separate future work item.

### Interop Tests

No new external interop run is required by the RFC 9308/RFC 9312 informational
slice. Existing interop evidence remains the support boundary for transport,
HTTP/3, QPACK, migration, and peer behavior. Future interop follow-up should
focus on:

- NAT rebinding and migration cells that remain prerequisite-blocked in the
  interop gap ledger
- Retry and Version Negotiation qlog visibility against external peers
- PMTU/ICMP behavior in a controlled network testbed

### Docs Validation

```powershell
git diff --check
```

Expected result for this branch: no whitespace errors. The current working tree
still reports pre-existing CRLF warnings for generated coverage files when Git
checks them.

### SpecTrace Validation

```powershell
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -RepoRoot . -Profiles core
```

Expected result for this branch: 619 SpecTrace JSON artifacts validate.

Generated coverage triage:

```powershell
pwsh -NoProfile -File scripts/spec-trace/Generate-QuicRequirementCoverageTriage.ps1 -RepoRoot .
```

Expected result for this branch: RFC 9308 remains 10/10 trace-clean and RFC
9312 remains 5/5 trace-clean.

## 7. Risk Notes

### Correct-Looking Behavior Without External Interop Evidence

- NAT rebinding and path validation have focused local proof, but the live
  interop `rebind-port` and `rebind-addr` cells remain prerequisite-blocked in
  the gap ledger.
- Retry and Version Negotiation are covered by parser/runtime/qlog evidence in
  this repository, but RFC 9312-specific external qlog visibility has not been
  proven against multiple peers in this slice.
- PMTU and ICMP diagnostics have focused metadata proof, but black-hole and ICMP
  behavior still benefit from controlled network interop evidence.
- HTTP/3 request stalls and QPACK blocked-stream troubleshooting guidance relies
  on the existing HTTP/3 and QPACK slices; this report does not promote broader
  HTTP/3 production-hosting support.

### Intentionally Implementation-Specific Behavior

- Public application 0-RTT remains unavailable until a replay-safe application
  profile exists.
- Stream priority is a local scheduling hint, not a peer-visible protocol
  signal.
- qlog extension event names such as `quic:flow_control_blocked` and
  `quic:path_validation_succeeded` are implementation diagnostics, not new QUIC
  wire behavior.
- Safe diagnostics intentionally avoid raw connection ID bytes, stateless reset
  tokens, Retry integrity tags, TLS secrets, protected payload bytes, and
  decrypted application data.
- The stack does not claim automatic fallback, QUIC-LB, loss bit, DSCP/QoS,
  ECMP, HTTP Datagrams, CONNECT-UDP, or MASQUE behavior from RFC 9308 or RFC
  9312.

## 8. Follow-Up Issues

These are recommended follow-up issues, not remaining gaps in the current
RFC 9308/RFC 9312 SpecTrace closure:

1. Add a future public 0-RTT design issue only if an application profile commits
   to replay-safe semantics.
2. Add RFC 9000-owned runtime integration tests for remote close draining,
   retired connection ID non-reuse, Version Negotiation diagnostics, Retry
   diagnostics, and unknown-version invariant parsing if those are not already
   sufficiently covered by existing homes.
3. Add PMTU and ICMP positive/negative network-testbed coverage for black-hole
   and Packet Too Big behavior.
4. Keep HTTP Datagrams, CONNECT-UDP, MASQUE, QUIC-LB, DSCP/QoS, and loss bit as
   separate future-feature issues with their own requirements.
5. Gather external interop evidence for NAT rebinding/path migration and qlog
   visibility once the prerequisite interop cells are stable.

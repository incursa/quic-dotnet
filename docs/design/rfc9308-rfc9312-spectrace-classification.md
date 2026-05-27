# RFC 9308 and RFC 9312 SpecTrace Classification

RFC 9308 and RFC 9312 are informational. The classifications below preserve the SpecTrace IDs while separating actual implementation obligations from application guidance, operational guidance, documentation boundaries, and no-action items.

## Classification Table

| SpecTrace ID | RFC section | Classification | Rationale | Related references | Recommended action |
|---|---|---|---|---|---|
| `REQ-QUIC-RFC9308-S3P1-0001` | RFC 9308 §3.1 | Guidance - application API | Public 0-RTT is an application replay-safety contract, not a transport feature to expose by default. | `src/Incursa.Quic/QuicConnection.cs`; `src/Incursa.Quic/QuicConnectionOptions.cs`; `docs/design/rfc9308-application-guidance.md`; `PublicConnectApi_DoesNotExposeApplicationZeroRttToggle` | Keep the public API profile-gated. No additional code unless a replay-safe application profile is designed. |
| `REQ-QUIC-RFC9308-S3P2-0001` | RFC 9308 §3.2 | Guidance - application API | Keep-alive and TLS session resumption affect application expectations and should be explained at the API/documentation boundary. | `src/Incursa.Quic/QuicConnectionOptions.cs`; `docs/design/rfc9308-application-guidance.md`; `Guidance_DistinguishesKeepAliveFromSessionResumption` | Maintain developer guidance and comments. No runtime change. |
| `REQ-QUIC-RFC9308-S4P1-0001` | RFC 9308 §4.1 | Guidance - application API | Stream mapping is an application-protocol design responsibility; the transport should not invent protocol-specific stream roles. | `src/Incursa.Quic/QuicStream.cs`; `docs/design/rfc9308-application-guidance.md`; `StreamPriority_IsLocalSchedulingOnly` | Keep docs/comments explicit that protocols must define stream roles and message boundaries. |
| `REQ-QUIC-RFC9308-S4P4-0001` | RFC 9308 §4.4 | Testable behavior | Flow-control blocked writes are concrete runtime behavior and diagnostics must be verified. | `src/Incursa.Quic/QuicConnectionRuntime.Streams.cs`; `src/Incursa.Quic/QuicDiagnostics.cs`; `src/Incursa.Quic.Qlog/QuicQlogDiagnosticsMapper.cs`; `FlowControlBlockedWrite_DoesNotAdvanceStreamSendState`; `FlowControlBlockedDiagnostic_MapsToQlog` | Keep focused regression tests and qlog mapping. No further code currently needed. |
| `REQ-QUIC-RFC9308-S4P5-0001` | RFC 9308 §4.5 | Testable behavior | Stream-limit blocked opens are concrete runtime behavior and diagnostics must be verified. | `src/Incursa.Quic/QuicConnectionRuntime.Streams.cs`; `src/Incursa.Quic/QuicDiagnostics.cs`; `src/Incursa.Quic.Qlog/QuicQlogDiagnosticsMapper.cs`; `StreamLimitBlockedOpen_DoesNotCreateAStream`; `StreamLimitBlockedDiagnostic_MapsToQlog` | Keep focused regression tests and qlog mapping. No further code currently needed. |
| `REQ-QUIC-RFC9308-S6-0001` | RFC 9308 §6 | Testable behavior | Application close-code propagation is observable runtime behavior and should remain distinct from QUIC transport errors. | `src/Incursa.Quic/QuicConnection.cs`; `src/Incursa.Quic/QuicConnectionRuntime.Routing.cs`; `CloseAsync_ProjectsApplicationErrorWithoutTransportError` | Keep regression coverage. No additional behavior required. |
| `REQ-QUIC-RFC9308-S9-0001` | RFC 9308 §9 | Normative dependency | Candidate validation before migration promotion is RFC 9000 transport behavior; RFC 9308 only reinforces applicability. | `src/Incursa.Quic/QuicConnectionRuntime.Paths.cs`; `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000`; `NatRebindingCandidate_RemainsUnpromotedUntilPathValidationSucceeds` | Preserve RFC 9000 path-validation proofs and RFC 9308 applicability regression. No new feature. |
| `REQ-QUIC-RFC9308-S11-0001` | RFC 9308 §11 | Documentation only | CID privacy/linkability guidance is a support-boundary statement for this stack; broader timing-linkability mitigation is not claimed. | `docs/design/rfc9308-application-guidance.md`; `Guidance_DocumentsConnectionIdPrivacyBoundary` | Keep documentation explicit. No code change. |
| `REQ-QUIC-RFC9308-S13-0001` | RFC 9308 §13, §14 | Documentation only | Version negotiation mechanisms are implemented elsewhere; deployment of new versions is operator rollout guidance. | `docs/design/rfc9308-application-guidance.md`; `Guidance_DistinguishesVersionMechanismsFromRolloutPolicy`; `SPEC-QUIC-RFC9368`; `SPEC-QUIC-RFC9369` | Keep docs tied to implemented version mechanisms. Future version rollout policy belongs in a separate feature or deployment plan. |
| `REQ-QUIC-RFC9308-S15-0001` | RFC 9308 §15 | Documentation only | The current stack has the RFC 9221 DATAGRAM transport floor, but HTTP Datagrams, CONNECT-UDP, and MASQUE are separate future features. | `docs/design/rfc9308-application-guidance.md`; `Guidance_DistinguishesQuicDatagramFromHttpDatagramsAndMasque`; `SPEC-QUIC-RFC9221`; `REQUIREMENT-GAPS.md` | Keep boundary docs. Treat HTTP Datagrams, CONNECT-UDP, and MASQUE as future-extension work if reopened. |
| `REQ-QUIC-RFC9312-S2-0001` | RFC 9312 §2, §3.1 | Guidance - operational | Packet header visibility is useful for manageability and troubleshooting; it should be diagnostic metadata, not a wire-image change. | `src/Incursa.Quic/QuicDiagnostics.cs`; `src/Incursa.Quic/QuicConnectionRuntime.Routing.cs`; `src/Incursa.Quic.Qlog/QuicQlogDiagnosticsMapper.cs`; `PacketHeaderAndCoalescedDiagnostics_MapToQlogWithoutPacketBytes`; `docs/design/rfc9312-manageability-diagnostics.md` | Keep metadata-only diagnostics. Avoid logging protected payload bytes. |
| `REQ-QUIC-RFC9312-S2-0002` | RFC 9312 §2.1, §3.4 | Guidance - operational | Coalesced packet decomposition is an operator/debugging visibility issue over existing packet processing. | `src/Incursa.Quic/QuicConnectionRuntime.Routing.cs`; `src/Incursa.Quic/QuicDiagnostics.cs`; `PacketHeaderAndCoalescedDiagnostics_MapToQlogWithoutPacketBytes` | Keep qlog/diagnostic coverage. No protocol behavior change. |
| `REQ-QUIC-RFC9312-S3-0001` | RFC 9312 §3.6, §4.3, §4.7 | Guidance - operational | CID lifecycle visibility helps diagnose routing, rebinding, and linkage issues; raw CID bytes and reset tokens remain sensitive. | `src/Incursa.Quic/QuicConnectionRuntime.Routing.cs`; `src/Incursa.Quic/QuicDiagnostics.cs`; `ConnectionIdDiagnostics_MapToQlogWithoutSensitiveConnectionMetadata` | Keep sequence-only diagnostics. No raw CID or token logging. |
| `REQ-QUIC-RFC9312-S3-0002` | RFC 9312 §3.6, §4.3, §4.7 | Guidance - operational | Migration and path validation are RFC 9000 behaviors, while RFC 9312 drives safe visibility into those transitions. | `src/Incursa.Quic/QuicConnectionRuntime.Paths.cs`; `PathValidationDiagnostics_MapToQlog`; `NatRebindingPathValidation_EmitsChallengeSuccessAndPromotionDiagnostics`; `docs/design/rfc9312-manageability-diagnostics.md` | Keep diagnostics and tests. Do not expose a new public migration-control API. |
| `REQ-QUIC-RFC9312-S4-0001` | RFC 9312 §3.8, §4.4, §4.6, §4.8, §4.10 | Guidance - operational | PMTU, ICMP, UDP errors, anti-amplification, close/drain, stateless reset, and spin-bit state are operational troubleshooting signals with safe metadata constraints. | `src/Incursa.Quic/QuicConnectionRuntime.Paths.cs`; `src/Incursa.Quic/QuicConnectionRuntime.Routing.cs`; `src/Incursa.Quic/QuicConnectionEndpointHost.cs`; `src/Incursa.Quic.Qlog/QuicQlogDiagnosticsMapper.cs`; `PmtuIcmpUdpCloseAndSpinDiagnostics_MapToQlog`; `CloseAsync_EmitsConnectionCloseStateDiagnostic`; `docs/design/rfc9312-manageability-diagnostics.md` | Keep safe diagnostics and docs. Loss bit, DSCP/QoS, QUIC-LB, ECMP, and broader network policy remain not implemented by design or future extension. |

## Items That Need Code

None in the current classification. The RFC 9308 and RFC 9312 code-facing items already have bounded implementation in this branch. Future code should only be added if a separate feature requirement is opened for public 0-RTT, HTTP Datagrams, CONNECT-UDP, MASQUE, DSCP/QoS, QUIC-LB, loss bit, or deployment-specific network controls.

## Items That Need Tests

No new test gaps remain for the current SpecTrace items. Existing focused tests cover:

- RFC 9308 API/documentation boundaries, flow-control blocked behavior, stream-limit blocked behavior, close-code separation, NAT rebinding non-promotion, and qlog blocked diagnostics.
- RFC 9312 packet/coalescing qlog mapping, CID diagnostics, path validation diagnostics, NAT rebinding diagnostics, PMTU/ICMP/UDP/close/spin diagnostics, and close-state emission.

## Items That Need Docs

The current docs are present, but these items should remain documentation-maintained:

- `REQ-QUIC-RFC9308-S3P2-0001`
- `REQ-QUIC-RFC9308-S4P1-0001`
- `REQ-QUIC-RFC9308-S11-0001`
- `REQ-QUIC-RFC9308-S13-0001`
- `REQ-QUIC-RFC9308-S15-0001`
- `REQ-QUIC-RFC9312-S2-0001`
- `REQ-QUIC-RFC9312-S2-0002`
- `REQ-QUIC-RFC9312-S3-0001`
- `REQ-QUIC-RFC9312-S3-0002`
- `REQ-QUIC-RFC9312-S4-0001`

## Informational Or No-Action Items

These items should be explicitly treated as informational/no-action unless a separate owning feature appears:

- `REQ-QUIC-RFC9308-S3P1-0001`: no public application 0-RTT until replay-safe profile work exists.
- `REQ-QUIC-RFC9308-S11-0001`: no broader CID timing-linkability claim.
- `REQ-QUIC-RFC9308-S13-0001`: no automatic new-version deployment policy.
- `REQ-QUIC-RFC9308-S15-0001`: no HTTP Datagrams, CONNECT-UDP, or MASQUE behavior from this slice.
- `REQ-QUIC-RFC9312-S4-0001`: no loss bit, DSCP/QoS, QUIC-LB, ECMP, or managed-network policy feature from this slice.

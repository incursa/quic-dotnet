---
workbench:
  type: specification
  workItems: []
  codeRefs: []
  pathHistory: []
  path: /specs/requirements/quic/REQUIREMENT-GAPS.md
---

# QUIC Requirement Gaps

This ledger tracks open questions, ambiguities, and follow-up decisions for QUIC requirement work.

## Open Gaps

- `interop-major-peer-matrix-inventory` remains open as an advisory refresh surface for later major-peer evidence. Hosted run `25904716076` is preserved in `interop-major-peer-matrix-evidence-25904716076`, but the cells still split across peer-specific success and failure modes rather than converging on one Incursa-side issue.

- `interop-peer-characterization-matrix-pilot` remains open as an advisory reporting refresh surface. The current report model can classify peer, role, testcase, outcome class, failure class, and artifact root, but later evidence runs still need to use that shape instead of flattening mixed peer results to green/red. This is an analysis/reporting gap, not a transport/runtime gap.

- `interop-network-simulator-backed-test-surface` remains open only for execution evidence not yet promoted under `REQ-QUIC-INT-0026`. `SIM-QUIC-BASE-0001` has local simple-p2p execution evidence; deterministic loss execution remains open for `SIM-QUIC-LOSS-0001`. Simulator settings stay evidence inputs, requirement statements stay normative claims, and verification artifacts stay proof records.

- `interop-all-upstream-client-nonhandshake-xquic-liveness` is open as the remaining local client-role all-upstream `transfer`/`keyupdate`/`chacha20` residual after the May 19, 2026 refresh. The generic stream-data liveness bug is closed by the focused ordered-read wake-up proof and by live quic-go `transfer`, `chacha20`, and `keyupdate` reruns. The ACK scheduler now has focused proof that the two-packet delayed-ACK threshold re-arms after a prior ACK while still delaying after only one new ack-eliciting packet. The broad client-role run under `.artifacts/interop-runner/all-upstream-streamdata-keyupdate-local/client/20260519-121832639-client-chrome` now passes `transfer` and `keyupdate` for 15 of 16 upstream server-capable peers, passes `chacha20` for 14 of 16, and reports `chacha20` unknown/unsupported for `mvfst` and `go-x-net`. The only failed peer cluster is `xquic`, where all three cells time out after 35,400 bytes. A focused `xquic` rerun after the ACK-threshold topoff still times out under `.artifacts/interop-runner/debug-client-transfer-xquic-after-ack-threshold/20260519-140609871-client-chrome`; the xquic server log shows STREAM sends continuing until congestion-window exhaustion around 45 KB and only early client ACK processing, while paired packet capture shows the simulator received later client-to-server datagrams with zero interface drops. Treat this as a reduced xquic-specific ingress or packet-opening liveness investigation before changing transport behavior; it is not HTTP/3, migration, server-role non-handshake, or support-readiness proof.

- `non-http3-interop-suite-inventory` remains open for cells that have not been promoted by their own proof slice. `v2` is intentionally deferred to the separate QUIC v2 requirement family for RFC 9369. `rebind-port` and `rebind-addr` are RFC 9000 migration/path-validation interop cells, not a different RFC, but they still need dedicated live runner evidence and inventory promotion before they can move out of prerequisite-blocked status. The current local `rebind-port` artifact at `artifacts/interop-runner/rebind-proof/20260520-165752528-server-nginx` shows no client packet from the second rebound external port, and the current local `rebind-addr` artifact at `artifacts/interop-runner/rebind-proof/20260520-171906828-server-nginx` completes the download but still fails the runner's server-path validation check, so the inventory remains prerequisite-blocked rather than promoted. Corruption and ECN cells remain outside this helper-supported inventory until their own proof slice promotes them.

## Future RFC Planning Gaps

- `quic-bit-greasing-compatible-versioning-v2` is a planning gap for `rfc9287.txt` sections `3.1`-`3.2`, `rfc9368.txt` sections `2`-`2.5`, `4`-`7.3`, and `rfc9369.txt` sections `3`-`7`. Pressure class: `versioning` and `transport-core`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: packet/version parsing and handshake version-selection flow, especially `QuicPacketParser` and `QuicConnectionRuntime`.

- `quic-datagram-ownership` is a planning gap for `rfc9221.txt` sections `3`-`5`. Pressure class: `transport-core` and `datagram adapter`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: outbound datagram ownership and emission, especially `QuicConnectionRuntimeEventModels.QuicConnectionSendDatagramEffect`, `QuicConnectionRuntime.SendDatagram`, and `QuicListenerHost.SendDatagram`.

- `http3-adapter-boundary` is a planning gap for `rfc9114.txt` sections `3`, `6.2.1`-`6.2.2`, `7.2.4`-`7.2.4.1`, `7`, and `9`. Pressure class: `HTTP/3 adapter`, `stream adapter`, and `diagnostics/manageability`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: effect emission and stream delivery across the transport boundary, especially `QuicConnectionRuntimeEventModels` and `QuicListenerHost`.

- `qpack-stream-state-boundary` is a planning gap for `rfc9204.txt` sections `2`-`5` and `7.1.1`. Pressure class: `stream adapter` and `HTTP/3 adapter`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: stream-state capture and restore, especially `QuicConnectionStreamSnapshot` and `QuicConnectionStreamState`.

- `websockets-http3-extended-connect` is a planning gap for `rfc9220.txt` section `3`. Pressure class: `HTTP/3 adapter` and `stream adapter`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: HTTP/3 stream delivery and adapter effect emission above the core transport runtime.

- `http-datagrams-and-capsules` is a planning gap for `rfc9297.txt` sections `2.1`-`2.2`, `3.1`-`3.5`, and `5.1`-`5.4`. Pressure class: `datagram adapter`, `stream adapter`, and `HTTP/3 adapter`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: outbound datagram ownership and capsule/stream delivery, especially `QuicConnectionRuntimeEventModels.QuicConnectionSendDatagramEffect`, `QuicConnectionRuntime.SendDatagram`, `QuicListenerHost.SendDatagram`, and `QuicConnectionStreamSnapshot`.

- `connect-udp` is a planning gap for `rfc9298.txt` sections `3`-`5`. Pressure class: `datagram adapter`, `HTTP/3 adapter`, and `stream adapter`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: UDP payload ownership and HTTP Datagrams bridging, especially the same outbound datagram path used by `QuicConnectionRuntime` and `QuicListenerHost`.

- `connect-ip-masque` is a planning gap for `rfc9484.txt` sections `4.1`, `4.7`, `6`, `7`, `10`, `12.1`-`12.4`. Pressure class: `datagram adapter`, `HTTP/3 adapter`, and `diagnostics/manageability`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: outbound datagram ownership, packet handling, and MTU-sensitive proxy flow, especially `QuicConnectionRuntimeEventModels.QuicConnectionSendDatagramEffect` and the adapter boundary above `QuicConnectionRuntime`.

- `dns-over-quic` is a planning gap for `rfc9250.txt` sections `3.1`-`5.8` and `8.1`-`8.2`. Pressure class: `DNS/discovery edge`, `stream adapter`, and `transport-core`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: stream delivery and handshake/resumption state, especially `QuicConnectionStreamSnapshot` and the `QuicConnectionRuntime` TLS/transport bridge flow.

- `encrypted-dns-discovery-and-provisioning` is a planning gap for `rfc9461.txt` sections `3.1`, `4.1`-`4.3`, `rfc9463.txt` sections `3.1`-`3.4`, `4.1`-`4.2`, `5.1`-`5.2`, and `6.1`-`6.2`, and `rfc9464.txt` sections `3.1`-`3.2`, `4.1`-`4.2`, and `5`. Pressure class: `DNS/discovery edge`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: no QUIC hot-path seam; keep resolver/configuration data as scalar snapshots that enter the core only at bootstrap or endpoint selection time.

- `manageability-and-applicability-guidance` is a planning gap for `rfc9308.txt` sections `2`, `3.1`-`3.2`, `4.1`-`4.5`, `8.1`, `9`, `11.1`-`11.3`, `13`-`15`, and `rfc9312.txt` sections `2.1`-`4.10`. Pressure class: `diagnostics/manageability` and `interop/test-only`. Current action is architecture planning only unless support is explicitly committed later. Allocation-sensitive seams: diagnostics emission and packet/version observation, especially `QuicConnectionRuntime.DiagnosticsSink`, runtime event emission, and packet inspection helpers.

## How To Use

- Add a gap here before implementation whenever RFC text leaves more than one plausible interpretation.
- Keep the note short and actionable.
- Reference the owning `SPEC-...` file and the follow-up artifact if one exists.
- Remove the gap entry once the owning requirement, architecture, work item, and verification artifacts carry the closed evidence.

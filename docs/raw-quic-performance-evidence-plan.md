# Raw QUIC Performance Evidence Plan

Updated: 2026-07-15

## Purpose

Raw QUIC performance work must start from a current, matched transport campaign.
The public ProtocolLab rows are useful diagnostics, but they are not yet a
decision-ready comparison between Incursa.Quic, quic-go, and MsQuic.

This plan separates evidence repair from runtime optimization. A runtime change
is selected only after the requested and effective workload shapes, target
identity, package provenance, validation, and generator health are proven.

## Current Public Snapshot

The latest published raw QUIC cohort was generated on 2026-07-12. It compares
`quic-dotnet-raw-dev` with `quic-go-raw` for two scenarios:

| Scenario | Incursa | quic-go | Evidence limitation |
| --- | ---: | ---: | --- |
| `quic.transport.stream-throughput.1mb` | 15,537,520.85 B/s | 106,827,936.04 B/s | One 5-second repetition on the same worker |
| `quic.transport.multiplex.100x64kb` | 6,360,267.55 B/s | 30,405,144.66 B/s | Reported as `c1/s1` despite the 100-stream contract |

The public QUIC index currently reports zero results eligible for a public
performance claim. The latest cohort is validation-passed but non-publishable,
has no source/package parity artifact, has no MsQuic target, and does not retain
enough raw measurement artifacts to support a ranking claim.

The gap shown by these numbers may be real. Its size is not yet established.

## Current Controller Readiness

The rack controller has one ready SUT worker and two ready load-generator
workers. All report the bundled raw QUIC executor and `libmsquic` capability.

A dry-run of `raw-quic-peer-matrix` on 2026-07-15 showed:

| Slice | Runnable targets | Blocker |
| --- | --- | --- |
| Stream throughput | Incursa, quic-go | MsQuic has no implementation package |
| Multiplex | Incursa, quic-go | MsQuic has no implementation package |
| Duplex peer matrix | None | Incursa and controller quic-go packages do not advertise the peer-matrix scenario |

The campaign description says three targets, but package resolution currently
produces two. That mismatch must fail visibly until the third target is packaged.

Local package production is now repaired, but controller registration is still
intentionally pending approval:

- Incursa commit `c9cef4f1` produces deterministic `quic-dotnet-raw-dev`
  packages with six raw scenarios, embedded provenance, and a matching external
  attestation. Clean Linux package `dev-c9cef4f1-clean` has SHA-256
  `861326182b8b474c3ceaeed92752db10f764d36f51e4a8cfed997d7a112c4649`.
- ProtocolLab commit `e3165c6` produces the distinct
  `msquic-dotnet-raw-adapter-v1` implementation package with the same six
  scenarios and trust contract. Clean Linux package `0.1.1-dev-e3165c6` has
  SHA-256 `bc60e9208cc7726db680dc61e08bba79421ccff094c4fa3553fe86178a143a53`.
- Both archives pass the controller's package admission logic. The Incursa
  Windows package also started successfully and its live adapter manifest
  reported all six scenarios.
- No package was uploaded and no worker/controller deployment was changed.
  Therefore the controller dry-run remains the authoritative registration
  blocker until an operator approves package admission and campaign execution.

## Coverage Matrix

| Area | Current coverage | Required next coverage |
| --- | --- | --- |
| Payload size | 128 B churn, 64 KiB multiplex/duplex, 1 MiB upload | 1 KiB, 16 KiB, 256 KiB, 1 MiB, and multi-MiB |
| Direction | Upload and bounded bidirectional echo | Upload, download, and simultaneous full duplex |
| Concurrency | Named c1, c8, c32 profiles; ad hoc c64/c128 overrides | Named c1, c4, c16, c32, c64, and c128 profiles |
| Stream topology | Single stream, 16-stream duplex, 100-stream multiplex | Multiple connections, many streams, mixed stream sizes |
| Lifecycle | Cold handshake and churn at c1 | Handshake/churn scaling, resumption, rejected resumption, 0-RTT outcomes |
| Flow control | Incidental multiplex evidence | Controlled windows, blocked duration, credit cadence, slow reader/writer |
| Network | Clean profile | Loss, delay, reordering, bandwidth, MTU, and ECN where executable |
| Duration | 3-30 second finite runs | Minutes-scale bounded-memory and recovery soaks |
| Diagnostics | Counters and traces on selected Incursa runs | Target and generator CPU, queue, buffer, retransmission, qlog, and network telemetry |

## Work Order

### 1. Repair comparison identity and package coverage

- `quic.transport.handshake-cold`, `quic.transport.connection-churn`, and
  `quic.transport.duplex-streams-peer-matrix` are now declared by the Incursa
  package, run helper, and live adapter manifest.
- `msquic-dotnet-raw-adapter-v1` now has a distinct implementation ID,
  immutable version, SHA-256, source metadata, and clean-source build
  attestation.
- Register current authoritative quic-go implementation, executor, and scenario
  packages instead of relying on legacy generated component identities.
- Normalize `quic.transport.connection-churn` and
  `quic.transport.stream-churn` without silently merging historical evidence.
- Require package-matrix preview to resolve three runnable targets for every
  selected peer scenario.

### 2. Prove requested and effective workload shape

- Record executor ID/version plus requested and effective connections,
  concurrency, streams per connection, warmup, duration, and repetition.
- Reject a cell when the effective shape does not match the scenario/run plan.
- Add reusable c1, c4, c16, c32, c64, and c128 QUIC profiles.
- Use deterministic round-robin target ordering and at least five repetitions.

### 3. Establish fresh matched baselines

Run Incursa, quic-go, and MsQuic with the same executor and scenario package:

1. `quic.transport.stream-throughput.1mb`
2. `quic.transport.multiplex.100x64kb`
3. `quic.transport.duplex-streams-peer-matrix`
4. cold handshake and connection/stream churn after canonical ID alignment

Classify each concurrency point as target-limited, generator-limited,
network-limited, unstable, or clean. Do not compare a new Incursa run with a
stale peer run as one campaign.

### 4. Expand transport workloads

Add payload-direction, flow-control, sustained-stream, and controlled-network
scenarios in small contract-first slices. Every new scenario must define exact
payload bytes/hashes, completion criteria, timeout behavior, required metrics,
and unsupported behavior before executor implementation.

### 5. Optimize the runtime from evidence

Use clean matched traces to choose the next Incursa change. Priority signals are
queue delay, write-completion latency, outstanding pooled bytes by bucket,
sent-packet retention, retransmission retention, target CPU, allocation sites,
exception sites, and generator saturation. Preserve rejected experiments.

## Acceptance Gates

A raw QUIC performance claim is ready only when:

- all compared targets use exact implementation identities and immutable packages;
- source and package provenance are present and parity is either passed or an
  explicit blocker;
- requested and effective shapes match;
- payload length and content are validated in both directions;
- every accepted cell has zero failed, timed-out, and malformed operations;
- target and generator telemetry show which side saturated;
- at least five repetitions pass with variance reported;
- target order is deterministic round robin;
- trace-instrumented runs are diagnostic only;
- shared-host runs are diagnostic only; and
- the complete peer campaign is rerun after accepted runtime changes.

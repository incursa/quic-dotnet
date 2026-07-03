---
title: "QUIC Network Simulator Correctness Plan"
---

# QUIC Network Simulator Correctness Plan

This page defines how simulator-backed network-condition tests should be tracked before they become implementation work.

The upstream [`quic-network-simulator`](https://github.com/quic-interop/quic-network-simulator) is an ns-3 and Docker Compose framework. It places a simulator container between client and server endpoint containers and supports scenarios such as point-to-point delay, bandwidth and queue limits, packet drop or corruption, explicit droplists, blackhole windows, client rebinding, and TCP or UDP cross-traffic.

The live public [`QUIC Interop Runner`](https://interop.seemann.io/quic) status page is a separate advisory status surface. It can inform peer characterization and scenario selection, but it does not replace repo-local requirement mapping or verification records.

The simulator creates the network condition. The repository's requirements and verification artifacts define the correctness claim.

When a scenario row cites RFC9000 or RFC9002 requirement IDs, confirm the current canonical IDs against the RFC9000 migration crosswalk and retired-ID ledger before changing the row or using it as promotion evidence. The scenario catalog should point at the live requirement IDs, not stale retired names.

## Repository Model

Simulator-backed work has three lanes. The lane is a reporting classification, not a protocol requirement by itself.

| Lane | Purpose | Promotion Rule |
| --- | --- | --- |
| `correctness` | Prove a bounded QUIC requirement under a named network condition. | Counts only for the mapped requirement IDs after evidence records the expected observable result. |
| `advisory-interop` | Characterize behavior against another implementation under simulator control. | Stays advisory unless a separate verification artifact promotes a bounded requirement claim. |
| `performance-only` | Measure throughput, latency, recovery cost, or congestion behavior. | Routes through benchmark reporting and does not count as correctness proof by itself. |

Do not create a requirement whose only meaning is a raw simulator setting such as "10 percent loss" or "50 ms delay." The requirement should name the QUIC behavior. The simulator profile, parameters, seed, and peer shape belong in the scenario and verification evidence.

For this lane:

- Simulator settings are evidence inputs.
- Requirement statements are the normative claims.
- Verification artifacts are the proof record.
- Promotion is per requirement ID, not per simulator profile.
- Advisory and performance-only scenarios can reference `REQ-QUIC-INT-0026` for accounting, but no protocol correctness claim is promoted without separate mapped protocol requirements and passing proof.

## Scenario Fields

Every planned scenario should carry:

| Field | Meaning |
| --- | --- |
| `scenario_id` | Stable id such as `SIM-QUIC-LOSS-0001`. |
| `classification` | `correctness`, `advisory-interop`, or `performance-only`. |
| `upstream_profile` | Simulator scenario such as `simple-p2p`, `drop-rate`, `droplist`, `blackhole`, `rebind`, `tcp-cross-traffic`, or `udp-cross-traffic`. |
| `upstream_reference` | Source URL or pinned upstream commit/path for the simulator profile documentation or source used to define parameters. |
| `parameters` | Exact simulator parameter values, including delay, bandwidth, queue, rates, droplists, blackhole window, rebind timing, cross-traffic rate, and deterministic seed when the profile supports one. |
| `local_role` | `client`, `server`, or `both`. |
| `peer_shape` | Local-loopback, same implementation, or named external peer. |
| `mapped_requirements` | Requirement IDs exercised by the scenario. |
| `expected_observables` | The concrete result that makes the scenario pass. |
| `evidence_required` | Logs, qlog, pcap, runner report, simulator stdout, command line, and summary output needed for audit. |
| `status` | `planned`, `implemented`, `passing`, `failing`, `blocked`, `flaky`, or `performance-only`. |
| `promotion_rule` | The exact claim that can be made if the scenario passes. |

Do not promote a scenario if any of these fields are missing for a correctness run. Advisory and performance-only rows may omit protocol requirement promotion, but they still need a stable scenario id, simulator profile, exact parameters, evidence bundle, and status.

## First Scenario Wave

| Scenario Id | Classification | Upstream Profile, Reference, And Parameters | Role / Peer Shape | Requirement Anchor | Expected Observable | Required Evidence | Status / Promotion |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `SIM-QUIC-BASE-0001` | `correctness` | `simple-p2p`; upstream `sim/scenarios/simple-p2p/README.md`; `--delay=15ms --bandwidth=10Mbps --queue=25`; no drop/corruption/rebind/cross-traffic | `both` / same implementation | `REQ-QUIC-INT-0026`, `REQ-QUIC-INT-0010` | One ordered transfer completes through the simulator and the harness exits honestly after byte delivery and EOF. | Scenario definition, upstream reference and commit/ref, exact simulator command, simulator stdout/exit code, client/server logs, runner report when used, qlog when available, summary with mapped requirement IDs. | `passing` for the local run under `.artifacts/network-simulator-live/SIM-QUIC-BASE-0001/current-baseline-clean-compose-20260519`; `VER-QUIC-INT-0020` accepts the preserved evidence as baseline transfer-under-simulator proof for `REQ-QUIC-INT-0010`. |
| `SIM-QUIC-LOSS-0001` | `correctness` | `droplist`; upstream `sim/scenarios/droplist/README.md`; `--delay=15ms --bandwidth=10Mbps --queue=25 --drops_to_client=<ip-packet-indexes> --drops_to_server=<ip-packet-indexes>`; no random drop | `both` / same implementation | `REQ-QUIC-RFC9002-S3-0009`, `REQ-QUIC-RFC9002-S3-0010`, `REQ-QUIC-RFC9002-S6P2-0001`, `RFC9002-S6-2-4-P1-R01`, `RFC9002-S6-2-4-P1-S2-R01` | Reliable data is acknowledged or declared lost, retransmitted in a new ack-eliciting packet, and the bounded transfer completes. Droplist packet indexes are bottleneck-link IP packet indexes, not QUIC packet numbers, so proof must show which QUIC packet was actually affected. | Baseline evidence plus droplist, packet trace or runner packet analysis, qlog loss/probe markers when available, and summary showing retransmission rather than duplicate accounting. | `passing` for the local run under `.artifacts/network-simulator-live/SIM-QUIC-LOSS-0001/20260522T060348Z` with `--drops_to_server=41`; `VER-QUIC-INT-0020` accepts the preserved evidence as bounded loss-detection proof for the mapped RFC9002 requirements. |
| `SIM-QUIC-BLACKHOLE-0001` | `correctness` | `blackhole`; upstream `sim/scenarios/blackhole/README.md`; `--delay=15ms --bandwidth=10Mbps --queue=25 --on=<flow-window> --off=<outage-window> --repeat=1 --direction=both|toclient|toserver` | `both` / same implementation | `REQ-QUIC-RFC9002-S6P2-0001`, `REQ-QUIC-RFC9002-S6P2P1-0001`, `RFC9002-S6-2-4-P1-R01`, `RFC9002-S6-2-4-P1-S1-R01`, `RFC9002-S6-2-4-P1-S2-R01` | PTO is armed from the linked RTT state, sends one or two ack-eliciting probe datagrams during the outage, and the connection resumes or exits with a classified bounded timeout. | Baseline evidence plus blackhole window parameters, timer/probe trace, qlog when available, pcap or packet-analysis output, and timeout classification if it does not resume. | `planned`; do not implement before baseline plus deterministic loss evidence are stable. |
| `SIM-QUIC-REORDER-0001` | `correctness` | No verified upstream reorder profile in `quic-network-simulator` as of this planning pass; candidate remains blocked until a deterministic upstream-compatible method is identified. | `both` / same implementation | `REQ-QUIC-RFC9000-S13P2P1-0013`, `RFC9000-S13-2-3-P5-S1-R01`, `REQ-QUIC-RFC9002-S6P1-0001` | Gap-detecting ACK behavior is immediate, ACK ranges remain retained until safe to retire, and loss declaration respects the basic loss criteria. | Baseline evidence plus packet trace proving the reorder shape, ACK-range summary, qlog when available, and loss-declaration summary. | `blocked`; do not promote until the simulator method can produce deterministic reordering rather than loss-only or probabilistic noise. |
| `SIM-QUIC-CORRUPT-0001` | `correctness` | `corrupt-rate`; upstream `sim/scenarios/corrupt-rate/README.md`; `--delay=15ms --bandwidth=10Mbps --queue=25 --rate_to_client=<0-100> --rate_to_server=<0-100> --burst_to_client=<n> --burst_to_server=<n>` | `both` / same implementation | `REQ-QUIC-RFC9000-S5P2-0010`, `REQ-QUIC-RFC9000-S5P2-0013` | Packets that cannot be opened are discarded and any processing side effects are reverted. | Baseline evidence plus corruption parameters, packet trace or runner analysis, endpoint logs that classify discarded packets, and qlog when available. | `planned`; later wave because packet-open side effects need focused observability. |
| `SIM-QUIC-REBIND-0001` | `advisory-interop` | `rebind`; upstream `sim/scenarios/rebind/README.md`; `--delay=15ms --bandwidth=10Mbps --queue=25 --first-rebind=3s --rebind-freq=0s`; add `--rebind-addr` only for address-rebind characterization | `server` / named external peer | `REQ-QUIC-INT-0025`, `RFC9000-S9-6-1-P4-S2-R01`, `REQ-QUIC-RFC9000-S9P6P2-0010`, `RFC9000-S9-6-3-P5-S1-R01`, `REQ-QUIC-CRT-0063`, `REQ-QUIC-CRT-0065`, `REQ-QUIC-CRT-0068`, `REQ-QUIC-CRT-0069`, `REQ-QUIC-CRT-0070` | Rebind or migration behavior is characterized with preserved source-address evidence; connectionmigration has separate hosted proof, but this scenario does not promote `rebind-port` or `rebind-addr`. | Runner report, simulator command/stdout, pcap/source-address summary, endpoint logs, qlog when available, peer/outcome/failure classification, and artifact root. | `planned`; advisory until a dedicated rebind proof has live runner evidence and inventory promotion. |
| `SIM-QUIC-XTRAFFIC-0001` | `performance-only` | `tcp-cross-traffic`; upstream `sim/scenarios/tcp-cross-traffic/README.md`; `--delay=15ms --bandwidth=10Mbps --queue=25`. Optional later `udp-cross-traffic` uses source file `sim/scenarios/udp-cross-traffic/udp-cross-traffic.cc` and requires `--crossdatarate=<rate>`. | `both` / same implementation or named external peer | `REQ-QUIC-INT-0026` accounting only; benchmark lane remains under `benchmarks/README.md` | Throughput, completion time, recovery cost, and congestion behavior are recorded without promoting correctness support. | Benchmark report, scenario definition, upstream reference and commit/ref, simulator command/stdout, endpoint logs, and environment summary. | `performance-only`; no protocol correctness promotion unless a future row adds explicit mapped protocol requirements and pass criteria. |

## Evidence Rules

Each implemented scenario should preserve evidence under `artifacts/network-simulator/<scenario-id>/<run-id>/` or an equivalent uploaded artifact root.

Required evidence:

| Evidence | Required For |
| --- | --- |
| Scenario definition and exact simulator command | Every scenario |
| Simulator stdout and exit code | Every scenario |
| Client and server logs | Every scenario |
| qlog, when the harness can emit it | Correctness and advisory interop |
| pcap or runner packet-analysis output, when available | Loss, corruption, rebind, and peer-comparison scenarios |
| Summary JSON or Markdown | Every scenario once automation exists |
| Requirement IDs and promotion result | Every correctness scenario |

## Status Accounting

Use these status meanings:

| Status | Meaning |
| --- | --- |
| `planned` | Scenario is defined but not executable in repo tooling. |
| `implemented` | Repo tooling can execute the scenario, but no accepted proof run is recorded. |
| `passing` | Evidence satisfies the scenario's expected observable result. |
| `failing` | The scenario ran and the observed behavior violated the expected result. |
| `blocked` | Infrastructure, peer, simulator, or prerequisite gaps prevent a useful verdict. |
| `flaky` | Repeated runs do not produce a stable verdict. |
| `performance-only` | The scenario measures behavior but is not correctness proof. |

## Implementation Order

1. Keep `REQ-QUIC-INT-0026`, `ARC-QUIC-INT-0020`, `WI-QUIC-INT-0020`, and `VER-QUIC-INT-0020` as the scenario-accounting source.
2. Implement only `SIM-QUIC-BASE-0001` and one deterministic loss scenario first.
3. Add generated scenario inventory only after the manual model proves stable.
4. Promote passing results only to the mapped requirement IDs named by the scenario.
5. Expand into random loss, blackhole, corruption, rebind, and cross-traffic after the first two scenarios produce useful evidence.

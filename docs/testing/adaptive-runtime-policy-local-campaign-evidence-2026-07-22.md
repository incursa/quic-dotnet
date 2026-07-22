---
title: "Adaptive Runtime Local Campaign Evidence - 2026-07-22"
---

# Adaptive Runtime Local Campaign Evidence - 2026-07-22

Status: partial local campaign retained; broader schedule paused on host
isolation

This record continues the append-only receive-credit campaign after the
planning and harness-review period. It does not replace or reinterpret the
July 21 evidence. No active controller, online learning, public adaptive-policy
API, package upload, ProtocolLab controller job, or stress schedule was used.
Machine learning remains limited to future offline regime discovery and rule
derivation from reviewed evidence.

## Harness Qualification

The first post-restart guardrail exposed two distinct measurement-contract
problems instead of a receive-credit performance result:

- ProtocolLab reported the adapter process as the diagnostic target even when
  the adapter had launched and measured a child QUIC server.
- A counter session could become ready after most or all of a short load
  interval had already completed. The retained `guardrail1` false-fast sample
  began timestamped counter data about 6.65 seconds after load start and did
  not observe stream-write-completion activity during the measured interval.

The repaired harness now retains adapter-backed child attribution in every
sample and gates load start on the live counter readiness message. Counter
shutdown is graceful, raw counter timestamps are checked after finalization,
and a local result fails closed if resolved, measured, and counter process
identities are missing or inconsistent.

The accepted implementation checkpoints are:

- `10a0ccd` in `protocol-lab-internal`: repair adapter-backed target
  attribution;
- `48423f8` in `protocol-lab-internal`: add the first counter readiness and
  shutdown contract;
- `629d5f7` in `protocol-lab-internal`: use the live readiness handshake and
  validate raw timestamps after shutdown;
- `22f23118` in `quic-dotnet`: retain per-sample target-attribution proof;
- `c665c687` and `fbbfa8b5` in `quic-dotnet`: permit empty contract-failure
  collections in the permanent runner.

Focused verification passed after these changes: 59 ProtocolLab tests and all
five `REQ-QUIC-CRT-0169` tests. The final fresh Release build before the valid
c1 gate completed with zero warnings and zero errors.

## Guardrail Progression

All roots below are retained under `.artifacts/adaptive-runtime`. No failed or
partial attempt was deleted, rewritten, or folded into a later row.

| Campaign | Cell | Classification | Review disposition |
| --- | --- | --- | --- |
| `adaptive-receive-credit-20260722-guardrail2` | `upload-1mb-x1-s1` | partial | The runner stopped before a local result because an empty generic failure list was rejected by PowerShell parameter binding. Partial artifacts are retained. |
| `adaptive-receive-credit-20260722-guardrail3` | `upload-1mb-x1-s1` | `invalid_contract` | All four samples timed out waiting for counter readiness because raw JSON output was buffered until shutdown. No load result was credited. |
| `adaptive-receive-credit-20260722-guardrail4` | `upload-1mb-x1-s1` | `invalid_environment` | Attribution, readiness, counters, payload, and correctness all passed. The earlier false-fast regime disappeared, but candidate p95 repeated only within 10.575 percent, outside the five-percent gate. |
| `adaptive-receive-credit-20260722-guardrail5` | `upload-1mb-x1-s1` | `neutral_local` | The 5-second warmup and 30-second interval produced a 1.688-percent maximum within-treatment range. Baseline/candidate throughput was 4.345/4.350 MiB/s and p95 was 258.824/252.214 ms. All four samples were exact and counter-attributed. |
| `adaptive-receive-credit-20260722-balanced1` | `upload-1mb-x16-s1` | `invalid_environment` | The first 30-second higher-connection row repeated only within 12.453 percent. The schedule was interrupted as the next cell began; this negative row remains intact. |
| `adaptive-receive-credit-20260722-guardrail-c16-60s1` | `upload-1mb-x16-s1` | `neutral_local` | A bounded 60-second gate contracted the maximum range to 4.337 percent. Baseline/candidate throughput was 26.524/26.689 MiB/s and p95 was 651.275/654.096 ms. |

The c1 and c16 gates show that the repaired measurement path is usable when
the workstation remains in one regime. They do not show a receive-credit
performance improvement; both results are neutral and local-only.

## Balanced 60-Second Profile

The resumed profile used a 5-second warmup, a 60-second measurement interval,
frozen binaries, alternating ABBA/BAAB order, and no stress cells.

| Cell | Classification | Maximum range | Baseline/candidate throughput | Baseline/candidate p95 |
| --- | --- | ---: | ---: | ---: |
| `upload-1mb-x16-s1` | `neutral_local` | 3.684% | 26.304/26.357 MiB/s | 658.720/681.378 ms |
| `duplex-64kb-x1-s16` | `neutral_local` | 2.901% | 1.823/1.832 MiB/s | 601.586/585.370 ms |
| `download-1mb-x16-s1` | `neutral_local` | 2.167% | 25.214/24.907 MiB/s | 675.591/691.192 ms |
| `multiplex-1kb-x1-s100` | `neutral_local` | 0.742% | 0.923/0.922 MiB/s | 106.074/106.473 ms |
| `duplex-64kb-x4-s16` | `invalid_environment` | 9.530% | 6.925/7.094 MiB/s | 604.470/596.761 ms |

Every balanced-profile sample exited zero, validated its exact payload, and
reported zero failed operations, timeouts, protocol errors, or invariant
violations. Counter capture succeeded in every sample. Every attribution row
used `adapter-process-metrics`, marked itself valid, and proved that resolved,
measured, and counter process IDs matched while the adapter root remained
distinct.

The final row is not credited. Both treatments improved between their early
and late repetitions: baseline throughput moved from 6.916 to 7.608 MB/s and
candidate throughput moved from 7.133 to 7.743 MB/s while both p95 values
improved. The shared drift is evidence of a host-regime change rather than a
candidate-policy effect.

## Host-Isolation Finding

After the invalid mixed-cardinality row, a read-only idle-host check sampled
15 seconds three times. Total CPU averaged between 38.5 and 48.4 percent and
peaked between 55.3 and 75.5 percent. Syncthing consistently consumed about
17 CPU-seconds per 15-second window, with additional Explorer, ChatGPT, Task
Manager, Edge, System Settings, OneDrive, and other desktop activity.

The three newest campaign roots contain about 638 MiB across roughly 2,100
files. Syncthing was actively reading the shared tree after those artifacts
were generated. No process was suspended or stopped because campaign authority
does not extend to changing user synchronization or desktop state.

A bounded 30-minute idle monitor then sampled 60 ten-second windows separated
by 20 seconds. A qualifying window required at most 20 percent mean CPU, 35
percent maximum CPU, processor queue length at most one, and at most three
Syncthing CPU-seconds. None qualified and the consecutive-stability count
remained zero of three. Later windows averaged as much as 78.74 percent CPU
and peaked at 92.29 percent. A final ten-second process-I/O sample observed
84.54 MiB read and 20.31 CPU-seconds across the Syncthing processes. The
permitted x4/s16 rerun was deliberately not spent in that regime.

The reviewed next gate is one append-only rerun of only
`duplex-64kb-x4-s16` at 5/60 seconds after a low-contention idle window is
observed. If that row remains `invalid_environment`, the broader campaign must
stop rather than stretch duration or silently accept workstation noise.

## Integrity Audit

A fresh audit covered all ten July 22 local-result documents present at this
checkpoint. All ten validate against
`adaptive-runtime-policy-local-result-v1`. Their checksum inventories contain
402 entries; every referenced path exists and every SHA-256 hash matches.
Invalid and contract-failure rows were included in this audit.

Key artifact identities are:

| Campaign/cell | Result SHA-256 | Manifest SHA-256 | Inventory SHA-256 |
| --- | --- | --- | --- |
| `guardrail3/upload-1mb-x1-s1` | `dae17685e5a3d0a1f92660bcc668dab25f23e83eac2c2b275c66a8830483e3b4` | `73e0b9cb62e3dd5d4dc51889018c75db946d2682abe0b15ef843a2fb3bded6b6` | `730abe3a51900be929f968553bf05d89543d72642b49a1cf5a499dbdcf66f72c` |
| `guardrail4/upload-1mb-x1-s1` | `8896cebb152753d127b532914ee34100b094f2615671ea16d0069e349a4085da` | `35525db91f1c2c5a20e51fe7b7bdab4da822e8871bf9f8760cc16514a5b02208` | `7c712dbf19030705eb575a3da12580ab82cb6d942c6330e815e0bd20dacc865a` |
| `guardrail5/upload-1mb-x1-s1` | `8df7bf243cecefb19dd119fbe3611801ccdaa2982413389f71d0e33e2f3f2f86` | `18ccfcd7295b08fffc587c5f69fa760a241336fab00cdd9be277635583b5af66` | `7e4e0feda874dda2715c58e02a3c688800a9b05d7b30693d2892a2bbabeb7f2a` |
| `guardrail-c16-60s1/upload-1mb-x16-s1` | `f05d9f7e79a81ce66a0d7b6d9c4fe7693162fc7ef0910cd18d308f1846cd03be` | `9e61f7b76b01f82a5035f2ad37bb3d7ca607f297ce65f55965f837db9ac01dc2` | `9c5e50e744e5823cd02b07b6488e4ae538698f5f7c5d338f13a0f340d6bdd50d` |
| `balanced60s1/duplex-64kb-x4-s16` | `bccfc40760ace772b317401df2cbd96e1922dbe1c37527b05e22a7feedee9eb0` | `916f18cd7f3b05980728872d175c9c534416cf85861cdd0fbdefd8ca62c9ac34` | `01f598e0b9cb3f21808f2531996c3bdd8441cfbe337f79a2fb562c043eb326e5` |

## Gate Decision

The repaired harness and the valid c1, c16, s16, download-c16, and s100 rows
are ready for offline dataset preparation after review. The local campaign as
a whole is not complete because the mixed x4/s16 cell failed environment
repeatability. `connection_first` and `stream_first` have not started.

No result in this record authorizes `active_internal`, stress expansion,
ProtocolLab submission, online exploration, or production selector changes.

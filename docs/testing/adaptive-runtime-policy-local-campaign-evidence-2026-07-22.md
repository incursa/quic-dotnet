---
title: "Adaptive Runtime Local Campaign Evidence - 2026-07-22"
---

# Adaptive Runtime Local Campaign Evidence - 2026-07-22

Status: post-SSD guardrail and varied local campaign retained; offline review
required before any runtime implementation

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

## Forced-Epoch Preservation Correction

A contract audit after the balanced profile found that forced-policy cells
retained result-level metrics but did not export the per-connection epoch rows
required by the offline dataset contract. Only `-ShadowOnly` cells enabled the
epoch publisher. The balanced results above remain valid aggregate diagnostic
evidence, but they are not eligible as raw epoch-layer training rows and must
not be silently represented as ML-ready data.

Commits `85b40119` and `c12e2c57` add behavior-neutral forced epoch capture.
The configured forced policy remains transport-authoritative; the existing
rule is evaluated only as a recorded recommendation. Each forced row now joins
to its source sample and treatment, records `selectionSource=forced`, carries
the actual applied policy, and fails validation when sample, treatment, and
snapshot policy identities disagree. The generic raw stream is retained as
`adaptive-runtime-epochs.raw.jsonl`.

The focused Release build completed with zero warnings and errors. The
`REQ-QUIC-CRT-0164` through `REQ-QUIC-CRT-0169` band passed 46 of 46 tests,
including all three forced policies and a proof that observation does not
change the selected receive-credit path. Both forced and shadow example rows
passed schema and join validation. Source-host startup smokes for
`legacy_current`, `immediate`, `read_dominant_batch`, and `shadow` all reported
the generic epoch contract.

The append-only
`adaptive-receive-credit-20260722-forced-epoch-smoke1/upload-1mb-x1-s1`
integration row retained 66 epoch files across four ABBA samples. Every row
used `selectionSource=forced`, every applied policy matched the source sample
treatment, and evidence validation joined all 66 rows with zero failures. Its
111 checksum entries had zero missing files or hash mismatches, and every
sample retained valid target attribution. The row is
`invalid_environment` because it deliberately ran during the documented host
contention; its timings are not credited.

The smoke identities are result
`779900d549fe0ed6669d9e4796becfa4da19f988e8da31459bf14daef965c0fe`,
manifest
`d1365cc5412434247d85cfdd7934783327835f8a5ba773bef0012de074b73f8d`,
inventory
`8c810410253739109df382d0240a7f2e21e091844cbd07299d8466222dc92922`,
and validation summary
`351ffa04ec8a3f5a710575b05ec395120f9965f6b6cc595c7f0a8380e0db23b6`.

Because epoch capture adds bounded instrumentation to every forced sample, a
new full-length c1 guardrail must requalify the measurement environment before
any ML-ready varied profile runs. The earlier aggregate balanced profile is
not substituted for that rerun.

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
remain useful aggregate diagnostic evidence. They are not raw epoch-layer
training rows because they predate forced-epoch capture. The local campaign as
a whole is not complete: the host remains contended, the instrumented c1 gate
has not cleared, and the ML-ready `balanced`, `connection_first`, and
`stream_first` profiles have not run.

No result in this record authorizes `active_internal`, stress expansion,
ProtocolLab submission, online exploration, or production selector changes.

## Post-SSD Requalification And Varied Campaign

The workstation's `C:` drive returned to local SSD storage before this slice.
The work resumed from the retained evidence rather than replacing any earlier
campaign. Syncthing remained stopped, no stale benchmark process was present,
and the campaign continued to use fixed policies, fixed sequences, and
fail-closed classification. No stress profile or production runtime tuning was
authorized.

### ProtocolLab Qualification

The distributed diagnostic path was requalified before local measurements.
The retained ProtocolLab implementation checkpoints are:

- `b2159d0`: repair cross-worker diagnostic attribution and controller-root
  artifact access;
- `971696f`: materialize adapter child artifacts before worker cleanup;
- `5fa8e34`: suppress inactive external-target diagnostics while retaining
  required target-side capture.

The following jobs remain negative or diagnostic-only evidence and were not
folded into later measurements:

- `job-49599a3e3e96464db850b9c65246ae40`: load workspace ownership prevented
  artifact creation;
- `job-e3eec67b6c8e458e934b5542cfd6c914`: pre-repair merged SUT artifacts and
  target counters were not usable;
- `job-4c87cc8cec91436c81f22aa8c5d02717`: target counters passed, but child
  artifacts were not yet materialized;
- `job-cebe14546d334fbdbd7abd3b56f51f42`: child artifacts and counters passed,
  but the old load CLI emitted an unresolved-target warning;
- `job-76df321b593e422f9ded14253cb6919f`: the same warning remained in the
  bundled CLI copy before both Runner DLL locations were updated.

The final forced baseline smoke
`job-4b66d91b95514002833d49fde80400b0` and candidate smoke
`job-560238ac02a64ee0b148ecc18f509ab5` both completed with 115 artifacts,
valid target counter capture, readable child stdout, 25 valid epoch rows, zero
invalid epoch rows, successful payload validation, and no load-side diagnostic
warning. The baseline applied only `LegacyCurrent`; the candidate applied only
`ReadDominantBatch`. These remain diagnostic-only results because SUT and load
VMs share one Lenovo P620 physical host under Proxmox.

### Instrumented C1 Guardrail

Campaign
`adaptive-receive-credit-20260722-postssd-guardrail-c1-60s1` completed the
`upload-1mb-x1-s1` ABBA cell as `neutral_local`. Maximum within-treatment
relative range was 3.644 percent. Baseline/candidate throughput was
4.601/4.600 MiB/s and p95 was 244.838/247.424 ms. All four samples exited zero
with exact payload validation and zero failed operations. Evidence validation
accepted all 1,043 epoch rows, and all 1,088 inventoried files passed the later
SHA-256 audit.

### Balanced Schedule And Bounded Recoveries

The append-only balanced attempt
`adaptive-receive-credit-varied-postssd-20260722-balanced60s1` used a 5-second
warmup, 60-second samples, ABBA/BAAB ordering, frozen binaries, and no stress
cells. `-ContinueOnFailure` preserved all five outcomes. The schedule-level
status is `incomplete_retained` because two cells failed their measurement
contract; this status is not rewritten after later independent recoveries.

| Cell | Original classification and reason | Independent recovery | Review disposition |
| --- | --- | --- | --- |
| `upload-1mb-x16-s1` | `neutral_local`; 1.628% range; 29.921/29.869 MiB/s; 585.411/581.314 ms p95 | Not needed | 16,576 validated epoch rows; usable local diagnostic row. |
| `duplex-64kb-x1-s16` | `invalid_environment`; 5.470% range | `neutral_local`; 0.609% range; 1.930/1.963 MiB/s; 571.650/552.152 ms p95 | Original remains environment-invalid; recovery has 1,047 validated epoch rows. |
| `download-1mb-x16-s1` | `invalid_environment`; 5.728% range | `invalid_environment`; 8.007% range | Both attempts passed correctness and schema validation, but neither is policy-effect evidence. Further retries stopped to avoid sampling-until-success bias. |
| `multiplex-1kb-x1-s100` | `invalid_contract`; sample 1 timed out during adapter start and sample 3 counter capture failed | `neutral_local`; 1.167% range; 0.962/0.973 MiB/s; 101.559/100.117 ms p95 | Original remains contract-invalid; recovery has 1,043 validated epoch rows. |
| `duplex-64kb-x4-s16` | `invalid_contract`; sample 3 counter capture failed; observed range was also 5.846% | `neutral_local`; 4.556% range; 6.773/6.720 MiB/s; 622.202/627.369 ms p95 | Original remains contract-invalid; recovery has 4,144 validated epoch rows. |

The counter failures retained zero timestamped numeric samples and reported
that `dotnet-counters` did not exit after load, was stopped, then exited with
code `-1`. The multiplex adapter-start failure was a canceled HTTP operation.
These are harness-reliability negatives, not candidate-policy losses. Separate
campaign IDs were used for every recovery; no failed cell directory, result,
manifest, or inventory was overwritten.

Across the c1 gate, the five-cell attempt, and four bounded recoveries, the ten
post-SSD local-result documents classify as five `neutral_local`, three
`invalid_environment`, and two `invalid_contract`. The eight contract-complete
documents passed evidence validation with 57,876 epoch rows and zero
validation failures. Of those, 23,853 rows belong to neutral local results;
the 34,023 environment-invalid rows remain labeled for environment/regime
analysis and must not be used as policy-effect evidence. The two
contract-invalid documents reference 4,885 retained observations, but they do
not have evidence-validation summaries and are not ML-eligible.

A fresh integrity audit rehashed all 58,323 files referenced by the ten
post-SSD checksum inventories. No path was missing and no SHA-256 mismatch was
found. Key post-SSD artifact identities are:

| Campaign/cell | Result SHA-256 | Manifest SHA-256 | Inventory SHA-256 |
| --- | --- | --- | --- |
| `postssd-guardrail-c1-60s1/upload-1mb-x1-s1` | `29b125226e8d8c1319d2825c1e4f5571610421caa66759ea6be71419d73abe97` | `5e4c21b1c762e46ccf6186a1b59304ee30cc739ea79bde24b8c6e73c781d9240` | `9d1bf387001c93541ddb80cfc94e558261c52c110fc658a875084257d6ef2bfe` |
| `balanced60s1/upload-1mb-x16-s1` | `57480ecf1bbdb1cd8a02d7143f33aad0583e4981c1c66fcbdcc7b7c3c932423e` | `dd8095de17784260199cca5ae9da16bbbbbd2a7177f1ffe59eac8dbfdd3379f0` | `dfe79ec7a0b16111375112709e6f490f7b9fea7273138f16df066e3d1604db48` |
| `recovery1-duplex-x1-s16/duplex-64kb-x1-s16` | `bf5755f257d321b2b599ae89db900df54eb094ce0ddd880df334741bef8d5700` | `a014c713c4a107bc9128fd4bab237ed6647b960772044238495b9cbb1b0c51b5` | `b1887f42cfab0561d343f5d8ad8f8be92f6108d55669f0e0fe70b338bf19d3d8` |
| `recovery1-multiplex-x1-s100/multiplex-1kb-x1-s100` | `bfa8e81bc961f61e4dbaef298fbe7ae417f0dab383c730cff803a473f0739928` | `544bd46d53b9b559df08662fcf013def27b32789bffe5fd31edcea3401a7233f` | `6af5306e16ddc11df27b07ab4db9a791889a54a9533e37c51a7cd35199fc2008` |
| `recovery1-duplex-x4-s16/duplex-64kb-x4-s16` | `fcd2051794dedc2d205e7329895e03aa2691768aec7d65d6d30eed7c89a79cb0` | `5a0e40c434a2fbe6821b1dbd00d1c0516b8b3858507a591acb63003c91998511` | `9a12158048fd5c093b86b247695b6cc03c72ab0a2519d2d322c6609a4b953638` |
| `recovery1-download-x16-s1/download-1mb-x16-s1` | `5f3383a4f77448a273f34cf72fec4fdcdc1d8baf8e8aa82dbdb64a7d0492097c` | `c7912078755dca843ebfc61a1bee3d560f3498a6d4f30388f790af07486e9d92` | `8f1ee1028e096dbb9ae933b66ecef945bd2cde65a4c9b50e57d72efea2798475` |

### Post-SSD Gate Decision

The planned non-stress varied collection is complete enough for offline
review: four distinct varied shapes now have neutral, contract-complete local
rows, while the 16-connection download shape has two explicit
environment-invalid rows. No valid row demonstrates a material receive-credit
improvement; the accepted interpretation remains neutral and diagnostic.

The next permitted activity is review, dataset curation, and offline regime
discovery using the documented provenance and exclusion labels. This evidence
does not authorize stress expansion, online learning, active controller
selection, ProtocolLab publication, or production implementation. Any derived
rule must be reviewed against the shadow-mode, acceptance, and rollback
contracts before runtime code changes begin.

## Remote Linux Worker Extension

Two independent Debian x64 workers were added after the post-SSD local
campaign. They are used as separate same-host target/load regimes, not as
publishable isolated-host benchmarks:

- `plab-worker-x64-02` has 2 logical processors and about 4 GiB RAM;
- `plab-worker-x64-03` has 6 logical processors and about 31 GiB RAM.

Both workers use the clean `quic-dotnet` commit `24a046ec`, ProtocolLab
execution snapshot `2c8e071`, .NET SDK 10.0.201, Go 1.26.5, and the repo-pinned
`dotnet-counters` 9.0.661903 tool. The Go archive was accepted only after its
SHA-256 matched
`5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053`.
The fixed-policy campaigns still perform no online exploration and authorize
no active selector.

### Provisioning Negatives

Every failed setup attempt remains retained:

- `adaptive-receive-credit-remote-x64-03-20260723-balanced30s1` failed because
  PowerShell on Linux does not support `Start-Process -WindowStyle`.
  Commit `1dafd8ba` made that parameter Windows-only.
- `adaptive-receive-credit-remote-x64-03-20260723-linuxfix-balanced30s1`
  retained five failed samples. The adapter could not build the pinned
  Raw QUIC server because the worker had SDK 10.0.302 while `global.json`
  requires 10.0.201. The empty aggregate metric objects then exposed a second
  fault: the local-cell runner accessed a missing `median` property and did
  not retain a result document.
- Commit `24a046ec` now maps missing aggregate medians to `null`. Its focused
  Release build completed with zero warnings and errors, and the
  `REQ-QUIC-CRT-0171|REQ-QUIC-CRT-0172` band passed 16 of 16 tests.
- `adaptive-receive-credit-remote-x64-03-20260723-sdk201-metricsfix-balanced30s1`
  then retained all five cells as `invalid_contract` instead of aborting. Its
  missing prerequisite was the `quic-go-raw-load` executable.
- `adaptive-receive-credit-remote-x64-03-20260723-provisioned-balanced30s1`
  ran real payload measurements after Go 1.26.5 was installed, but all five
  cells remained `invalid_contract` because runtime counters had not yet been
  restored. This campaign was allowed to finish unchanged; instrumentation
  was not changed between its samples.

These rows are harness and environment evidence only. They are not silently
merged into the contract-complete policy-effect population.

### Constrained Worker Balanced Campaign

Campaign
`adaptive-receive-credit-remote-x64-02-20260723-provisioned-balanced30s1`
completed all five fixed-policy cells. Every sample proved exact payload
correctness, every target attribution joined, every runtime-counter capture
succeeded, and all five evidence-validation summaries are valid.

| Cell | Classification | Epoch rows | Throughput median | p95 median |
| --- | --- | ---: | ---: | ---: |
| `upload-1mb-x16-s1` | `invalid_environment` | 8,846 | 50.024 MB/s | 428.718 ms |
| `duplex-64kb-x1-s16` | `invalid_environment` | 559 | 15.297 MB/s | 89.707 ms |
| `download-1mb-x16-s1` | `invalid_environment` | 8,643 | 43.039 MB/s | 491.986 ms |
| `multiplex-1kb-x1-s100` | `invalid_environment` | 560 | 5.651 MB/s | 19.822 ms |
| `duplex-64kb-x4-s16` | `invalid_environment` | 2,211 | 20.465 MB/s | 272.350 ms |

The 20,819 epoch rows are a coherent constrained/saturated-host regime. They
remain useful for offline regime discovery, but their
`invalid_environment` label excludes them from policy-effect claims.

The retained archive contains 22,767 entries and 17,628,511 bytes. Its remote
and workstation copies both have SHA-256
`6476597dc2870f50e76ead09da4e84fcf662e1cb12d2987226a6b31f4130317b`.

### Six-Core Worker Balanced Campaign

Campaign
`adaptive-receive-credit-remote-x64-03-20260723-instrumented-balanced30s1`
retained every cell and ended `incomplete_retained`, as required when any cell
fails a terminal gate.

| Cell | Classification | Epoch rows | Review result |
| --- | --- | ---: | --- |
| `upload-1mb-x16-s1` | `neutral_local` | 8,785 | Four correct samples; 211.434 MB/s and 82.152 ms p95 medians. |
| `duplex-64kb-x1-s16` | `failed_correctness` | 556 | The final candidate sample had 10 stream deadline timeouts after 14,294 completed streams. |
| `download-1mb-x16-s1` | `negative_retained` | 8,822 | Candidate throughput and p95 were effectively flat, but median peak outstanding buffer bytes increased 9.40%, from 3,758,080 to 4,111,360. |
| `multiplex-1kb-x1-s100` | `negative_retained` | 560 | Candidate throughput improved 1.86% and p95 improved 2.61%, but median peak outstanding buffer bytes increased 12.38%, from 206,848 to 232,448. The row also retained 412 `arithmetic_saturated` epochs. |
| `duplex-64kb-x4-s16` | `failed_correctness` | 1,742 | Three samples across both policies had rare stream deadline timeouts; only one candidate sample completed. |

All five evidence-validation summaries are valid, including the negative and
correctness-failure rows, for 20,465 joined epoch rows and zero validation
failures. The two negative rows demonstrate why a single universally enabled
policy remains unacceptable: throughput or latency improvements can coexist
with a material retained-memory regression.

The retained archive contains 22,412 entries and 20,808,671 bytes. Its remote
and workstation copies both have SHA-256
`d169ffebd6cdb890d48ddf1344b6c7bf4920fc934e0dbaacc69019ed65777533`.

### Remote Extension Gate

The c32 and c4-by-s100 stress extension remains blocked at this checkpoint.
The x4/s16 correctness failures occurred under both policies, so higher load
must not be assumed safe. Two new non-stress campaigns provide the next
bounded gate:

- x64-02: connection-first `legacy_current` versus `immediate`;
- x64-03: stream-first `legacy_current` versus `immediate`.

They exercise a third implementation and a different temporal order while
rechecking the failed stream shapes. No stress expansion, model training,
active policy selection, or production runtime change is authorized by this
checkpoint.

### Immediate-Policy Non-Stress Gate

Both bounded follow-up campaigns finished without changing their schedule or
instrumentation. They compare `legacy_current` with `immediate`; they do not
exercise an adaptive selector.

Campaign
`adaptive-receive-credit-remote-x64-02-20260723-instrumented-connection-first-immediate30s1`
completed its connection-first schedule:

| Cell | Classification | Epoch rows | Candidate-versus-baseline review |
| --- | --- | ---: | --- |
| `upload-1mb-x16-s1` | `invalid_environment` | 8,881 | Throughput -2.22%; p95 -1.52%; peak outstanding buffer bytes +7.80%. |
| `download-1mb-x16-s1` | `invalid_environment` | 8,667 | Throughput -2.00%; p95 -7.25%; peak outstanding buffer bytes +1.14%. |
| `duplex-64kb-x1-s16` | `neutral_local` | 559 | Throughput +2.43%; p95 -0.93%; peak outstanding buffer bytes +3.59%. |
| `duplex-64kb-x4-s16` | `invalid_environment` | 2,111 | Throughput -13.78%; p95 +3.07%; peak outstanding buffer bytes -17.83%. |
| `multiplex-1kb-x1-s100` | `negative_retained` | 556 | Throughput -2.99%; p95 +2.40%; peak outstanding buffer bytes +14.71%. |

All 20,774 rows passed the evidence contract. The three
`invalid_environment` rows remain saturation/regime evidence only. The
retained archive contains 22,722 entries and 17,658,151 bytes. Its remote and
workstation copies both have SHA-256
`716edcf2a391ec75d0595cdead17528a935ae14bc399b4ad9faf5d7dd02a1c43`.

Campaign
`adaptive-receive-credit-remote-x64-03-20260723-instrumented-stream-first-immediate30s1`
ended `incomplete_retained` after completing its stream-first schedule:

| Cell | Classification | Epoch rows | Candidate-versus-baseline review |
| --- | --- | ---: | --- |
| `duplex-64kb-x1-s16` | `negative_retained` | 559 | Throughput -9.99% and p95 +5.65%, despite peak outstanding buffer bytes decreasing 17.71%. |
| `duplex-64kb-x4-s16` | `failed_correctness` | 1,962 | Both baseline samples failed exact-payload validation with four protocol errors each; both candidate samples passed. The row is excluded rather than attributed to either policy. |
| `multiplex-1kb-x1-s100` | `neutral_local` | 560 | Throughput -0.70%; p95 +1.01%; peak outstanding buffer bytes -5.88%. |
| `upload-1mb-x16-s1` | `negative_retained` | 8,790 | Throughput -0.49%; p95 +0.37%; peak outstanding buffer bytes +6.20%. |
| `download-1mb-x16-s1` | `neutral_local` | 8,824 | Throughput +0.26%; p95 +0.75%; peak outstanding buffer bytes -6.16%. |

All 20,695 rows passed the evidence contract, including the explicitly
excluded correctness-failure row. The retained archive contains 22,642
entries and 21,080,641 bytes. Its remote and workstation copies both have
SHA-256
`06e576a13d21f98581579b0f812b6a64b1e13bb5f2f8edf6a074070ecb51e04c`.

The immediate-policy evidence reinforces the conservative decision. It
contains useful neutral rows and memory reductions in some shapes, but also
throughput/latency losses, memory regressions, saturation-sensitive rows, and
a repeated x4/s16 correctness boundary. The c32 and c4-by-s100 stress
extension therefore remains blocked.

### Remote Round-Robin Offline Dataset

The four contract-complete remote campaigns were materialized together on
`plab-worker-x64-03` as
`offline-review-remote-roundrobin-20260723-v1`. The input contained 20 local
results and 82,753 epoch rows. Evidence validation joined every row, with zero
unmatched results and zero unmatched epoch rows.

The normalized classification population is:

| Classification | Rows |
| --- | ---: |
| `invalid_environment` | 40,478 |
| `failed_correctness` | 4,260 |
| `neutral_local` | 18,728 |
| `negative_retained` | 19,287 |

Default curation includes 25,981 rows and excludes 56,772. Inclusion requires
the row-level analysis exclusion flag to be exactly `none`; 12,931 included
rows are `neutral_local`, and 13,050 are explicitly retained negative
evidence. The excluded population preserves environment-invalid,
correctness-failed, warmup, observation-saturated, observation-missing, and
terminal-partial epochs rather than dropping or relabeling them.

The dataset contains four campaigns, five workload-family keys, two host
fingerprints, and one frozen binary cohort. Its split status is
`insufficient_group_diversity`: the contract requires at least three workload
families and three host fingerprints before train, validation, and test can be
populated without crossing host and workload holdouts. All 82,753 rows are
therefore `holdout_blocked`; no training split and no model were produced.

The validated artifact identities are:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `catalog/policy-catalog.json` | 11,030 | `1815d9e8222eef980ae95f9dd498a3ef20be1078130921e677df748fdcd9606a` |
| `normalized/normalized-dataset.json` | 391,489,331 | `aedfa8a7cfd05da816182384c145d5842f68d8330866b561a06473e5c20bb096` |
| `curated/curated-manifest.json` | 95,030,728 | `90b400c2331f90e73ce58aea7061465b269cfcd8f1f6b166e36617d90ffeba23` |
| `split/split-manifest.json` | 75,280,748 | `b76177b8f7f124a271780093bbcef6683a8426d02366bc47822a36e816db846e` |

The full materialization took about 94 minutes on the six-core worker. Its
append-only local archive contains nine entries and 18,843,666 bytes, with
SHA-256
`f1898c28c9eea24fe44c06ca7530bbfa46f8a89be58b51d28f544d8fea523f54`.
This run time is capacity-planning evidence for later pipeline work, not
authorization to optimize or change the pipeline during this planning period.

# Raw QUIC Performance Evidence Plan

Updated: 2026-07-16

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

### Live coverage audit on 2026-07-16

The current public page is newer than the two-row snapshot above, but it still
does not provide a decision-ready transport baseline. It reports four tested
implementation ecosystems, fourteen exact targets, six observed raw QUIC
scenarios, fifty-five current rows, and zero rows eligible for a public
performance claim. The newest evidence is dated 2026-07-16. The observed
scenario set is connection churn, duplex streams, cold handshake, 1 KiB echo,
100x64 KiB multiplex, and 1 MiB upload throughput. Large-payload scaling,
small-stream scheduling, sustained directional transfers, and the large duplex
shape are therefore absent from the public comparison surface.

A read-only controller dry-run confirmed that stale registered packages, not
missing public contracts, are now the immediate breadth blocker. All three
peers resolve only for 1 MiB throughput and 100x64 KiB multiplex; most lifecycle
rows resolve only quic-go, stream-limit and stream-churn coverage is absent, and
slow-reader selection cannot find the packaged comparison suite. No package was
uploaded, registered, or published and no job was submitted.

The source-backed inventory now also includes the exact mixed-size workload
`quic.transport.multiplex.mixed-4x16`. Public commit `8e1d3f4`, component
commit `cbcea9f`, internal commit `75357a1`, and Incursa commit `e7d23130`
define four stable connections, sixteen concurrent streams per connection, and
a deterministic 1 KiB/16 KiB/64 KiB/1 MiB round-robin payload sequence. The
runner validates 9,052,160 bytes per connection batch from the declared
contract, rather than treating the 1 MiB maximum as a uniform stream size.

Clean package-backed localhost diagnostics passed exact validation for Incursa
and quic-go with no failed or timed-out streams. Incursa measured
46,946,593.49 B/s and quic-go measured 54,075,853.60 B/s in one short c4/s16
repetition. This is functional and directional evidence only. MsQuic package
selection was exact, but the host reported `System.Net.Quic.IsSupported=false`,
so no MsQuic performance result exists for this smoke. The package hashes and
test totals are retained in `performance-improvement-wishlist.md`.

This addition strengthens the offline coverage matrix but does not repair the
public comparison by itself. No package was registered and no rack campaign or
publication ran. The next proposed contract gaps are controlled network
impairment (RTT, loss, and reordering), sustained small writes on stable streams,
and one-stream-per-connection fanout. Those lanes must preserve exact payload
and content validation, then pass matched five-repetition c4/c16/c32 campaigns
with isolated target and generator telemetry before supporting runtime tuning
or public peer claims.

Sustained small-write pressure is now also represented by the exact
`quic.transport.sustained-download.4096x1kb` contract. Public commit `7efcec4`,
component commit `3e04d81`, internal commit `cdf4778`, and Incursa commit
`d3644aca` require one stable bidirectional stream, exactly 4,096 sequential
server writes of 1,024 bytes, and 4,194,304 content-validated bytes. The
scenario definition has identical SHA-256
`386e543bdf3eb8ccf3eabee9b435d1663583f2f69bf20f1619271e3629b8789d`
across the public, component-package, and internal-runner copies.

Clean package-backed localhost diagnostics passed exact validation for Incursa
and quic-go with zero failures or timeouts. One short shared-host sample measured
Incursa at 39,213,386.37 B/s and 592.84 ms p95, and quic-go at 49,448,791.74
B/s and 378.91 ms p95. MsQuic package selection was exact, but this Windows
host reports `System.Net.Quic.IsSupported=false`. These results are functional
and directional evidence only, not a peer ranking.

The first smoke also found a ProtocolLab evidence defect: actual commands used
four connections and one stream per connection, while aggregate metadata
reported effective concurrency 128 from a generic profile default. ProtocolLab
internal commit `6cb1e06` fixes the runner plan and packaged-executor environment
to derive raw QUIC concurrency from the executed controls. Its regression test
passed along with all 241 `LoadToolInvokerTests`. Follow-up package-backed run
`raw-smallwrites-loadshape-fixed-d-20260716-direct-package-cell` passed exact
validation and benchmark execution, reported requested and effective concurrency
4, completed 28 transfers and 117,440,512 received bytes, and recorded zero
failures or timeouts. The original diagnostic remains reviewable under
`C:\shared\temp\protocol-lab-small-writes-smoke-20260716`; the corrected proof
is under `C:\shared\temp\protocol-lab-small-writes-loadshape-fixed-d-20260716`.
No package was uploaded or registered and no rack job or publication ran.

Offline coverage is now aligned for the five expanded peer shapes. Component
commit `558a29d` packages the exact public comparison suite, advertises the
existing sustained-download executor behavior, and advances quic-go target
support to 64 KiB/16 MiB upload, 100x1 KiB/16x1 MiB multiplex, and 16x1 MiB
duplex. Internal commit `6856861` forwards exact scenario/protocol identity to
target processes so target behavior does not infer direction from payload size.
The clean package hashes are:

| Package | Version | SHA-256 |
| --- | --- | --- |
| `org.protocol-lab.components.executor.quic-go-raw-load` Windows | `0.1.13` | `fc5dab790af32350f564b0db392ad2ec83e25e5687a55a8342002f9d2783b894` |
| `org.protocol-lab.components.implementation.quic-go-raw` | `0.1.16` | `dc8cdba6970bf81c6ed994c4c2f5defadddffd641fc52ba84ae7d117954a3b01` |
| `org.protocol-lab.components.scenario.raw-quic-transport` | `0.1.15` | `aa456e933441df661a7c2d0c70805abbf7c667e5c4181040543c58877a63f006` |

Package-to-package one-second diagnostics passed all five new shapes with zero
failed operations or timeouts and exact directional byte accounting. These are
behavior smokes only. The next decision-ready step remains an operator-approved
package refresh and a five-repetition, deterministic round-robin
Incursa/quic-go/MsQuic rack campaign with target and generator telemetry.

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

The workload contract is also ready for a materially broader rerun. Public
ProtocolLab commit `69edaed` and internal commit `ed7b177` add the
dimension-neutral `raw-quic-peer-confidence` profile. It supplies 15-second
measurement windows, 5-second warmups, cooldowns, five repetitions, and a
non-publishable comparison boundary without overriding scenario dimensions.
Handshake, throughput, multiplex, connection-churn, and duplex scenarios now
retain their own stream shapes across c1/c4/c16/c32/c64/c128. The campaign uses
round-robin peer ordering and includes all five workload families.

The public repository-health workflow, 102 contract tests, 84 raw execution
and package tests, and temporary component-package production passed. This is
local readiness evidence only; no packages were registered and no lab jobs ran.

The reusable peer package gap is now closed offline. Public ProtocolLab commit
`cd12d21` defines connection churn separately from stable-connection stream
churn and adds the five-scenario comparison suite. ProtocolLab Components
commit `4a81387` promotes the tested lifecycle-aware quic-go executor, and
internal commit `39dc882` aligns the internal scenario filename with its ID.
Clean immutable builds produced:

- raw scenario pack `0.1.7`, SHA-256
  `378c8657e7b114c0168fc66d0cdef6dffd06c02eb82f6f9d6c4de832c05f2278`;
- quic-go target `0.1.9`, SHA-256
  `dd0efec4748420b1f546c988b63c2a309d7aeb6124f86bcfcff889f4c9485b89`;
- Windows quic-go executor `0.1.5`, SHA-256
  `5a7e4e0afe9b8e9dbfee03ba4e129af32b32fe7387257d34f3dcfa49633cd15b`;
  and
- Linux quic-go executor `0.1.5`, SHA-256
  `b716bfa7d8f9fb8fead289786dc57620360d7733006af79faf96d6396eb1b60a`.

The Incursa, MsQuic/System.Net.Quic, and quic-go target manifests now have an
exact offline intersection for cold handshake, connection churn, 1 MiB stream
throughput, 100-stream multiplex, and duplex peer matrix. A package-to-package
Windows smoke completed 232 fresh connection-and-stream operations and 300
cold handshakes in bounded 250 ms diagnostic windows with zero failures or
timeouts and exact bidirectional byte symmetry. This proves package behavior
and matrix eligibility locally; it is not matched rack evidence or a ranking.

Public contract commit `ff870ee`, reusable component commit `32507af`, internal
runner commit `f23b47e`, and Incursa commit `bee9068a` add two more matched lanes. The 1 KiB latency
scenario preserves its c1/c4/c16/c32/c64/c128 ladder, while stream-limit
pressure remains a one-connection, 100-concurrent-stream semantic capacity
check. Incursa, MsQuic/System.Net.Quic, and quic-go all advertise both lanes;
the shared executor validates the canonical `latency-echo` and
`stream-limit-pressure` behavior names. Together with both duplex variants,
the clean target packages have an exact eight-scenario intersection. The large
1 MiB bidirectional payload
lane is intentionally not advertised by quic-go because that target caps echo
responses at 64 KiB. Focused Go tests, 125 ProtocolLab parser/validator/adapter
tests, 20 Incursa package-template tests, all 84 component manifest pairs, and
the public repository-health workflow passed. Clean package production yielded:

- scenario pack `0.1.8`: `5ff08be7d06f19194da114648574c724c5fd0ee8925bbf1168047850518c0ea0`;
- quic-go target `0.1.11`: `ffb11cc8a03e19a0e0183e15bafe713164e7c9b4077cd9ac80a068d7cf01ed34`;
- Windows executor `0.1.6`: `ea41cbf54a339c0d34c2330947d63fc0c8193a2b7e95bdb00fc39a799157ba3b`;
- Linux executor `0.1.6`: `9b9ee69e69dd81618d3227ecec439e6ee0ec4c07d345444fe5502df45c68e89e`;
- Incursa target `dev-bee9068a-clean`: `3d6364fb924cc19d7f2e36e486ad3ee2d26694c061b4cdb8037c8542cd3fb409`;
- Windows MsQuic target `0.1.2-dev-f23b47e`: `8f51fb59274cceb4c7002d0b147237d3c9b17a28233d65325f6ed0ecf5b19b83`;
- Linux MsQuic target `0.1.2-dev-f23b47e`: `0c1ac872216ae224eb4152e2ad46d6eeeecb0ad1882fe70b3e24a58add3bde35`.

A bounded 250 ms package-to-package Windows smoke completed 3,660 c4 latency
streams and 200 c1/s100 stream-limit operations with zero failures or timeouts
and exact sent/received byte symmetry. Live matched rack evidence remains
pending; no registration, deployment, or campaign ran.

Stream-churn parity is now complete offline. Public contract commit `cc149c7`
defines 1,000 sequential bidirectional 128-byte streams on one stable
connection and fixes the total expected byte count to 256,000. Component commit
`5be4862` adds real executor dispatch and immutable package versions, internal
commit `0a51cfe` adds Incursa/MsQuic adapter and campaign parity plus behavior
validation for every raw scenario, and Incursa commit `e5a5304d` advertises the
lane from the source-backed package. Focused execution, adapter, and contract
tests passed 143/143; Incursa package-template tests passed 20/20; Go executor
tests and all 90 component manifest pairs passed. Clean parity-eligible packages
were produced without registration:

- Linux quic-go executor `0.1.8`:
  `ef178d6cfd86bc203a45cfbb12cf0247ab36b6b676f56a6348800edf2e4df127`;
- Windows quic-go executor `0.1.8`:
  `a848dc00cfb18a4aba6a824bf3401839394920f4c709fe489bd717631ebf307c`;
- raw scenario pack `0.1.10`:
  `f8975470af05673f68b66c7598faad86cf39d2b1205a6f1268b9a4a0cb2b7fa3`;
- Incursa Linux target `dev-20260716T064015Z-e5a5304d-clean`:
  `22451ecf8a71261f285b636507421f019ef51793b357faea05a2df831192f961`;
- MsQuic Linux target `dev-20260716T064043Z-0a51cfe-clean`:
  `b6c45f220ffc4dd394056547be0df36f4ca3b59f1b95e27f6ba6d0fbda94ca68`.

The five attestations match their archives and all five package manifests
reference the exact stream-churn identity. This proves clean package inventory,
not package-backed rack execution or performance.

A read-only controller dry-run on 2026-07-16 confirms the live package catalog
is still behind this offline set. Throughput and multiplex resolve all three
targets; cold handshake, connection churn, latency, and duplex resolve only
quic-go; stream churn and stream-limit pressure resolve no runnable targets;
and slow-reader planning fails because the registered scenario inventory does
not provide its suite. The preview retained the intended confidence profile,
Comparison workflow, five repetitions, and round-robin ordering. No job was
submitted. The dry-run artifact is
`C:\shared\temp\protocol-lab-raw-stream-churn-20260715\controller-peer-matrix-dryrun.json`.

The source-backed matrix is now broader than the live catalog. Public commit
`a5ac2dd`, component commit `8ce81ff`, and internal commit `bcfda50` add five
orthogonal workload shapes:

- `quic.transport.stream-throughput.64kb` and
  `quic.transport.stream-throughput.16mb` isolate single-stream payload-size
  scaling around the existing 1 MiB lane;
- `quic.transport.multiplex.100x1kb` isolates stream scheduling with little
  aggregate data;
- `quic.transport.multiplex.16x1mb` combines bounded fanout with 16 MiB in each
  direction; and
- `quic.transport.duplex-streams.16x1mb` exercises simultaneous application
  reads and writes under the same large aggregate payload.

All scenarios retain exact expected-byte validation. Focused internal tests
passed 81/81, all 91 public/internal component manifest pairs passed, and the
Go executor tests passed. Clean local packages were built without registration:

- scenario pack `dev-20260716-expanded-raw`, SHA-256
  `601fbb52196fbb8b931ac071df3ef0ec7975b2da243ac41858a8a5997b8524bb`;
- Windows source-backed quic-go executor `dev-20260716-expanded-raw`, SHA-256
  `2da31eeea109e96294937aab343be346679d57d07be9aa24dbb1b09b8b189197`.

Four of five initial Incursa source-backed smokes passed exact validation and
benchmark execution. The 100x1 KiB multiplex lane had one warmup read timeout,
then passed an isolated rerun with the same shape. This is retained as a
variance and reliability warning, not classified as a runtime defect or
discarded as noise. Repeated c1/c4/c16 evidence is required before tracing or
tuning. These runs are local, shared-host, and non-publishable; no package was
uploaded or registered, no service was deployed or restarted, and no result
was published.

The required c1/c4/c16 matrix is now complete for these five new shapes: five
repetitions per cell, 75 measured runs in total, with exact byte validation.

| Concurrency | Scenario | Validation | Benchmark | Median MiB/s | Range | p95 ms |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 64 KiB throughput | 5/5 | 5/5 | 35.31 | 13.6% | 2.9 |
| 1 | 16 MiB throughput | 5/5 | 4/5 | 31.22 | 111.1% | 516.0 |
| 1 | 100x1 KiB multiplex | 5/5 | 5/5 | 6.46 | 9.3% | 15.6 |
| 1 | 16x1 MiB multiplex | 5/5 | 5/5 | 17.26 | 3.4% | 996.5 |
| 1 | 16x1 MiB duplex | 5/5 | 5/5 | 17.96 | 7.0% | 936.2 |
| 4 | 64 KiB throughput | 5/5 | 5/5 | 118.37 | 4.9% | 3.2 |
| 4 | 16 MiB throughput | 5/5 | 5/5 | 140.57 | 12.4% | 538.9 |
| 4 | 100x1 KiB multiplex | 4/5 | 4/5 | 16.23 | 13.8% | 28.1 |
| 4 | 16x1 MiB multiplex | 5/5 | 5/5 | 56.89 | 38.0% | 1,174.2 |
| 4 | 16x1 MiB duplex | 5/5 | 5/5 | 61.77 | 5.4% | 1,112.9 |
| 16 | 64 KiB throughput | 5/5 | 5/5 | 82.95 | 20.7% | 7.9 |
| 16 | 16 MiB throughput | 5/5 | 5/5 | 236.47 | 3.3% | 1,016.7 |
| 16 | 100x1 KiB multiplex | 3/5 | 2/5 | 20.69 | 104.0% | 80.8 |
| 16 | 16x1 MiB multiplex | 5/5 | 5/5 | 37.68 | 15.8% | 6,463.1 |
| 16 | 16x1 MiB duplex | 5/5 | 5/5 | 118.00 | 3.1% | 2,077.4 |

This matrix disproves the broad interpretation that Incursa raw QUIC is simply
slow. It instead identifies high-fanout completion and small-stream scheduling
as the current transport-level problem. A counter run of c16 100x1 KiB found
maximum total shard depth 227, maximum delayed sends 105, maximum retained sent
packets 140, and a peak of 991 pooled buffers; target CPU remained low and the
thread-pool queue stayed empty. A clean CPU trace was predominantly waiting,
not executing hot runtime code, and ended at 3,199/3,200 completed streams with
exact sent and received payload bytes.

Internal commits `2e30595` and `4518a22` make EOF failures reviewable by
reporting zero-based connection and stream indexes, QUIC stream ID, and
per-stream received/expected bytes. In a fresh five-repetition diagnostic the
failed coordinates varied, and the two measured failures each delivered all
1,638,400 bytes before one stream missed EOF. A subsequent three-repetition
run passed every cell. Incursa commit `608b5d86` independently proved 100-stream
silent FIN loss recovery in 10 consecutive runs. The evidence therefore
supports a multi-connection progress investigation and additional directional
coverage, not a speculative shard-count, pool-size, or retransmission change.

That multi-connection investigation is now complete. A 16-connection,
100-stream-per-connection integration test reproduced incomplete server
`CompleteWritesAsync` operations even though every client had received exact
payload bytes and EOF. The remaining completion requests had already been
removed from the pending-action ledger. Under congestion, the runtime could
have a small positive send budget that could not fit even a FIN-only STREAM
header. The scheduler classified that valid queued frame as invalid, and the
direct-send fallback removed the caller request without completing it.

Incursa commit `52701dcb` classifies that condition as transient budget
exhaustion, retains the queued FIN for congestion recovery, and ensures a true
non-transient failure after queue commitment completes the caller with an
exception instead of hanging. The exact high-fanout proof passed 20/20 stress
repetitions. Focused scheduler, standalone-FIN, listener-resilience, public API,
and RFC 9000 gates passed. The broad test project passed 9,584 tests with five
skips and one unrelated HTTP/3 close-notification timeout that passed 5/5 exact
reruns; the solution-level command also reported the already absent
`eng/tools/Incursa.Quic.TraceAnalysis` project in this worktree.

The post-fix source-backed run
`local-raw-c16-100x1kb-budget-fix-20260716-quic-transport-v1-comparison`
passed exact validation and benchmark execution 5/5, with zero failed or
timed-out requests. Its median throughput was 25.45 MiB/s and median p95 latency
was 64.35 ms. The run is local shared-host evidence with variance and readiness
blockers, so it proves the progress fix but does not establish a publishable
throughput improvement. No package was registered, no lab service changed, and
no result was published.

## Exact Download Coverage Added 2026-07-16

The contract-first `quic.transport.stream-download.1mb` lane now isolates the
server-to-client send path. Its 16-byte request control prelude is excluded
from payload metrics; each operation must receive exactly 1 MiB and validate
every byte against the deterministic `offset % 251` pattern. The runner also
rejects reversed byte accounting for this direction.

The aligned commits are public `63242f4`, components `0032d2a`, internal
`42f937b`, and Incursa `a450928a`. Local immutable package evidence is:

| Package | Version | SHA-256 |
| --- | --- | --- |
| `org.protocol-lab.components.scenario.raw-quic-transport` | `0.1.12` | `e434f72a3fd92afde2ec3dad0e17205d942ec4d8a6c8d08bb4e612529f705e0a` |
| `org.protocol-lab.components.executor.quic-go-raw-load` Windows | `0.1.10` | `f3f5af7320b51e4fc20e1fb27d1d2061ea29c5a7a4da355bedb0fed233cce96e` |
| `org.protocol-lab.components.implementation.quic-go-raw` | `0.1.13` | `0279f2590b58eb41f74ba2c81c6387a31795c0437b37373d90ef4d9e723f9c98` |

All three first local c1 diagnostics passed exact validation with zero failed
or timed-out operations:

| Target | Retained run | Throughput | p95 |
| --- | --- | ---: | ---: |
| Incursa | `raw-download-smoke-20260716-quic-transport-v1-comparison` | 38.21 MiB/s | 29.68 ms |
| MsQuic | `raw-download-msquic-smoke-20260716-quic-transport-v1-comparison` | 181.44 MiB/s | 6.49 ms |
| quic-go | `raw-download-quicgo-smoke-20260716-direct-package-cell` | 61.79 MiB/s | 17.59 ms |

This is a sequential one-repetition shared-host diagnostic, not a matched or
publishable peer ranking. It does establish a concrete Incursa
server-to-client gap worth profiling before broad HTTP/3 tuning. The next
authoritative campaign must run all three targets in deterministic round-robin
order at c1/c4/c16/c32/c64/c128, use at least five repetitions, retain target
and generator telemetry, and prove source/package parity. No package was
uploaded or registered and no controller, worker, job, or publication changed.

## Rejected Fixed-Burst Optimization 2026-07-16

The first Incursa download profile showed that `QuicSendPolicy` releases at
most four queued application datagrams after each recovery-progress event. A
counter and sampled-CPU diagnostic found low thread-pool pressure, no measured
retransmission buildup, and a maximum of 13 delayed sends, making that fixed cap
a credible c1 candidate. Raising the cap to ten improved the isolated c1
download median from 36.57 to 40.49 MiB/s and reduced p95 from 36.20 to 31.06 ms.

The same candidate was neutral at c4 and c16 and did not improve the
high-fanout shape:

| Workload | Four-datagram control | Ten-datagram candidate | Decision signal |
| --- | ---: | ---: | --- |
| download c1 | 36.57 MiB/s, 36.20 ms p95 | 40.49 MiB/s, 31.06 ms p95 | isolated gain |
| download c4 | 104.88 MiB/s, 44.05 ms p95 | 103.23 MiB/s, 45.06 ms p95 | neutral/noisy |
| download c16 | 181.24 MiB/s, 98.16 ms p95 | 181.59 MiB/s, 91.93 ms p95 | throughput neutral, candidate variance higher |
| c16/s100 multiplex | 24.04 MiB/s, 64.13 ms p95, 10.18% range | 24.60 MiB/s, 69.05 ms p95, 34.12% range | reject for latency and instability |

Every cell passed exact validation 5/5 with no failed or timed-out operations.
The code was restored to four datagrams and the experiment is retained as a
negative result. A larger constant is not a general raw QUIC scaling fix. The
next diagnostic coverage must capture congestion window, bytes in flight,
available send bytes, datagrams released per recovery event, blocked reason,
and write-completion latency. Any next scheduler candidate must be paced or
ACK/recovery proportional and must be evaluated on download plus high-fanout
multiplex and duplex lanes before acceptance.

## Recovery Send Decision Telemetry Added 2026-07-16

Incursa now emits bounded-tag recovery send metrics for congestion window,
bytes in flight, available send bytes, budgeted and flushed datagrams, queue
depth before and after release, outcome, and blocked reason. ProtocolLab counter
capture retains these instruments alongside the existing shard queue delay,
buffer retention, sent-packet retention, and stream-write completion metrics.

The source-backed c1 download diagnostic
`raw-download-recovery-metrics2-20260716-quic-transport-v1-comparison` and c16/s100
multiplex diagnostic
`raw-multiplex-recovery-metrics-20260716-quic-transport-v1-comparison` both passed
exact validation with zero failed or timed-out operations. The c16/s100 run
observed maximum shard depth 222, packet/write queue delay 62.44/63.19 ms,
88 delayed sends, 1,268 outstanding pooled buffers, and 70.88 ms maximum sampled
write completion. Maximum observed one-second decision rates included 553 burst
limit outcomes, 428 post-policy congestion-blocked flushes, and ten policy-level
congestion-blocked outcomes.

This isolates the next candidate: when less than one full datagram remains in
the congestion window, the policy currently exposes all remaining packet bytes
as STREAM-frame payload even though short-header, packet-number, AEAD tag, and
ACK headroom must still fit. The later congestion preflight rejects those
attempts. The next experiment must make the partial-datagram payload budget
packet-overhead-aware, preserve standalone FIN progress, and prove fewer futile
flushes plus no c1/c4/c16 or high-fanout regression. Counter-attached numbers are
diagnostic and must not be used as throughput claims.

## Rejected Partial-Datagram Budget Optimization 2026-07-16

An overhead-aware send-policy candidate reserved 50 bytes of packet overhead
when less than one full datagram remained in the congestion or
anti-amplification budget. The counter-attached c16/s100 run
`raw-multiplex-overhead-budget-candidate-20260716-quic-transport-v1-comparison`
proved the intended mechanism: maximum observed one-second post-policy
`flush_blocked` decisions fell from 428 to 2, policy-level `budget_blocked`
decisions rose from 10 to 401, and maximum outstanding pooled buffers fell from
1,268 to 940. It did not improve the whole service boundary: maximum packet and
stream-write queue delay increased from 62.44/63.19 ms to 69.50/78.75 ms.

Uninstrumented c16/s100 evidence was favorable but insufficient. Candidate
runs `raw-multiplex-overhead-budget-candidate5-20260716-quic-transport-v1-comparison`
and `raw-multiplex-overhead-budget-candidate5b-20260716-quic-transport-v1-comparison`
reached 25.60/24.97 MiB/s and 62.38/59.49 ms p95 around control
`raw-multiplex-overhead-budget-control5-20260716-quic-transport-v1-comparison`
at 24.42 MiB/s and 67.45 ms p95.

The mandatory exact 1 MiB download guardrail rejected the candidate. Against
the retained burst-four baselines, c1 was neutral-to-better, c4 modestly worse,
and c16 reached 167.02 MiB/s with 118.73 ms p95 versus 181.24 MiB/s with
98.16 ms p95. The immediately adjacent c16 control
`raw-download-overhead-budget-c16-control5-20260716-quic-transport-v1-comparison`
reached 168.13 MiB/s with 108.58 ms p95, confirming a 9.35 percent latency
regression even when throughput was effectively neutral. All compared cells
passed exact validation 5/5 with zero failures or timeouts.

The runtime remains on the prior policy and the experiment is retained as
negative evidence. Early rejection of payloads that cannot fit packet overhead
is not sufficient by itself. A materially different next candidate must retain
useful partial sends and change pacing, coalescing, or ACK-proportional release
timing, with both high-fanout multiplex and bulk-download latency as acceptance
gates.

## Rejected ACK-Proportional Immediate Release 2026-07-16

The next candidate converted newly acknowledged protected packet bytes into an
immediate application-send datagram allowance, preserving a floor of four and a
service-boundary cap of sixteen. Focused API, congestion, recovery, RFC 9000,
and RFC 9002 tests passed 1,067/1,067.

Counter run
`raw-multiplex-ack-proportional-metrics-20260716-quic-transport-v1-comparison`
proved that aggregated ACKs produced budgets up to 16 and flushes up to 13.
Against the fixed-four counter run, maximum outstanding buffers fell from 1,268
to 1,151 and maximum sampled stream-write completion fell from 70.88 to
68.63 ms. The same run raised maximum packet/write queue delay from 62.44/63.19
to 69.38/69.75 ms, delayed sends from 88 to 161, and post-policy blocked flushes
from 428 to 483.

Uninstrumented run
`raw-multiplex-ack-proportional-candidate5-20260716-quic-transport-v1-comparison`
passed exact validation 5/5 with no failures or timeouts, but reached only
24.64 MiB/s with 70.40 ms p95. The fixed-four control reached 24.42 MiB/s with
67.45 ms p95. The throughput difference is neutral and the 4.38 percent latency
regression fails the high-fanout guardrail, so the candidate was restored before
running the download ladder.

ACK-byte credit must not be retried as a larger immediate burst. A materially
different follow-up needs time-domain pacing or packet coalescing that reduces
timer and send wakeups without adding queue service pressure to the ACK-handling
transition.

## Sustained Upload Coverage Added 2026-07-16

`quic.transport.sustained-stream.256x64kb` now isolates repeated application
writes on one long-lived stream. Each operation writes 256 sequential 64 KiB
chunks from client to server and requires exact receipt of 16 MiB. The aligned
commits are public `f5fccb6`, components `60b8023`, internal `1d16ae5`, and
Incursa `6caa4d79`.

Source-backed local five-repetition ladders produced the following diagnostic
results with exact validation, zero failed operations, and zero timeouts:

| Connections | Validation | Benchmark | Median throughput | Relative range | Median p95 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5/5 | 5/5 | 36.94 MiB/s | 18.9% | 511.12 ms |
| 4 | 5/5 | 5/5 | 128.66 MiB/s | 26.3% | 671.77 ms |
| 16 | 5/5 | 5/5 | 230.46 MiB/s | 5.6% | 1,005.24 ms |

The runner classified possible generator saturation at every point and possible
or unknown target saturation. These localhost/shared-host results establish a
working workload and a profile target, not a peer ranking or publishable claim.

Counter-attached run
`codex-sustained-c16-counters-path-20260716-direct-package-cell` showed balanced
receive work across eight shards. Per-shard maximum depth ranged from 28 to 38,
packet-receive enqueue counts ranged from 97,307 to 97,453, mean packet queue
delay ranged from 4.82 to 6.86 ms, and peak delay was 32.44 ms. Flow-control
credit queue delay averaged 3.93 to 5.11 ms and peaked at 26.94 ms. Delayed
application sends, retained application-send buffers, and pending
retransmissions stayed at zero. Pooled buffers peaked at 143/589,824 bytes and
drained to zero. This supports a future receive scheduling/batching experiment
only after the pressure reproduces with isolated target and generator telemetry.

The first direct-package execution without component materialization is retained
as `load-tool-unavailable` evidence. Two counter attempts also retained honest
`tool-unavailable` artifacts because the materialized catalog root could not
resolve the restored repo-local tool manifest. The successful run placed the
declared `dotnet-counters` version explicitly on `PATH`. No package was uploaded
or registered, no controller/worker/job changed, and nothing was published.

## Sustained Download Coverage Added 2026-07-16

`quic.transport.sustained-download.256x64kb` mirrors the sustained upload shape
in the server-to-client direction. Each operation requests and validates an
exact deterministic 16 MiB response delivered as 256 sequential 64 KiB server
writes on one long-lived bidirectional stream. The aligned commits are public
`09fdb35`, components `40fc0ae`, internal `2213c24`, and Incursa `1bf25ae7`.

Source-backed local five-repetition ladders produced the following diagnostic
results with exact content validation, zero failed operations, and zero
timeouts:

| Connections | Validation | Benchmark | Median throughput | Relative range | Median p95 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5/5 | 5/5 | 35.04 MiB/s | 7.2% | 570.90 ms |
| 4 | 5/5 | 5/5 | 105.60 MiB/s | 27.6% | 675.74 ms |
| 16 | 5/5 | 5/5 | 177.10 MiB/s | 7.3% | 1,340.93 ms |

The retained upload medians were 36.94, 128.66, and 230.46 MiB/s at the same
connection counts. The widening c16 directional gap is diagnostic evidence of
server send-path pressure, not a peer ranking. The shared-host runner reported
possible or unknown target saturation; generator saturation was not detected at
c4 or c16.

Counter-attached run `sd-dl-c16-ctr-20260716-direct-package-cell` passed exact
validation and completed 64 transfers / 1 GiB with zero failures or timeouts.
Across eight shards, queue depth peaked between 29 and 56. Stream-write queue
delay averaged about 6-7 ms and peaked at 24.03 ms. Oversized-write continuation
was the only application-send queue cause: delayed sends and retained buffers
peaked at 4-10 per shard, while direct-send-blocked, pending-retransmission, and
small-write-delay retention remained zero. Sent-packet retention peaked at
94-168 packets per shard with oldest observed age below 38 ms. Aggregate pooled
buffers peaked at 829 / 1.95 MiB and ended at 19 / 3 KiB. Stream write
completion averaged 6.69 ms and peaked at 22.41 ms. This evidence prioritizes
the incomplete-write continuation and send scheduling path over generic pool
resizing.

The first materialized smoke is retained as a launch prerequisite failure: its
executor path exceeded the Windows process path limit even though the package
and materialization both contained the executable. Re-running with an explicit
short materialization root passed. No package was uploaded or registered, no
controller/worker/job changed, and nothing was published.

## Oversized-Write Continuation Improved 2026-07-16

The sustained-download trace identified an avoidable quadratic-shaped copy
path: every partial STREAM send rented a new owner and copied the complete
shrinking unsent tail. The accepted implementation keeps the queued owner and
stream bytes in place, writes the next STREAM header immediately before the
unsent data, and advances a validated payload offset/length. The fragment still
gets its own owner because sent-packet tracking and retransmission require it.
This does not change congestion control, flow control, retransmission, FIN,
cancellation, write-gate serialization, or packet protection semantics.

Permanent BenchmarkDotNet evidence:

| STREAM data | Rent and rebuild | Advance header | Ratio |
| ---: | ---: | ---: | ---: |
| 32 KiB | 679.45 ns | 35.18 ns | 0.05 |
| 64 KiB | 1,298.63 ns | 35.38 ns | 0.03 |

Counter/trace run `sd-dl-zc2-c16-ctr-20260716-direct-package-cell` passed exact
64-transfer / 1 GiB validation with zero failures/timeouts. Its sampled pool
rent rate was 84,421/s versus 106,888/s in
`sd-dl-c16-ctr-20260716-direct-package-cell`; sampled rented-byte rate was
206.1 versus 664.9 MiB/s. Maximum outstanding buffers, queue depth, delayed
sends, and retained packets did not consistently improve. Instrumentation and
run variance prevent an end-to-end claim from this comparison.

Matched 3-second, one-second-warmup, five-repetition source-backed ladders all
passed exact validation and benchmark execution:

| Connections | Control throughput | Candidate throughput | Delta | Control p95 | Candidate p95 | Delta |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 35.04 MiB/s | 35.72 MiB/s | +2.0% | 570.90 ms | 538.39 ms | -5.7% |
| 4 | 105.60 MiB/s | 101.59 MiB/s | -3.8% | 675.74 ms | 700.35 ms | +3.6% |
| 16 | 177.10 MiB/s | 175.79 MiB/s | -0.7% | 1,340.93 ms | 1,337.01 ms | -0.3% |

These shared-host results are throughput-neutral within observed variance. The
candidate is retained because the targeted operation is substantially cheaper,
the trace confirms lower owner-rent pressure, exact behavior is preserved, and
no load point shows a material repeatable regression. It is not a publishable
peer result. Focused tests passed 60 with four intentional skips. The full
suite passed 9,591 with five skips and one dropped-FIN timing failure; that
unrelated assertion passed 10/10 isolated reruns.

## Semantic Raw STREAM Staging 2026-07-16

The next send-side trace isolated a capacity amplification rather than a pool
leak. The public write path commits at most 32 KiB of stream data at a time.
Formatting those bytes as a STREAM frame before queueing adds header bytes, so
`ArrayPool<byte>.Shared` rounds each long-lived queued owner to 64 KiB. At c128,
thousands of valid outstanding writes therefore retained about twice their
application-data capacity even though buffers eventually drained and
retransmission retention remained bounded.

The accepted candidate queues raw application bytes plus semantic stream
metadata and formats only the fragment selected for service. The queue retains
stream ID, offset, priority, FIN state, enqueue timestamp, and queue cause.
Raw writes remain single-entry scheduler selections. Packet protection still
receives a separately owned framed plaintext buffer, and that owner transfers
to sent-packet tracking for PTO/retransmission exactly as before. Protection
failure leaves the raw queue owner intact. Partial progress advances the raw
owner slice and stream offset only after successful protection and accounting.

Counter-attached exact diagnostics proved the intended retention mechanism:

| Connections | Control peak pool | Candidate peak pool | Candidate 64 KiB bucket | Result |
| ---: | ---: | ---: | ---: | --- |
| 64 | 3,937 buffers / 9.81 MiB | 3,869 buffers / 9.71 MiB | 136 buffers / 4.25 MiB | exact, no errors |
| 128 | 5,373 buffers / 62.06 MiB | 8,518 buffers / 21.29 MiB | 235 buffers / 7.38 MiB | exact, no errors |

The higher c128 buffer count is expected because the raw 32 KiB owners are
smaller; retained capacity is the acceptance signal. Counter-attached
throughput is not used as a performance claim.

The clean source-backed A/B campaign alternated baseline and candidate order,
used five repetitions at every c1/c4/c16/c32/c64/c128 point, disabled traces
and counters, and validated the exact 1 MiB response content in every cell:

| Connections | Control median | Candidate median | Throughput delta | Control p95 | Candidate p95 | p95 delta |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 37.13 MiB/s | 37.43 MiB/s | +0.8% | 34.23 ms | 35.62 ms | +4.1% |
| 4 | 96.66 MiB/s | 100.53 MiB/s | +4.0% | 50.17 ms | 45.63 ms | -9.1% |
| 16 | 174.65 MiB/s | 173.10 MiB/s | -0.9% | 99.00 ms | 109.36 ms | +10.5% |
| 32 | 169.30 MiB/s | 169.90 MiB/s | +0.4% | 199.09 ms | 186.02 ms | -6.6% |
| 64 | 158.41 MiB/s | 160.39 MiB/s | +1.3% | 344.44 ms | 331.69 ms | -3.7% |
| 128 | 149.11 MiB/s | 148.60 MiB/s | -0.3% | 644.16 ms | 648.74 ms | +0.7% |

The short c16 candidate set had higher variance, so a second alternating set
used ten-second measurement windows. Its five candidate cells reached
182.93 MiB/s median and 87.99 ms median p95 versus 177.95 MiB/s and 91.91 ms
for the five controls. All 70 uninstrumented cells passed exact validation with
zero failed or timed-out operations. These shared-host results establish no
material c1-c128 regression; they are not a peer ranking or publishable claim.

Focused queue, scheduler, public API, high-fanout FIN, RFC 9000, and RFC 9002
tests pass 115/115. One full-suite run passed 9,596 tests with five intentional
skips; its only failure was the existing timing-sensitive dropped-FIN injection
assertion, which then passed 10/10 isolated reruns. The final full-suite gate
passed 9,597 tests with five intentional skips and zero failures. Evidence remains under
`C:\shared\temp\protocol-lab-raw-owner-ab-20260716` and the two counter roots
under `C:\shared\temp\protocol-lab-raw-queued-owner-candidate-20260716`.
Nothing was deployed, registered, uploaded, or published.

## Fresh Raw Coverage and Package Startup 2026-07-16

A current source-backed campaign replaced the stale public raw picture with
five-repetition, round-robin, exact-validation cells on the shared Windows
host. Counters and traces were disabled, and every accepted Incursa and
quic-go cell completed with zero failures and timeouts. System.Net.Quic/MsQuic
reported unsupported on this host, so these results are diagnostic rather than
a complete three-peer ranking.

| Scenario | Connections | Incursa median | quic-go median | Incursa p95 | quic-go p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 MiB download | 1 | 37.75 MiB/s | 59.82 MiB/s | 35.28 ms | 18.58 ms |
| 1 MiB download | 16 | 180.80 MiB/s | 52.38 MiB/s | 89.45 ms | 309.08 ms |
| 1 MiB download | 64 | 181.88 MiB/s | 50.51 MiB/s | 348.74 ms | 1,267.43 ms |
| 1 MiB download | 128 | 173.74 MiB/s | 50.48 MiB/s | 685.96 ms | 2,513.82 ms |
| 100 ms slow reader, 16x64 KiB | 1 | 8.49 MiB/s | 8.59 MiB/s | 119.16 ms | 118.48 ms |
| 100 ms slow reader, 16x64 KiB | 16 | 66.49 MiB/s | 43.30 MiB/s | 236.47 ms | 375.13 ms |
| 100 ms slow reader, 16x64 KiB | 64 | 85.09 MiB/s | 42.79 MiB/s | 703.40 ms | 1,483.50 ms |
| 4,096x1 KiB download | 1 | 26.52 MiB/s | 49.56 MiB/s | 173.16 ms | 86.65 ms |
| 4,096x1 KiB download | 16 | 179.60 MiB/s | 40.74 MiB/s | 352.71 ms | 1,579.66 ms |
| 1,000-stream churn | 1 | 3,533.94 ops/s | 4,540.68 ops/s | 0.58 ms | 0.55 ms |

The slow-reader lane is healthy and does not justify a backpressure change.
The remaining current gaps are low-concurrency per-write overhead in the
4,096-write download and about 22 percent lower stable-connection stream-churn
rate. Both reverse at higher transfer concurrency, so future work must preserve
the strong c16-c128 behavior rather than optimizing only c1.

Package-backed coverage also exposed a source-mode startup defect. When
`PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT` was set, the packaged adapter still
used its intentionally absent package-local project path. Source mode now
resolves the raw server project from the supplied source root and prefers its
existing Release executable or DLL before falling back to `dotnet run`.
Focused package tests pass 22/22. Diagnostic package
`quic-dotnet-raw-dev@0.0.0-sourcepathfix2-20260716` passed one source-backed and
one prebuilt package-backed slow-reader cell. The missing-project attempt and
the first cold-build timeout are retained under
`raw-slow-reader-current-c1-20260716-quic-transport-v1-comparison` and
`raw-package-sourcepath-fix-c1-20260716-quic-transport-v1-comparison`.

The accepted campaign roots are under
`C:\shared\temp\protocol-lab-raw-peer-current-20260716\runs`. No package was
uploaded or registered, and no controller, worker, deployment, or publication
state changed.

## Receive Ring Contention Removed 2026-07-16

The c1 sustained-small-write CPU trace identified the receive-ring return
monitor as a sampled hot edge. The accepted runtime uses a versioned bounded
free list and carries the exact ring index and lease generation through the
existing ownership token. ArrayPool fallback, wrong-index, stale-generation,
and duplicate-return rejection, shard ownership transfer, and the 128-byte
shard work-item layout remain intact.

The permanent pre-change/candidate ShortRun comparison was allocation-free:

| Operation | Pre-change | Candidate | Delta |
| --- | ---: | ---: | ---: |
| One rent/return | 40.88 ns | 33.74 ns | -17.5% |
| 64-operation burst | 38.75 ns | 32.75 ns | -15.5% |

Matched uninstrumented source-backed runs used five samples per variant and
load point with exact 4 MiB content validation:

| Connections | Pre-change throughput | Candidate throughput | Delta | Pre-change p95 | Candidate p95 | Delta |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 37.90 MB/s | 39.07 MB/s | +3.1% | 149.81 ms | 129.68 ms | -13.4% |
| 16 | 190.52 MB/s | 188.85 MB/s | -0.9% | 350.99 ms | 356.03 ms | +1.4% |

All 20 cells passed validation and benchmark execution with zero failed or
timed-out operations. Candidate trace
`receive-pool-candidate-cpu-c1-20260716` no longer contains a
`QuicReceiveBufferPool` monitor frame. The c1 baseline throughput CV was 9.53
percent; c16 baseline and candidate CVs were 0.60 and 0.85 percent. The c16
result is neutral and all shared-host evidence remains diagnostic. Matched run
artifacts are under
`C:\shared\temp\protocol-lab-receive-pool-matched-ab-20260716\runs`.
Benchmark reports are under
`C:\shared\temp\bdn-receive-pool-baseline-20260716` and
`C:\shared\temp\bdn-receive-pool-lockfree-generation-state-20260716`.

The failed direct-catalog smoke
`receive-pool-baseline-smoke-c1-20260716` is retained because it exposed a
coverage mismatch: the bundled source load-tool manifest rejects the
server-to-client traffic shape, while the materialized current executor package
supports it. ProtocolLab must align source and package capability declarations
before direct source-catalog raw campaigns are considered parity evidence.

## Current Raw Cross-Section and Coverage Repair 2026-07-16

The source load-tool declaration and executable behavior are now aligned.
ProtocolLab internal commits `d11f0dd`, `b394890`, and `acbb155` declare every
used raw traffic shape, advertise the complete source scenario inventory, add
mixed-size round-robin payloads, exact 100 ms delayed reads, stable-connection
stream churn, and fix the duplex peer workload at 16 streams. Component commit
`d2edb1b` carries the same duplex shape through c128 in immutable scenario
package `0.1.18` (SHA-256
`c65ac9f7186151e5c4fdbf56394f56de59333687589c2d4589a779822917e388`).

Four short source-backed smoke cells passed exact validation and benchmark
execution with zero failures/timeouts: mixed-size c4/s16, stream-churn c1/s1000,
slow-reader c1/s16, and duplex-peer c1/s16. The slow-reader median was 112.36 ms,
which proves the requested 100 ms read delay was exercised. Artifacts are under
`C:\shared\temp\protocol-lab-raw-coverage-smoke-20260716\runs`.

A separate clean five-repetition c16 cross-section on final Incursa commit
`852d4c45` measured:

| Scenario | Median throughput | Throughput range | Median p95 | p95 range |
| --- | ---: | ---: | ---: | ---: |
| 16 MiB upload | 259.49 MB/s | 2.96% | 1,031.56 ms | 17.64% |
| 100x1 KiB multiplex | 30.74 MB/s | 48.25% | 50.73 ms | 9.91% |
| 16x1 MiB duplex | 123.26 MB/s | 8.25% | 2,389.22 ms | 19.56% |

All 15 cells passed exact validation with zero failed or timed-out operations.
The results are shared-host diagnostics, not peer rankings. The upload lane is
stable enough to guide profiling; multiplex contains one host-scheduling
outlier and duplex tail variance remains too high for a public claim. Artifacts
are under `C:\shared\temp\protocol-lab-current-raw-baseline-20260716\runs`.

## Coverage Matrix

| Area | Current coverage | Required next coverage |
| --- | --- | --- |
| Payload size | 128 B churn; deterministic mixed 1 KiB, 16 KiB, 64 KiB, and 1 MiB streams; 1 KiB latency/multiplex; 64 KiB throughput/multiplex/duplex/stream-limit pressure; 1 MiB upload/multiplex/duplex; 16 MiB upload | 256 KiB and multi-MiB per-stream fanout with fixed aggregate bytes |
| Direction | Upload, exact 1 MiB download-only, bounded bidirectional echo, simultaneous 16x1 MiB duplex, and sustained 256x64 KiB upload and download | Asymmetric simultaneous transfer |
| Concurrency | Scenario-owned c1, c4, c16, c32, c64, and c128 ladders under a dimension-neutral confidence profile | Prove every shape remains requested/effective-identical in live package-backed runs |
| Stream topology | Single stream, sustained long-lived upload/download, mixed-size streams over multiple stable connections, 16-stream large multiplex/duplex, 100-stream small/medium multiplex, and one-connection stream-limit pressure | Orthogonal fanout at fixed aggregate concurrency and large multiplex/duplex beyond c32 |
| Lifecycle | Distinct cold-handshake, connection-churn, and stream-churn contracts; handshake and connection-churn c1-c128 package coverage | Matched handshake/churn scaling, then resumption, rejected resumption, and 0-RTT outcomes |
| Flow control | Exact 100 ms slow-reader lane plus incidental multiplex evidence | Controlled windows, blocked duration, credit cadence, and slow-writer pressure |
| Network | Clean profile | Loss, delay, reordering, bandwidth, MTU, and ECN where executable |
| Duration | 3-30 second finite runs | Minutes-scale bounded-memory and recovery soaks |
| Diagnostics | Counters and traces on selected Incursa runs, including receive-ring contention proof | Target and generator CPU, queue, buffer, retransmission, qlog, and network telemetry |
| Source/package parity | Source traffic-shape declarations and executable behaviors are aligned; package executor support exists; immutable scenario package 0.1.18 aligns duplex c1-c128 | Run matched source/package cells from the same package inventory after registration approval |

## Work Order

### 1. Repair comparison identity and package coverage

- `quic.transport.handshake-cold`, `quic.transport.connection-churn`, and
  `quic.transport.duplex-streams-peer-matrix` are now declared by the Incursa
  package, run helper, and live adapter manifest.
- `msquic-dotnet-raw-adapter-v1` now has a distinct implementation ID,
  immutable version, SHA-256, source metadata, and clean-source build
  attestation.
- Current authoritative quic-go implementation, executor, and scenario
  packages now build cleanly with immutable versions and attestations.
- `quic.transport.connection-churn` and `quic.transport.stream-churn` are now
  distinct public contracts and are not silently merged with historical evidence.
- The three target manifests have an exact offline eight-scenario intersection.
  Controller registration and a package-matrix preview resolving three runnable
  targets remain intentionally pending operator approval.
- The same three target manifests now also intersect on 1 KiB latency echo and
  one-connection stream-limit pressure; fresh immutable archives prove all
  eight package-declared peer lanes offline.
- Stream churn and slow-reader bring the current offline comparison inventory
  to nine campaign lanes. The unchanged controller catalog does not yet expose
  that intersection, as proven by the 2026-07-16 read-only dry-run.
- Mixed-size, stream-churn, slow-reader, and duplex-peer source cells now execute
  end to end with exact validation. The remaining blocker is current package
  registration and matched campaign execution, not missing source dispatch.

### 2. Prove requested and effective workload shape

- Record executor ID/version plus requested and effective connections,
  concurrency, streams per connection, warmup, duration, and repetition.
- Reject a cell when the effective shape does not match the scenario/run plan.
- Add reusable c1, c4, c16, c32, c64, and c128 QUIC profiles.
- Use deterministic round-robin target ordering and at least five repetitions.

### 3. Establish fresh matched baselines

Run Incursa, quic-go, and MsQuic with the same executor and scenario package:

1. `quic.transport.stream-throughput.1mb`
2. `quic.transport.latency.echo-1kb`
3. `quic.transport.multiplex.100x64kb`
4. `quic.transport.stream-limits.100x64kb`
5. `quic.transport.duplex-streams-peer-matrix`
6. `quic.transport.flow-control.slow-reader-16x64kb`
7. cold handshake, connection churn, and stable-connection stream churn

Classify each concurrency point as target-limited, generator-limited,
network-limited, unstable, or clean. Do not compare a new Incursa run with a
stale peer run as one campaign.

### 4. Expand transport workloads

Add payload-direction, flow-control, mixed-size, and controlled-network
scenarios in small contract-first slices. Every new scenario must define exact
payload bytes/hashes, completion criteria, timeout behavior, required metrics,
and unsupported behavior before executor implementation.

After the current peer campaign is clean, prefer this next contract order:
the sustained 64 KiB upload/download and mixed-size stable-connection lanes are
complete; add fixed-total-byte write-granularity pairs, orthogonal fanout, and
controlled RTT/loss/reordering. The 1 MiB download-only lane is complete. These
isolate direction, write-completion latency, long-run retention, scheduler
fairness, and recovery without conflating all five dimensions in one workload.

### 5. Optimize the runtime from evidence

Use clean matched traces to choose the next Incursa change. Priority signals are
queue delay, write-completion latency, outstanding pooled bytes by bucket,
sent-packet retention, retransmission retention, target CPU, allocation sites,
exception sites, and generator saturation. Preserve rejected experiments.
The current sustained-upload trace prioritizes packet-receive scheduling and
batching over pool-size changes: all buffers drained and no delayed sends or
retransmission retention accumulated.

## Fixed-Total Write Shape and ACK Ledger 2026-07-16

The source-backed raw surface now has exact fixed-total 16 MiB upload and
download pairs for 256 application writes of 64 KiB and 16,384 application
writes of 1 KiB. Go executor tests prove application write boundaries; wire
validation continues to prove exact payload bytes and content rather than
claiming that UDP packetization preserves those boundaries. ProtocolLab
internal commits `a36ee07` and `beaef5b`, component commit `75912ad`, and
Incursa commit `4d99d6ce` retain the workload and source-target freshness
support. The immutable local packages were built but were not uploaded or
registered.

A matched c16 Incursa/MsQuic characterization showed that the relative
small-write penalty is not Incursa-specific: Incursa was 24.5% slower on the
1 KiB shape than its 64 KiB control, while MsQuic was 30.9% slower. Incursa's
absolute c16 throughput remained approximately 40-55% below MsQuic, so the
actionable gap is the shared raw runtime rather than the application write
shape alone. This peer evidence is shared-host diagnostic evidence, not a
publishable ranking.

The subsequent ACK receipt-ledger candidate replaced linear history scans in
packet recording and pending-ACK checks with maintained range/largest state
and a binary-search start index. Permanent microbenchmarks reduced the 2,400
receipt recording lifecycle from 5.882 ms to 74.912 us and the pending-ACK
check from 4.935 us to 23.04 ns.

Source-backed ProtocolLab baseline/candidate campaigns each ran both upload
shapes for five repetitions at c1 and c16. All 40 cells passed exact validation
and benchmark execution with zero failed or timed-out operations. At c1:

| Scenario | Baseline | Candidate | Throughput delta | p95 delta |
| --- | ---: | ---: | ---: | ---: |
| `quic.transport.sustained-stream.16384x1kb` | 27.43 MiB/s | 56.98 MiB/s | +107.7% | -48.1% |
| `quic.transport.sustained-stream.256x64kb` | 43.01 MiB/s | 74.23 MiB/s | +72.6% | -45.2% |

At c16, throughput was +0.7% and -2.1% respectively, both within the 7-10%
observed ranges. The accepted conclusion is bounded: ACK receipt history was a
major c1 bottleneck, while high-concurrency throughput remains constrained
elsewhere. Run roots and comparisons are under
`C:\shared\temp\protocol-lab-ack-ledger-*20260716`. No package, lab service,
worker, controller, or publication state changed.

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

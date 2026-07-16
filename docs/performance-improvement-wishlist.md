# QUIC Performance Improvement Wishlist

This is a pragmatic backlog for improving Incursa.Quic performance evidence, runtime efficiency, and benchmark trustworthiness. Each item includes the finish line so we can tell when it is actually done.

## Progress Notes

- 2026-07-16: the raw receive-buffer ring no longer serializes every socket
  receive and runtime return through one monitor. A versioned lock-free free
  list now carries the exact bounded ring index and lease generation in the
  ownership token, retains the existing ArrayPool fallback, and rejects
  wrong-index, stale-generation, and duplicate returns. The packed state
  reserves 12 bits for at most 4,095 ring slots and 52 bits for the generation
  so long-running wraparound is not a practical service-lifetime risk.

  A permanent ShortRun benchmark compared the pre-change commit `9e643620`
  with the accepted candidate. Single rent/return improved from 40.88 to
  33.74 ns (-17.5 percent), and a 64-operation burst improved from 38.75 to
  32.75 ns per operation (-15.5 percent). Both remained allocation-free.
  Retain the baseline report under
  `C:\shared\temp\bdn-receive-pool-baseline-20260716` and the accepted report
  under
  `C:\shared\temp\bdn-receive-pool-lockfree-generation-state-20260716`.

  Five alternating, uninstrumented source-backed samples at c1 and c16 used
  the same packaged `quic-go-raw-load@0.1.15` executor and
  `raw-quic-transport@0.1.17` scenario. All 20 cells passed exact 4 MiB content
  validation with zero failures/timeouts. At c1, median throughput changed
  from 37,902,025 to 39,070,802 B/s (+3.1 percent) and p95 from 149.81 to
  129.68 ms (-13.4 percent); the baseline throughput CV was 9.53 percent, so
  this is directional rather than stable evidence. At c16, throughput changed
  from 190,522,132 to 188,852,425 B/s (-0.9 percent) and p95 from 350.99 to
  356.03 ms (+1.4 percent), with CVs below 1 percent. The c16 result is neutral
  shared-host evidence, not a publishable claim. Retain all 20 cells under
  `C:\shared\temp\protocol-lab-receive-pool-matched-ab-20260716\runs`.

  The retained baseline CPU trace sampled 808
  `Monitor.Enter_Slowpath <- QuicReceiveBufferPool.Return` edges. Candidate
  trace `receive-pool-candidate-cpu-c1-20260716` contains no receive-pool
  monitor frame; remaining monitor samples belong to other runtime locks. This
  trace predates the generation hardening but proves the same monitor-removal
  mechanism retained by the accepted implementation. Focused ownership/layout
  tests passed 23/23, including a copied stale-ownership regression and the
  concurrent pool stress test. Two final full Release runs each completed
  9,601 passes and five intentional skips with one different load-sensitive
  failure: the first hit the known dropped-server-FIN assertion and the second
  timed out waiting for an HTTP/3 peer close. Each exact failed test then passed
  10/10 reruns on the same final binary. These unrelated suite-load flakes are
  retained rather than hidden or used to alter the receive-pool implementation.

  The first direct source-catalog smoke is retained as infrastructure evidence:
  its bundled `quic-go-raw-load` manifest rejected the server-to-client traffic
  shape, while the current package-backed executor accepted and completed the
  exact same cell. Source/package load-tool capability parity is therefore a
  ProtocolLab coverage repair item. No package, controller, worker,
  deployment, registration, or publication state changed.

- 2026-07-16: sustained small-write raw QUIC coverage is accepted as an
  evidence-infrastructure slice. The new
  `quic.transport.sustained-download.4096x1kb` contract keeps one stable
  bidirectional stream and requires exactly 4,096 sequential server writes of
  1,024 bytes, for 4,194,304 exact content-validated bytes. This directly
  contrasts the existing 256x64 KiB sustained-download lane without changing
  total payload size.

  Public ProtocolLab commit `7efcec4`, component commit `3e04d81`, internal
  runner commit `cdf4778`, and Incursa commit `d3644aca` align the authoritative
  scenario, reusable Go executor and target, runner validation, source
  adapters, and implementation packages. Component Go tests and all 93 public
  plus 93 internal component-manifest validations passed. Incursa adapter and
  server builds passed with 0 warnings and 0 errors, its focused package tests
  passed 21/21, and the internal exact-scenario tests passed 2/2. The broader
  internal filter passed 122/127; its five initial failures were two corrected
  parser expectations and three pre-existing timeout-prone Incursa conformance
  cases for older 1 MiB download, 16 MiB download, and slow-reader scenarios.
  Focused parser and execution guardrails then passed 4/4.

  Clean immutable packages were produced without registration:

  - scenario pack `0.1.17`:
    `b2268f979838f825615fdf258101aadd593ade2a5b5c92ae885b071ecb319a4f`;
  - quic-go executor Windows `0.1.15`:
    `24954184259186222a27dc736126c9d3331116ff77250b7c7e02f046133e062c`;
  - quic-go executor Linux `0.1.15`:
    `03926cc45d2de001fbb796d89ada62e3de1f3b337b10797a08bcbe9307056988`;
  - quic-go target `0.1.18`:
    `834217dca38e9cdadb805c59152b6961928dfafd4bb42f31f6a626af37068129`;
  - Incursa target `0.0.0-smallwrites-20260716`:
    `390f6e34a5985c552d7b5ea354e64c5086b3df30ad11348e9845daef258cbe23`;
    and
  - MsQuic target `0.0.0-smallwrites-20260716`:
    `187b4c393d12093d3b28fd87134f65aca806b79d40564d1a3cea4738f25aefeb`.

  Package-backed localhost validation passed for Incursa and quic-go with zero
  failed or timed-out transfers. In one short diagnostic sample, Incursa
  completed 20 exact 4 MiB transfers at 39,213,386.37 B/s with 592.84 ms p95;
  quic-go completed 24 at 49,448,791.74 B/s with 378.91 ms p95. MsQuic was
  correctly reported unsupported because `System.Net.Quic.IsSupported` is
  false on this host. The initial evidence incorrectly reported effective
  concurrency 128 even though the executed commands used four connections and
  one stream per connection. ProtocolLab internal commit `6cb1e06` now derives
  packaged raw QUIC requested, effective, and exported concurrency from those
  actual controls instead of a generic profile default. Its focused regression
  passed 1/1 and all `LoadToolInvokerTests` passed 241/241. Follow-up run
  `raw-smallwrites-loadshape-fixed-d-20260716-direct-package-cell` passed
  validation and benchmark execution with requested/effective concurrency 4,
  28 exact transfers, 117,440,512 received bytes, and zero failures or timeouts.
  Treat these shared-host samples as functional proof only.

  No package was uploaded or registered and no rack campaign or publication
  ran. Next coverage priorities remain controlled RTT/loss/reordering and
  one-stream-per-connection fanout, followed by an approved five-repetition
  c1/c4/c16/c32 three-peer campaign with isolated target and generator
  telemetry.

- 2026-07-16: mixed-size raw QUIC multiplex coverage is accepted as an
  evidence-infrastructure slice. The new
  `quic.transport.multiplex.mixed-4x16` contract keeps four stable connections,
  opens sixteen concurrent bidirectional streams per connection, and applies
  the deterministic 1 KiB, 16 KiB, 64 KiB, and 1 MiB payload sequence in
  round-robin order. Exact validation requires 9,052,160 bytes per connection
  batch rather than inferring a uniform payload from the largest stream.

  Public ProtocolLab commit `8e1d3f4`, component commit `cbcea9f`, internal
  runner commit `75357a1`, and Incursa commit `e7d23130` align the authoritative
  scenario, reusable Go executor and target, runner validation, source adapters,
  implementation packages, and comparison suites. Focused internal tests
  passed 27/27 after building the adapter executables, and Incursa package
  tests passed 20/20. Clean immutable Windows packages were produced without
  registration:

  - scenario pack `0.1.16`:
    `5b05c883625aabd298a6cf0fa35cd61a169da7bb5ca1d9270f11aba218377ba7`;
  - quic-go executor `0.1.14`:
    `83ebb9f3cc86bd031a78f2a75a85adcd4a01f137220e29e41feabdbd7a6a35c2`;
  - quic-go target `0.1.17`:
    `1f19d776c82978e8913a8c6b79fe58e3134c231955029d189834ac128acbae97`;
  - Incursa target `0.0.0-mixed-20260716`:
    `2588d2e7c9e424c4aa588991bd87f81df88bd85714efb8e153a672ba20f9e8ad`;
    and
  - MsQuic target `0.0.0-mixed-20260716`:
    `403389b33b0692387a51386b5795762936b756a58fa50b4ca3ebf693da97efbf`.

  A short package-backed c4/s16 localhost smoke passed exact validation for
  Incursa and quic-go with zero failed or timed-out streams. Incursa completed
  384 streams at 46,946,593.49 B/s and quic-go completed 448 streams at
  54,075,853.60 B/s. This one-repetition shared-host result is diagnostic only,
  not a ranking. The MsQuic package advertised the exact scenario, but
  `System.Net.Quic.IsSupported` was false on this Windows host, so its validation
  was correctly reported as unavailable rather than passed or failed.

  No package was uploaded or registered and no rack campaign or publication
  ran. The next coverage priorities are controlled RTT/loss/reordering,
  sustained small-write pressure, and connection-fanout scaling. Each should be
  implemented as an exact contract and locally package-proven before requesting
  an approved five-repetition c4/c16/c32 three-peer rack campaign with isolated
  target and generator telemetry.

- 2026-07-16: demand-triggered sent-packet dictionary reservation was modeled
  and rejected before changing the runtime. The permanent
  `QuicSentPacketDictionaryCapacityBenchmarks` comparison covers the current
  64-entry start, an intermediate 1,024-entry reserve at 512 retained packets,
  and a late 2,048-entry reserve at 1,536 retained packets.

  The early reserve cut allocation by 42 percent and population time by 24
  percent at 1,664 packets, close to the 1,656-packet trace peak, but increased
  allocation and time by about 25 percent at 1,024 packets. Moving the larger
  reserve trigger to 1,536 removed that midrange penalty and reduced allocation
  by 16 percent at 1,664 and 2,048 packets, with population time improving by
  about 2 and 8 percent. However, its additional per-packet condition measured
  3-10 percent slower below the trigger in the isolated ledger benchmark.

  Retain the ShortRun artifacts under
  `C:\shared\temp\quic-bdn-sent-capacity-{expanded,late}-short*-20260716`.
  Do not add a condition to every packet insertion for this capacity policy.
  Revisit only with a materially different pressure signal outside the packet
  insertion hot path or a sent-packet storage design that avoids dictionary
  growth without penalizing ordinary connections.

- 2026-07-16: the current Incursa raw QUIC package completed a fresh local
  breadth sweep across all 17 explicitly selected scenarios. Run
  `incursa-raw-fresh-coverage-all-20260716-quic-transport-v1-comparison`
  passed exact validation and benchmark execution 17/17, with zero failed or
  timed-out operations and target/load-tool process telemetry present for every
  cell. The retained evidence is under
  `C:\shared\temp\protocol-lab-raw-audit-20260716-v2\diagnostic-runs`.

  The strongest current shapes were 1 KiB echo latency (3,579.7 operations/s,
  0.59 ms p95), 100x1 KiB multiplexing (5,760.9 operations/s, 31.32 ms p95),
  and stream churn (3,426.1 operations/s, 0.62 ms p95). The clearest pressure
  lanes were 100x64 KiB stream limits (15.18 MiB/s, 943.12 ms p95), 100x64 KiB
  multiplexing (13.53 MiB/s, 1,148.95 ms p95), 16x1 MiB multiplexing
  (22.48 MiB/s, 920.82 ms p95), and simultaneous 16x1 MiB duplex
  (24.52 MiB/s, 804.79 ms p95). These are directional measurements, not
  accepted regressions or peer gaps.

  This sweep is single-repetition, localhost/shared-host, and target saturation
  warnings are present. The ProtocolLab runner metadata also records unrelated
  dirty work, while the Incursa target came from the retained clean package.
  Treat the run only as a current functional and diagnostic baseline. It does
  not refresh the public site and cannot support a peer ranking. The next
  coverage gaps remain mixed-size multiplexing across multiple stable
  connections and controlled RTT/loss/reordering; the next runtime evidence
  should continue to use 100x64 KiB stream-limit pressure with 1 MiB and
  100x1 KiB guardrails.

- 2026-07-16: increasing the initial spilled STREAM receive-segment list
  capacity from 8 to 16 was tested and rejected. The current 100-stream limit
  trace showed `BufferedSegment[]` as the second-largest allocation group, so
  the candidate attempted to avoid one geometric list growth without changing
  flow control, receive buffers, or scheduling. Focused receive-buffer and
  reordered STREAM tests passed 25/25, but the actual receive-state ShortRun
  benchmark retained the same 1.72 KiB allocation per operation and regressed
  from 4.384 to 4.575 microseconds. The runtime change was restored before any
  ProtocolLab campaign. Retain the benchmark artifacts under
  `C:\shared\temp\quic-bdn-segment-capacity-{baseline,candidate}-20260716`;
  do not revisit list pre-sizing without a different measured mechanism.

- 2026-07-16: immediate disposal of completed ProtocolLab raw-server stream
  facades was tested and rejected. The candidate removed the connection-lifetime
  `ConcurrentBag<QuicStream>` after confirming that sent-packet payload copies
  are connection-owned. A new resilience assertion disposed the server facade
  immediately after a deliberately dropped FIN to test the remaining lifetime
  dependency directly.

  The performance signal was initially promising but required careful ordering.
  A sequential five-repetition campaign was contradictory and the first
  counter-attached c16/s100 sample overstated the gain. Balanced alternating
  baseline/candidate runs then showed median multiplex throughput changes of
  +8.5 percent at c4 and +3.0 percent at c16, with p95 changes of -17.9 and
  -11.1 percent. Canonical workload runs passed validation with zero failures
  or timeouts and changed median throughput by +2.1 percent for stream churn,
  +2.9 percent for the c16 slow-reader case, and +2.7 percent for 100-stream
  limit pressure. A longer 1 MiB guardrail was neutral: 74.26 to 74.70 MiB/s
  (+0.6 percent), with p95 improving from 17.35 to 16.17 ms.

  The candidate nevertheless failed the correctness gate. The full Release
  suite reproduced the known timing-sensitive
  `DroppedServerFinIsRecoveredAndShardContinuesProcessing` failure with
  `retransmittedFin=0` after immediate disposal. That single failure does not
  prove causation because the same test has failed under prior full-suite load,
  but it prevents accepting a lifetime change until deterministic ACK-complete
  retirement proof exists. The run also contained the existing unrelated
  incomplete-content HTTP/3 timeout and the solution's missing local
  trace-analysis project reference; 9,590 tests passed and five were skipped.
  Runtime and test changes were restored; the dropped-FIN test then passed
  10/10 focused reruns and the unrelated HTTP/3 timeout passed in isolation.
  Retain the diagnostic runs under
  `incursa-raw-retention-*20260716`; do not remove completed-stream retention
  until ACK-complete stream retirement is modeled explicitly and the
  dropped-FIN test passes under repeated full-suite pressure.

  Coverage lesson: raw scenario defaults can expand every declared connection
  shape. The first combined counter sweep therefore attempted slow-reader c1
  through c128 and recorded a c128 target-start failure. Future focused runs
  must pin each named workload to its canonical connection and stream shape;
  matrix-wide ladders remain separate scaling evidence.

- 2026-07-16: raw QUIC peer coverage is expanded and package-proven for the
  five source-backed workload shapes that were missing from the reusable target
  inventory: 64 KiB and 16 MiB upload throughput, 100x1 KiB and 16x1 MiB
  multiplex, and 16x1 MiB simultaneous duplex. Component commit `558a29d`
  advances the quic-go target to `0.1.16`, the executor to `0.1.13`, and the
  scenario pack to `0.1.15`; internal commit `6856861` forwards exact
  `PLAB_SCENARIO_ID` and `PLAB_PROTOCOL` values to target processes.

  The first package smoke exposed and rejected payload-size guessing in the
  quic-go target: a 64 KiB upload was incorrectly echoed. The accepted target
  chooses no-echo or 1 KiB/64 KiB/1 MiB echo behavior from the exact scenario
  identity. Clean immutable packages were built with SHA-256 values
  `fc5dab790af32350f564b0db392ad2ec83e25e5687a55a8342002f9d2783b894`
  (Windows executor),
  `dc8cdba6970bf81c6ed994c4c2f5defadddffd641fc52ba84ae7d117954a3b01`
  (quic-go target), and
  `aa456e933441df661a7c2d0c70805abbf7c667e5c4181040543c58877a63f006`
  (scenario pack). The packaged comparison suite hashes identically to the
  public authority.

  One-second package-to-package diagnostics completed all five new shapes with
  zero failed or timed-out operations. Upload lanes received zero response
  bytes; multiplex and duplex lanes received exact echo bytes. This is package
  behavior proof, not benchmark evidence or a peer ranking. The live controller
  still has stale packages and the public site still has no claim-eligible raw
  QUIC result, so the next gate is an approved package refresh followed by a
  matched Incursa/quic-go/MsQuic campaign before selecting another runtime
  optimization from the published numbers.

- 2026-07-16: sustained raw QUIC upload coverage is accepted as an evidence
  slice. The new `quic.transport.sustained-stream.256x64kb` contract keeps one
  bidirectional stream open for 256 sequential 64 KiB application writes and
  validates exactly 16 MiB per operation. Public ProtocolLab commit `f5fccb6`,
  component commit `60b8023`, internal commit `1d16ae5`, and Incursa commit
  `6caa4d79` align the contract, reusable quic-go executor and target, runner
  validation, source adapters, package declarations, and comparison suites.

  Clean package validation produced scenario, Windows executor, Linux executor,
  and quic-go target SHA-256 values
  `d52858b4f4c1ef2894eda3fbf77376297d3ce39c99bd440841f8172baf8c3310`,
  `4a9cc985cf63c641ec7a5716bf0e2c97f70fa4eae62a3b17adb19c61a8707a69`,
  `b7790532f851ad649d5de6cf899ba50475591acf7b44759597404ca1f38dcc65`,
  and `c46e8b35bca0bfc1476765811ee6363c021bdad842421f204f6e88c892696de2`.
  The Incursa raw package built for Windows and Linux with SHA-256
  `8956ce7340d78fc161cd305fdcdfb79e3a038fb703f6047266956e00bea86997`.

  Matched source-backed local c1/c4/c16 ladders passed exact validation and
  benchmark execution 5/5 at every load, with zero failed or timed-out
  operations. Median throughput was 36.94, 128.66, and 230.46 MiB/s; median p95
  was 511.12, 671.77, and 1,005.24 ms. Relative throughput ranges were 18.9,
  26.3, and 5.6 percent. These shared-host runs flag possible generator and
  target saturation and are diagnostic, not publishable peer evidence.

  Counter run `codex-sustained-c16-counters-path-20260716-direct-package-cell`
  passed exact validation and exposed balanced receive pressure rather than a
  retention leak. Across eight shards, maximum queue depth ranged from 28 to
  38; packet-receive queue delay averaged 4.82 to 6.86 ms and peaked at
  32.44 ms. Delayed application sends, retained application-send buffers, and
  pending retransmissions remained zero. Outstanding pooled buffers peaked at
  143/589,824 bytes and drained to zero. The first two capture attempts are
  retained as negative prerequisite evidence: a restored repo-local tool was
  invisible from the materialized catalog root until `dotnet-counters` was put
  explicitly on `PATH`.

  No runtime change is justified from this single trace. The next coverage
  slices are the same sustained shape in the server-to-client direction and a
  mixed-size multiplex workload across multiple stable connections. Reproduce
  receive queue delay with isolated target/generator telemetry before testing a
  bounded receive-work batching or scheduling change.

  The server-to-client slice is now implemented as
  `quic.transport.sustained-download.256x64kb` across public `09fdb35`,
  components `40fc0ae`, internal `2213c24`, and Incursa `1bf25ae7`. Fifteen
  source-backed cells passed exact content validation and benchmark execution
  15/15 with zero failures and timeouts. Median throughput at c1/c4/c16 was
  35.04/105.60/177.10 MiB/s, compared with retained upload medians of
  36.94/128.66/230.46 MiB/s. Relative ranges were 7.2/27.6/7.3 percent and
  median p95 was 570.90/675.74/1,340.93 ms. Treat the widening c16 gap as a
  local directional diagnostic, not a peer comparison.

  Counter run `sd-dl-c16-ctr-20260716-direct-package-cell` passed exact
  validation for 1 GiB across 64 completed transfers. Unlike upload, every
  shard observed oversized-write continuation pressure: delayed application
  sends and retained application-send buffers peaked at 4-10, stream-write
  queue delay averaged about 6-7 ms and peaked at 24.03 ms, and sent-packet
  retention peaked at 94-168 packets per shard. Aggregate pooled buffers peaked
  at 829 / 1.95 MiB and drained to 19 / 3 KiB. Direct-send-blocked,
  pending-retransmission, and small-write-delay retention stayed zero. This
  narrows the next runtime investigation to incomplete-write continuation and
  server send scheduling; do not tune pool sizes as a substitute.

  Oversized-write continuation now advances the unsent STREAM header inside
  the existing queued owner instead of renting and copying the entire shrinking
  remainder after every protected fragment. The queued owner, priority,
  sequence, enqueue timestamp, queue cause, FIN bit, and stream offset remain
  stable; protection failure does not mutate the queue. A permanent
  `QuicStreamRemainderLayoutBenchmarks` comparison measured 32 KiB remainder
  advancement at 35.18 ns versus 679.45 ns for rent-and-rebuild, and 64 KiB at
  35.38 ns versus 1,298.63 ns, or about 19x and 37x faster for this operation.

  Counter/trace run `sd-dl-zc2-c16-ctr-20260716-direct-package-cell` passed
  exact 1 GiB validation with zero failures/timeouts. Against the retained
  traced control, sampled pool-rent rate fell from 106,888 to 84,421 rents/s
  and sampled rented-byte rate from 664.9 to 206.1 MiB/s. Queue and retention
  maxima were mixed and sometimes worse, so the trace is mechanism evidence,
  not a throughput claim. The preceding `sd-dl-zc-c16-ctr-20260716` attempt is
  retained because counters were honestly unavailable until the manifest-pinned
  tool was placed explicitly on `PATH`.

  Exact-duration, uninstrumented five-repetition controls and candidates passed
  30/30 validations. Candidate median throughput changed by +2.0/-3.8/-0.7
  percent at c1/c4/c16 and median p95 by -5.7/+3.6/-0.3 percent. This is neutral
  within shared-host variance, so the slice is accepted only as a bounded
  allocation-path improvement. Focused tests passed 60 with four intentional
  skips. The full suite passed 9,591 with five skips; its sole failure was the
  existing dropped-FIN timing assertion, which then passed 10/10 isolated
  reruns. No package, controller, worker, deployment, or publication changed.

- 2026-07-16: semantic raw STREAM staging removes the pooled-capacity penalty
  from queued large writes. A public write that exceeds the current packet
  service budget now queues its unframed application bytes with stream ID,
  offset, priority, FIN state, enqueue time, and queue cause. STREAM framing is
  deferred until the scheduler selects a fragment. Packet protection and
  sent-packet retention still receive an independently owned framed plaintext
  buffer, preserving PTO rebuild, retransmission, cancellation, ordering, and
  delayed-consumption behavior. Raw entries are not mixed with other queued
  writes in this first bounded slice.

  This is materially different from the rejected cursor-only design below. It
  removes the long-lived encoded payload owner whose 32 KiB data plus STREAM
  header rounded to a 64 KiB `ArrayPool` bucket; it does not merely advance a
  cursor through that oversized owner. Counter-attached c128 download evidence
  passed exact validation and reduced peak pooled capacity from about 62.1 MiB
  to 21.3 MiB. The 64 KiB bucket fell from 1,003 buffers / 65.1 MiB to
  235 buffers / 7.4 MiB. Throughput and latency from this instrumented run are
  diagnostic only.

  Sixty alternating, uninstrumented source-backed 1 MiB download cells passed
  exact validation with zero failures and timeouts. Candidate median throughput
  deltas at c1/c4/c16/c32/c64/c128 were +0.8/+4.0/-0.9/+0.4/+1.3/-0.3 percent;
  p95 deltas were +4.1/-9.1/+10.5/-6.6/-3.7/+0.7 percent. Because the short c16
  set was noisy, ten longer confirmation cells were run: candidate median
  throughput was 182.93 versus 177.95 MiB/s and median p95 was 87.99 versus
  91.91 ms. All confirmation cells also passed exact validation without errors.

  Focused queue, scheduler, API, FIN, high-fanout, and recovery tests pass
  115/115. One complete-suite run passed 9,596 tests with five intentional
  skips and only the timing-sensitive dropped-FIN injection assertion failing;
  that exact test then passed 10/10 isolated reruns. The final full-suite gate
  passed 9,597 tests with five intentional skips and zero failures. Evidence is
  retained under
  `protocol-lab-raw-owner-ab-20260716`. No package, controller, worker,
  deployment, or publication changed.

- 2026-07-16: fresh raw coverage disproves the stale public summary and narrows
  the next optimization target. Five-repetition, round-robin, uninstrumented
  source-backed cells passed exact validation for 1 MiB download at
  c1/c16/c64/c128, 100 ms slow-reader flow control at c1/c16/c64, stable
  1,000-stream churn, and 4,096x1 KiB sustained download at c1/c16. All accepted
  Incursa and quic-go cells had zero failures and timeouts; System.Net.Quic was
  unsupported on the shared Windows host.

  Incursa is behind quic-go at c1 for 1 MiB download (37.75 versus 59.82 MiB/s),
  sustained small writes (26.52 versus 49.56 MiB/s), and stream churn
  (3,533.94 versus 4,540.68 ops/s). It scales strongly at c16 and above: the
  1 MiB download reaches 180.80 versus 52.38 MiB/s at c16, slow-reader reaches
  66.49 versus 43.30 MiB/s at c16 and 85.09 versus 42.79 MiB/s at c64, and the
  sustained small-write lane reaches 179.60 versus 40.74 MiB/s at c16. The next
  runtime diagnostic therefore targets c1 per-write and stream-lifecycle cost
  without regressing c16-c128.

  The same campaign found and fixed package source-mode startup. A packaged
  adapter with `PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT` now resolves the server
  project under that root and prefers an existing Release executable or DLL.
  Package tests pass 22/22; a rebuilt diagnostic-only package passed both
  source-backed and ordinary prebuilt slow-reader cells. The missing-project
  and cold-build-timeout attempts remain retained as negative evidence. No
  package was uploaded or registered, and no controller, worker, deployment,
  or publication changed.

- 2026-07-16: an ACK-proportional queued-send burst was tested and rejected.
  The candidate retained the four-datagram floor, translated newly acknowledged
  protected bytes into datagram credit, and bounded one recovery transition at
  sixteen datagrams. Focused API, congestion, recovery, RFC 9000, and RFC 9002
  tests passed 1,067/1,067.

  Counter-attached c16/s100 evidence proved that aggregated ACKs raised the
  budget to 16 and released as many as 13 datagrams. Compared with the fixed-four
  trace, peak outstanding buffers fell from 1,268 to 1,151 and maximum sampled
  write completion fell from 70.88 to 68.63 ms. The larger release also raised
  maximum packet/write queue delay from 62.44/63.19 to 69.38/69.75 ms, delayed
  sends from 88 to 161, and post-policy blocked flushes from 428 to 483.

  The uninstrumented five-repetition c16/s100 candidate was effectively neutral
  in throughput and worse in latency: 24.64 MiB/s and 70.40 ms p95 versus the
  fixed-four control at 24.42 MiB/s and 67.45 ms p95. All five candidate cells
  passed exact validation with zero failures or timeouts. Runtime and tests were
  restored before running the download ladder because the multiplex acceptance
  gate had already failed. Retained run IDs are
  `raw-multiplex-ack-proportional-metrics-20260716-quic-transport-v1-comparison`
  and `raw-multiplex-ack-proportional-candidate5-20260716-quic-transport-v1-comparison`.
  Do not retry ACK-byte credit as a larger immediate burst. The next scheduler
  candidate needs time-domain pacing or packet coalescing that lowers wakeups
  without increasing one-transition queue service pressure.

- 2026-07-16: packet-overhead-aware partial congestion budgets were tested and
  rejected. The candidate reserved 50 bytes of short-header, packet-number, and
  AEAD overhead before exposing a sub-datagram STREAM payload budget. In the
  counter-attached c16/s100 diagnostic it moved maximum observed one-second
  `flush_blocked` decisions from 428 to 2 and `budget_blocked` decisions from
  10 to 401, while reducing maximum outstanding pooled buffers from 1,268 to
  940. The intended early-classification mechanism worked, but maximum packet
  and stream-write queue delay increased from 62.44/63.19 ms to 69.50/78.75 ms.

  Two candidate c16/s100 five-repetition runs around an adjacent control were
  directionally favorable: candidate medians were 25.60 and 24.97 MiB/s with
  62.38 and 59.49 ms p95, versus 24.42 MiB/s and 67.45 ms for the control. The
  required 1 MiB download guardrail did not hold. Compared with retained c1/c4/c16
  baselines, the candidate was +0.88/-2.65/-7.85 percent in throughput and
  -10.54/+5.31/+20.96 percent in p95. An immediately adjacent c16 download
  control narrowed the throughput difference to -0.66 percent but still showed
  a 9.35 percent p95 regression: 167.02 MiB/s and 118.73 ms candidate versus
  168.13 MiB/s and 108.58 ms control. Every reported cell passed exact validation
  5/5 with zero failed or timed-out operations.

  The source and candidate-only tests were removed. Retained run IDs begin with
  `raw-multiplex-overhead-budget-{candidate5,control5,candidate5b}-20260716`,
  `raw-download-overhead-budget-c{1,4,16}-candidate5-20260716`, and
  `raw-download-overhead-budget-c16-control5-20260716`. Do not retry this
  payload-budget subtraction by itself. The next candidate must preserve useful
  partial sends while changing release timing through pacing, coalescing, or an
  ACK-proportional scheduler and must pass both multiplex and bulk-download
  latency guardrails.

- 2026-07-16: recovery-driven application-send decisions now expose bounded
  metrics for congestion window, bytes in flight, congestion/anti-amplification
  available bytes, datagram budget, actual datagrams released, queue depth before
  and after release, outcome, and blocked reason. The existing stream-write
  completion metric remains the end-to-end latency signal. Metrics use only
  bounded `role`, `outcome`, and `blocked_reason` tags; no connection or stream
  identifier cardinality was added. Focused metrics and RFC recovery tests passed
  43/43. The full suite passed 9,585 tests with five skips and two suite-load
  failures; the dropped-FIN timing test and stateless-reset fuzz test each passed
  5/5 isolated reruns.

  Counter-attached source-backed diagnostics proved ProtocolLab captures the new
  instruments. `raw-download-recovery-metrics2-20260716-quic-transport-v1-comparison`
  passed exact c1 download validation with zero failures/timeouts and observed
  recovery releases of two to four datagrams. The more important
  `raw-multiplex-recovery-metrics-20260716-quic-transport-v1-comparison` c16/s100
  diagnostic also passed exact validation with zero failures/timeouts. Under
  counter overhead it reached 222 queued shard items, 62.44 ms packet-receive
  queue delay, 63.19 ms stream-write queue delay, 88 delayed sends, 1,268
  outstanding pooled buffers, and 70.88 ms maximum sampled stream-write
  completion latency.

  The decision telemetry identified a policy/preflight mismatch rather than a
  larger fixed-burst opportunity. Maximum observed one-second rates included
  553 `burst_limit_reached` decisions, 428 `flush_blocked` decisions classified
  as `congestion_limited`, and ten policy-level `budget_blocked` decisions.
  The blocked flushes occurred after the policy allowed a one-datagram budget,
  so the next bounded candidate is to account for packet/header/ACK headroom in
  partial-datagram congestion budgets before frame selection and protection.
  These counter-attached shared-host runs are diagnostic only and make no
  throughput or peer-ranking claim.

- 2026-07-16: increasing the queued application-send recovery burst from four
  datagrams to the RFC 9002 initial-window count of ten was rejected. A sampled
  CPU/counter trace of `quic.transport.stream-download.1mb` showed the fixed
  four-datagram recovery flush as a plausible c1 limiter: target CPU averaged
  about 1.4 cores, thread-pool queue length peaked at one, delayed sends peaked
  at 13, retained application bytes peaked at 802,816, and retransmissions
  remained zero. Five-repetition c1 A/B evidence then improved median throughput
  from 36.57 to 40.49 MiB/s and p95 from 36.20 to 31.06 ms with the larger cap.

  The result did not scale. At c4, median throughput moved from 104.88 to
  103.23 MiB/s and p95 from 44.05 to 45.06 ms. At c16, throughput was effectively
  unchanged at 181.24 versus 181.59 MiB/s, while candidate variance increased.
  More importantly, the c16/s100 1 KiB multiplex candidate reached 24.60 MiB/s
  with 69.05 ms p95 and 34.12 percent throughput range. Its immediately adjacent
  four-datagram control reached 24.04 MiB/s with 64.13 ms p95 and 10.18 percent
  range, while the earlier post-FIN-fix four-datagram run reached 25.45 MiB/s.
  All measured cells passed exact validation 5/5 with zero failures/timeouts,
  so this is a scaling/variance result rather than a correctness failure.

  The candidate passed 37 focused tests and 889 broad transport/RFC tests. The
  full suite passed 9,583 tests with five skips and two timing failures that each
  passed 5/5 isolated reruns. The source and tests were restored to the proven
  four-datagram behavior. Retained run IDs are
  `raw-download-*-burst{4,10}-*-20260716-quic-transport-v1-comparison`,
  `raw-multiplex-c16s100-burst10-candidate-20260716-quic-transport-v1-comparison`,
  and `raw-multiplex-c16s100-burst4-control2-20260716-quic-transport-v1-comparison`.
  Do not retry a larger fixed burst cap without a materially different scheduler.
  The next candidate must use measured congestion/recovery state, packet pacing
  or send coalescing, and write-completion telemetry so it can improve c16-c128
  without trading away multiplex latency or stability.

- 2026-07-16: true server-to-client raw QUIC coverage is now implemented end to
  end as `quic.transport.stream-download.1mb`. The contract uses a 16-byte
  `PLAB-DL1` request prelude, excludes that control traffic from payload
  metrics, requires exactly 1 MiB of response data per operation, and validates
  every response byte against the deterministic `offset % 251` pattern.
  Public ProtocolLab commit `63242f4`, component commit `0032d2a`, internal
  commit `42f937b`, and Incursa commit `a450928a` align the contract, reusable
  executor, quic-go target, Incursa and MsQuic source adapters, package
  templates, runner validation, and campaign declarations.

  Focused ProtocolLab validation passed 116/116 tests, the Incursa package
  contract passed 20/20 tests, all 92 component manifest pairs validated, and
  the Go executor and quic-go target suites passed. Fresh one-repetition local
  c1 diagnostics all completed with exact bytes and zero failures/timeouts:
  MsQuic reached 181.44 MiB/s with 6.49 ms p95, quic-go reached 61.79 MiB/s
  with 17.59 ms p95, and Incursa reached 38.21 MiB/s with 29.68 ms p95. These
  are sequential shared-host smokes, not a matched five-repetition campaign or
  a publishable ranking. They are sufficient to prioritize Incursa's isolated
  server-to-client send scheduling and completion path for trace diagnosis.
  No package was uploaded or registered, no lab service changed, and no result
  was published.

- 2026-07-16: Incursa commit `52701dcb` fixes the intermittent c16/s100
  raw QUIC EOF failure exposed by the expanded matrix. A new 16-connection,
  100-stream-per-connection integration proof reproduced the defect as
  `CompleteWritesAsync` requests that remained incomplete after all response
  payload bytes and FINs had reached the clients. The queued request ledger was
  already empty. The direct-send fallback had removed the request after
  classifying a valid FIN-only STREAM frame as invalid when congestion left a
  positive payload budget too small to fit the frame header.

  The scheduler now reports that boundary as a transient invalid payload
  budget, the runtime retains and retries the queued FIN after congestion
  recovery, and genuine non-transient post-queue failures complete the caller
  with an exception instead of orphaning it. The exact high-fanout test passed
  20/20 stress repetitions. Scheduler, standalone-FIN, listener-resilience,
  public API, and RFC 9000 focused gates passed 29 and 34 tests respectively.
  The broad test project passed 9,584 of 9,590 tests with five skips and one
  unrelated HTTP/3 close-notification timeout; that exact timeout then passed
  5/5 isolated reruns. The solution-level command also reported the pre-existing
  absent `eng/tools/Incursa.Quic.TraceAnalysis` project in this worktree.

  Source-backed ProtocolLab run
  `local-raw-c16-100x1kb-budget-fix-20260716-quic-transport-v1-comparison`
  then passed exact validation and benchmark execution 5/5 with zero failed or
  timed-out requests. Median throughput was 25.45 MiB/s and median p95 latency
  was 64.35 ms. This is shared-host diagnostic evidence, not a publishable
  comparison or a throughput-improvement claim. The next contract priority is
  true download-only raw QUIC, followed by mixed-size, asymmetric, and
  minutes-scale bounded-memory workloads; no package, controller, worker,
  deployment, or publication action was performed.

- 2026-07-16: the expanded source-backed raw QUIC matrix completed 75 measured
  runs across five scenarios, c1/c4/c16, and five repetitions per cell. Large
  single-stream throughput remained healthy and stable at c16: 16 MiB upload
  reached a 236.47 MiB/s median with a 3.3 percent range. High fanout was the
  distinct weak shape: 16x1 MiB multiplex passed exact validation 5/5 but fell
  to 37.68 MiB/s with 6,463 ms p95, while 100x1 KiB multiplex had only 3/5
  validation passes and 2/5 benchmark successes. A fresh five-repetition run
  with internal commit `2e30595` identified three EOF timeouts at varying
  coordinates (`14/40`, `8/35`, and `0/81`); both measured failures delivered
  the exact 1,638,400 aggregate bytes before one of 1,600 streams missed EOF.
  Internal commit `4518a22` now also records the QUIC stream ID and per-stream
  received/expected bytes without changing the output schema. A following
  three-repetition run passed 3/3, confirming intermittency rather than a fixed
  stream-index defect.

  Incursa commit `608b5d86` adds a 100-stream integration proof that silently
  discards one server FIN-only datagram, requires every exact payload and EOF,
  and then proves the connection remains usable. It passed 10 consecutive
  runs and the complete 18-test listener resilience class passed. Ordinary
  tail loss and retransmission therefore work in that bounded shape; no
  runtime change is justified from the current trace alone. Retained runs are
  under `C:\shared\temp\protocol-lab-local-raw-20260716` and
  `protocol-lab-internal\.artifacts\runs\local-raw-c16-100x1kb-*`. All are
  shared-host diagnostics and non-publishable. The next coverage priority is
  a download-only lane, followed by a multi-connection high-fanout integration
  proof and lightweight server-side completion attribution.

- 2026-07-16: raw QUIC workload coverage now separates payload-size, stream-count,
  aggregate-byte, and simultaneous-read/write effects instead of relying on the
  stale 1 MiB throughput and 100x64 KiB multiplex rows. Public ProtocolLab
  commit `a5ac2dd`, component-package commit `8ce81ff`, and internal runner
  commit `bcfda50` add 64 KiB and 16 MiB single-stream throughput, 100x1 KiB and
  16x1 MiB multiplex, and 16x1 MiB duplex scenarios with exact byte validation.
  Focused internal coverage passed 81/81, component manifest validation passed
  91/91, the reusable Go executor tests passed, and clean local scenario and
  executor packages were produced. Four of five first source-backed Incursa
  smokes passed; `quic.transport.multiplex.100x1kb` had one warmup read timeout
  and then passed an isolated rerun. Treat that lane as a variance/reliability
  signal until repeated runs establish its failure rate. No package was
  registered, no lab service changed, and no result is publishable. The next
  optimization gate is a repeated c1/c4/c16 ladder with target and generator
  health retained, followed by traces only for the shapes that reproduce the
  pressure.

- 2026-07-16: current source-backed raw QUIC coverage reproduced the existing
  high-concurrency pressure with the corrected 100-stream multiplex contract.
  A c1 stream-churn counter run completed 31,000 streams with zero failures at
  3,029.84 streams/s, maximum shard depth 2, and no delayed-send or
  retransmission buildup. In contrast, c16/s100 multiplex completed exact
  payload validation but reached 821 queued shard items, 944 ms packet-receive
  queue delay, 915 ms STREAM-write queue delay, and 14,897 outstanding 4 KiB
  pooled buffers. A GC trace attributed 664.89 MB of sampled allocation to
  `System.Byte[]`, followed by receive `BufferedSegment` lists and sent-packet
  dictionary entries.

  The previously rejected 16-shard default was repeated before the retained
  negative record was rediscovered. It improved uninstrumented c16 median
  throughput from 65.69 to 93.20 MiB/s and did not regress a five-repetition c1
  A/B, but the matched c16 counter run increased peak pooled buffers from
  14,897 to 25,704 and worsened maximum packet/write queue delay to
  1,380/1,228 ms. Combined with the retained c128 timeout/pressure failure, this
  confirms that more shard consumers increase offered work without fixing
  receive-segment lifetime or producer backpressure. The runtime candidate was
  reverted. Evidence remains under
  `C:\shared\temp\protocol-lab-local-raw-20260716`; it is diagnostic,
  shared-host, and non-publishable. Do not retry the shard-count change without
  a materially different bounded receive/backpressure design.

- 2026-07-15: raw QUIC peer coverage repair is accepted as an evidence-enabling
  slice. The public contract now distinguishes fresh-connection churn from
  repeated stream churn on a stable connection, and a dimension-neutral
  five-repetition comparison suite selects cold handshake, connection churn,
  1 MiB throughput, 100-stream multiplex, and duplex peer workloads across the
  scenario-owned c1/c4/c16/c32/c64/c128 ladders. The reusable quic-go executor
  was advanced to the lifecycle-aware implementation already proven in the
  internal lab, with explicit behavior validation, cold-handshake execution,
  fresh-connection churn, connect-time metrics, tight-window duplex handling,
  timeout classification, and requested/effective load echo.

  Clean immutable scenario, target, and Windows/Linux executor packages built
  successfully with external attestations. Their SHA-256 values are recorded
  in `docs/raw-quic-performance-evidence-plan.md`. The Incursa,
  MsQuic/System.Net.Quic, and quic-go manifests now share all five peer scenario
  IDs offline. A package-to-package Windows diagnostic completed 232 connection
  churn operations and 300 cold handshakes in bounded 250 ms windows with zero
  failures/timeouts and exact churn byte symmetry. Public contract health,
  84 component manifest pairs, both quic-go Go test suites, and 70 focused
  internal tests passed. No package was uploaded, no controller or worker was
  changed, and no result was published. The next gate is operator-approved
  package registration and a three-target matrix preview; runtime optimization
  must wait for fresh matched rack evidence.

- 2026-07-15: replacing the per-chunk incomplete-write async state machine
  with one pooled STREAM-action request for the complete public write was
  rejected. The candidate preserved the 32 KiB runtime work-item boundary and
  reposted each continuation chunk under the original request identifier. Its
  focused lifecycle tests passed 21/21, and the broader cancellation,
  flow-control, and RFC 9002 PTO set passed 63/63.

  A matched source-backed c64 counter and sampled-CPU diagnostic passed exact
  validation on both sides. The intended mechanism was visible: the former
  `WriteStreamChunksAsync` continuation accounted for 5.03 percent inclusive
  sampled CPU and its companion await path 1.72 percent in the baseline, while
  pending-request insertion fell from 3.23 to 1.41 percent and exclusive
  `Monitor.Enter_Slowpath` fell from 10.90 to 7.48 percent. However, traced
  throughput fell 2.58 percent, mean CPU rose 3.34 percent, allocation rate rose
  1.27 percent, and p95 rose 0.44 percent. Maximum per-shard queue depth rose
  from 1,321 to 2,283, the sum of per-shard maxima rose from 7,592 to 9,929,
  and peak outstanding pooled buffers/bytes rose from 32,150/263.43 MB to
  39,740/325.57 MB. Instrumented results are diagnostic, not throughput claims.

  Independent ownership review also found that a continuation post failure
  could violate `TryWrite*` terminal suppression after a partial write, that
  the design extended inline completion callbacks under the stream-action lock
  to multi-chunk writes, and that cancellation could race the next chunk post.
  Correcting all three safely requires a broader completion-dispatch ownership
  design rather than another local state-machine removal. The runtime and
  candidate-only tests were reverted without starting a clean repetition
  matrix. Retained evidence is under
  `.artifacts/protocol-lab/single-request-c64-cpu-20260715a` and the matching
  `quic-single-request-{baseline,candidate}-c64-cpu-20260715a-*` ProtocolLab
  runs. Do not repeat this one-request continuation design without first moving
  completion callbacks outside the stream-action lock and defining an atomic
  cancellation/terminal handoff between chunks. No result was uploaded,
  deployed, or published.

- 2026-07-15: atomic STREAM-write preparation is accepted as a bounded
  runtime-path optimization. The runtime previously acquired the stream-state
  lock separately to resolve or open the local stream, capture rollback state,
  and reserve flow-control capacity. `PrepareStreamWrite` now performs those
  operations under one lock while preserving the 32 KiB runtime chunk, public
  write-gate serialization, rollback state, flow-control retry ownership,
  cancellation, disposal, exception propagation, and the later priority read.
  Focused regression coverage preserves the prior unavailable result and
  default transport error for missing local and peer-initiated stream IDs.

  The permanent `QuicStreamWritePreparationBenchmarks` ShortRun reduced 64-
  operation preparation from 5.421 to 3.938 microseconds and 256-operation
  preparation from 20.741 to 15.629 microseconds, about 27 and 25 percent,
  respectively, with zero managed allocation on both paths. The suite is also
  part of `Invoke-QuicBaseline.ps1`; its final dry invocation passed through
  that checked-in runner.

  A matched c64 counter and CPU diagnostic passed exact validation on both
  sides. Maximum per-shard queue depth fell from 1,718 to 1,058, the sum of
  per-shard maxima from 8,895 to 6,112, mean packet-receive queue delay from
  94.54 to 87.46 ms, mean packet service from 1.761 to 1.573 ms, mean
  STREAM-write queue delay from 108.58 to 98.95 ms, and mean STREAM-write
  service from 0.504 to 0.436 ms. Peak outstanding pooled buffers fell from
  37,965 to 36,272. The trace removed the former write-path capture and reserve
  calls, but exclusive `Monitor.Enter_Slowpath` rose from 8.70 to 9.43 percent,
  mean write completion moved from 1,825 to 1,964 ms, and delayed application
  sends and retained sent packets were slightly higher. These instrumented
  results are diagnostic and are not throughput claims.

  Sixty post-fix, uninstrumented source-backed ProtocolLab cells passed exact
  payload validation and benchmark execution with zero failed or timed-out
  requests. Five deterministic alternating pairs at c4 and c16 moved aggregate
  request-rate medians by +6.72 and +0.09 percent and same-pair medians by
  +6.02 and +1.06 percent. Ten pairs at c32 and c64 moved aggregate medians by
  +0.14 and -0.27 percent and same-pair medians by +0.82 and -0.92 percent.
  The two c32 campaigns individually disagreed (-3.16 and +4.95 percent), so
  only the combined flat result is accepted. Combined c32/c64 p95 medians moved
  -1.66/+0.92 percent, with same-pair medians at -1.65/-0.48 percent. This is
  accepted for lower write-preparation cost and no demonstrated scaling
  regression, not for a broad c16-c64 throughput gain. Evidence remains under
  `.artifacts/protocol-lab/atomic-write-preparation-*` and matching ProtocolLab
  run roots. Shared-host results remain diagnostic and non-publishable.

  Focused preparation, write-cancellation, flow-control, RFC 9000, and RFC 9002
  coverage passed 836/836 before the final contract correction; the corrected
  preparation tests passed 5/5. The final all-up run completed 9,577 passes and
  five intentional skips with only the standing incomplete-content peer-close
  timeout; that exact test passed ten consecutive isolated reruns against the
  final binaries. No result was uploaded, deployed, or published.

- 2026-07-15: a lazy per-stream index of retained packets carrying non-empty
  STREAM data is accepted. RESET_STREAM acknowledgment handling previously
  scanned and reparsed every retained packet to determine whether the
  acknowledged stream still had outstanding data. The runtime now parses each
  tracked packet on insertion and removal, counts each distinct stream once per
  packet, and performs an O(1) count lookup before consulting the retransmission
  queue. Every replacement, acknowledgment, loss, packet-number-space discard,
  protection-level discard, and key-phase discard uses the indexed removal
  path. Zero-length STREAM frames, including FIN-only frames, remain excluded
  from outstanding-data ownership.

  Permanent BenchmarkDotNet coverage measures lookup, equal-parser-work
  bookkeeping, and the complete acknowledgment lifecycle. At 64/256/1,024
  retained packets, lookup fell from 1,138/4,875/19,555 ns to
  4.15/3.86/3.80 ns. The complete former scan-after-every-ACK lifecycle fell
  from 35.81/601.75/10,054.57 microseconds to 5.64/23.54/93.66 microseconds.
  Index add/remove cost, including the same two payload parses, was 1.89/1.21/
  1.20 times the parse-only baseline; fresh-index allocation was 4,624/22,312/
  102,216 bytes. The accepted trade therefore pays bounded dictionary work at
  packet lifecycle boundaries to remove the quadratic acknowledgment scan.

  Fifty-eight of 59 uninstrumented source-backed ProtocolLab cells passed exact
  validation, and those successful cells reported zero request failures or
  request timeouts. Five
  deterministic alternating pairs at c1/c4/c16/c32 moved aggregate median
  request rate by +4.45/+4.55/+9.38/+7.80 percent and same-pair medians by
  +2.91/+3.91/+9.35/+7.34 percent; aggregate p50 moved -1.61/-3.56/-4.84/
  -5.32 percent. At c64, the aggregate request-rate median moved -0.90 percent
  while the same-pair median moved +4.63 percent; one fully valid candidate
  outlier is retained rather than discarded. Four valid c128 pairs moved the
  aggregate request-rate median +0.67 percent but the same-pair median
  -2.36 percent, with aggregate/paired p50 at +1.14/+1.10 percent. Both c64 and
  c128 showed possible target saturation. The fifth c128 baseline cell then
  failed raw load validation with a network-inactivity timeout and four recorded
  errors, so its candidate counterpart was not run and c128 is not used for an
  acceptance percentage claim. The 59-cell summary and all raw evidence remain
  under `.artifacts/protocol-lab/sent-stream-index-pairs-20260715a` and the
  corresponding ProtocolLab run roots. These are shared-host diagnostics, not
  publishable rankings.

  Focused index and RFC 9000 RESET_STREAM tests passed, including packet
  replacement, every removal path, repeated/multi-stream packets, and FIN-only
  behavior. The final logged all-up test run completed 9,572 passes and five
  intentional skips with only the standing incomplete-content peer-close
  timeout; that exact test passed ten consecutive isolated reruns. An earlier
  candidate all-up run completed 9,571 passes and reproduced only the standing
  dropped-server-FIN timing failure, which also passed ten consecutive isolated
  reruns. No result was uploaded, deployed, or published.

  Packet-mailbox batching was also rejected before implementation. The matched
  CPU trace attributed only about 0.24 percent exclusive CPU to channel
  publication while packet transition and service work dominated. Do not add a
  mailbox batch merely to remove channel writes unless a materially different
  trace shows publication or wake-up cost has become significant.

- 2026-07-14: releasing `pendingStreamActionRequestsGate` during expensive
  STREAM-write processing through pooled completion-source processing leases
  was rejected. The candidate kept each request visible during processing,
  delayed pool reuse until both processing and `ValueTask` consumption ended,
  made the short gate the cancellation linearization point, preserved terminal
  cleanup and write-gate serialization, and deferred busy retry entries so a
  low request ID could not starve ready work. Focused ownership, cancellation,
  lifecycle, retry-fairness, and RFC tests passed 72/72 in ten consecutive
  runs. The final all-up test run passed 9,572 tests with five intentional
  skips and reproduced only the standing dropped-server-FIN timing failure;
  that exact test then passed ten consecutive reruns.

  Current source-backed c64 CPU diagnostics
  `quic-queue-lease-current-{baseline,candidate}-c64-cpu-20260714a-quic-transport-v1-comparison`
  both passed exact 12,800-stream and 838,860,800-byte validation with zero
  failures or timeouts. Sampled exclusive `Monitor.Enter_Slowpath` fell from
  8.52 to 5.01 percent, but traced request rate fell from 974.16 to 950.18 per
  second and p50/p99 latency rose from 5,224.79/6,192.35 to
  5,411.92/6,579.81 ms. Candidate final counter samples also retained 16,453
  pooled buffers versus zero in the matched baseline; the earlier candidate
  diagnostic ended with 15,149. Counter timing includes load-phase boundaries,
  so this is not asserted as a leak, but the design did not prove improved
  backlog drain. Instrumented trace movement is diagnostic, not acceptance
  evidence.

  Fifty deterministic alternating, uninstrumented source-backed cells at c1,
  c4, c16, c32, and c64 all passed exact validation with zero failed requests
  and zero timeouts. Candidate median request-rate deltas were
  -1.57/-5.08/+0.32/-3.29/+1.54 percent. Median p50 deltas were
  -2.28/-0.77/+2.45/+3.58/+4.25 percent. Same-repetition median request-rate
  deltas were +0.39/-5.08/-1.18/-1.21/-1.41 percent, so the apparent c64
  aggregate median gain was not stable within matched pairs. Evidence remains
  under `quic-queue-lease-matched-20260714a-*`, with the combined summary and
  transcript under `.artifacts/campaigns`.

  The runtime implementation and candidate-only tests were reverted. Do not
  repeat another pending-action processing barrier or lease that only shortens
  this monitor: three materially different barrier designs have now reduced
  lock hold time without improving queue service capacity. A future candidate
  must reduce per-write service work or bound producer ingress before runtime
  work-item creation, and must improve c16-c64 without regressing c1-c4. No
  result was uploaded or published.

- 2026-07-14: increasing the runtime STREAM-write work-item chunk from 32 KiB
  to 64 KiB was rejected. The candidate targeted the two sequential shard
  work items created by each 64 KiB ProtocolLab application write; packet
  fragmentation, congestion control, flow control, and the public write gate
  were unchanged. A source-backed c64 counter/GC run passed exact validation
  and reduced mean sampled STREAM-write queue delay from 127.75 to 116.33 ms,
  mean STREAM-write service time from 0.567 to 0.409 ms, successful write
  completion time from 2,019.13 to 1,327.67 ms, and outstanding 64 KiB buffer
  count from 1,843 to 1,029. The same diagnostic raised maximum STREAM-write
  queue depth from 229 to 269, maximum total shard depth from 1,346 to 1,704,
  delayed application sends from 211 to 301, and outstanding 64 KiB capacity
  from 64.16 to 67.24 MB. Instrumented throughput is not an acceptance claim.

  Fifty alternating, uninstrumented source-backed cells at c1, c4, c16, c32,
  and c64 all passed exact payload validation with zero failures and zero
  timeouts. Candidate median request-rate deltas were -0.56/-0.42/+1.16/
  +2.32/+0.02 percent respectively. Median p95 deltas were +0.66/-17.21/
  -2.15/-2.48/+0.25 percent, and p99 deltas were +1.46/-11.03/-3.69/-2.65/
  +0.46 percent. Evidence remains under the `quic-runtime-chunk64-gate-*` and
  `quic-runtime-chunk64-matrix-*` ProtocolLab runs.

  Correctness blocked acceptance. The full candidate test project completed
  9,566 passes and five intentional skips, but deterministically failed two
  RFC 9002 PTO tests: the 64 KiB finished-stream probe was not retained as a
  probe packet, and PTO emitted only the repair fragments instead of both the
  repair and queued stream data. Both failures reproduced in an isolated
  candidate run; the exact two tests passed 2/2 at baseline commit `9addb6e0`.
  The runtime change was reverted. Do not increase the application-to-runtime
  STREAM-write chunk unless a materially different design preserves PTO repair
  and queued-data probe behavior under the existing recovery tests. No result
  was uploaded or published.

- 2026-07-14: per-connection admission of oversized application writes was
  rejected after five bounded designs. The candidate kept caller memory
  borrowed until the public `ValueTask` completed, retained already-owned
  flow-control retries without another pool rent, serialized release in
  request order, preserved the stream write gate, and covered cancellation,
  disposal, flow-control requeue, ordering, and delayed consumption. A fixed
  cap of 32 reduced the c64 diagnostic peak from 211 to 34 delayed application
  buffers and from 64.16 to 52.72 MB of outstanding 64 KiB pool capacity, but
  raised maximum shard depth from 1,346 to 1,740. A cap of 64 retained 72
  buffers and 36.21 MB of 64 KiB pool capacity, but still imposed admission on
  lower-load traffic. These instrumented observations prove a lifetime bound;
  they do not prove throughput.

  Clean source-backed gates rejected both fixed caps. Cap 32 improved c64
  median request rate by 4.44 percent, but its c1/c4/c16/c32 guardrail matrix
  included a c4 p95 regression of 12.41 percent and a c32 request-rate
  regression of 2.52 percent with 43.77 percent candidate range. Cap 64 moved
  median request rate by -2.67/-2.97/+2.38 percent at c4/c32/c64 and regressed
  c4 p95 by 26.21 percent. Run IDs use `quic-admission-gate-*`,
  `quic-admission-matrix-*`, and `quic-admission64-gate-*`.

  Three pressure-sensitive variants then activated admission only after the
  shard's pending STREAM-write count reached 128, 192, or 512. Threshold 128
  did not activate in the c4 counter diagnostic and did activate at c64, where
  it retained 141 delayed buffers and 37.68 MB of 64 KiB pool capacity. Its
  clean c4/c32/c64 request-rate deltas were +2.85/+0.37/+11.63 percent, but c4
  p95 regressed 21.20 percent. Threshold 192 moved c4/c64 request rate by
  -0.81/+1.72 percent and c4 p95 by +20.88 percent. The final threshold 512
  gate completed all 20 alternating c4/c64 cells with exact payload
  validation, zero failures, and zero timeouts. It moved median request rate
  by -1.05/-1.91 percent and p95 by -8.10/+0.91 percent, so it did not retain a
  high-concurrency benefit. Evidence remains under
  `quic-admission-pressure*-20260714a` ProtocolLab runs.

  The implementation, metrics, and candidate-only tests were reverted. Do not
  repeat per-connection queue-count admission with another cap or threshold.
  A materially different follow-up must reduce creation or service cost of
  shard STREAM-write work, or apply bounded producer backpressure before each
  write becomes an independently queued runtime item, while preserving flow
  control, write ordering, cancellation, and `ValueTask` memory lifetime. No
  result was uploaded or published.

- 2026-07-14: retaining the original queued STREAM payload and advancing a
  consumed-data cursor instead of rebuilding the complete unsent tail after
  every fragment was rejected. The candidate preserved the queued owner until
  final removal, transferred only packet-sized fragment owners to sent-packet
  tracking, kept partially consumed writes out of batching, preserved FIN
  promotion and offsets, and advanced the cursor only after successful packet
  protection and accounting. Focused queue/scheduler tests passed 38/38,
  broader blocked-send, delayed-consumption, API, RFC, and interop tests passed
  126/126, and independent review found no ownership, retransmission, ordering,
  FIN, or transient-failure defect. The full test project passed 9,572 tests
  with five intentional skips and only the standing dropped-FIN and incomplete-
  content close-timeout flakes; each exact failure then passed five consecutive
  reruns.

  A permanent 64 KiB fragmentation benchmark measured the former repeated-tail
  rebuild at 39.545 microseconds and the cursor path at 7.315 microseconds
  (-81.5 percent, about 5.4 times faster), with zero managed allocation in both
  cases. The exact source-backed c64 counter/GC run
  `quic-stream-cursor-c64-gc-20260714a-quic-transport-v1-comparison` also passed
  12,800-stream and 838,860,800-byte validation. Against
  `quic-pressure-metrics-c64-gc-20260714b-quic-transport-v1-comparison`, observed
  outbound-stream-payload rent traffic fell from 6,990.74 to 782.62 MiB, total
  owner-attributed rent traffic fell from 12,010.24 to 7,360.61 MiB, mean write
  completion fell 12.7 percent, and traced throughput rose 15.4 percent. The
  same run doubled peak delayed application sends and retained application-send
  buffers from 211 to 428, demonstrating that cheaper tail formatting did not
  solve queue admission or service capacity.

  Fifty alternating, uninstrumented source-backed cells at c1, c4, c16, c32,
  and c64 all passed exact validation with no failed requests or timeouts. The
  median same-pair request-rate deltas were -2.99/-0.84/-1.24/-0.59/+3.43
  percent, and mean-latency deltas were +2.69/+1.73/+1.90/+1.03/+1.78 percent.
  At c128, three exact baseline cells succeeded, while the candidate produced
  only two valid cells before a warmup write timeout and then failed its retry
  with 100 timed-out streams plus an exact byte-count mismatch. The local load
  generator reported saturation and both variants reached multi-gigabyte
  working sets, so c128 is not used for a percentage claim; the asymmetric
  candidate failures still block acceptance. The implementation, candidate-only
  tests, and benchmark were reverted. Evidence remains under the
  `quic-stream-cursor-*20260714a` ProtocolLab runs and
  `.artifacts/bdn/queued-stream-cursor-short-20260714a`. Future outbound staging
  work must pair copy reduction with bounded admission or earlier completion;
  cursor-only production can feed the existing backlog faster without improving
  service capacity. No result was uploaded or published.

- 2026-07-14: runtime-pressure diagnostics now sample the first observation,
  at least every 250 ms, and every 32 work items during a sustained burst
  instead of rebuilding all pressure measurements for every work item. The
  sampling state is per connection runtime, preserves time-based visibility
  when work is sparse, and does not alter queue admission, scheduling, flow
  control, cancellation, or packet ownership. A permanent observed-metrics
  benchmark covering 64 snapshot attempts improved from 291.1 to 46.97 ns per
  attempt (-83.9 percent) and from 120 to 4 B (-96.7 percent). Production and
  benchmark Release builds completed with zero warnings, and 29/29 focused
  metrics tests passed. The full test project completed 9,567 passes and five
  intentional skips with only the standing incomplete-content peer-close
  timeout; that exact test then passed five consecutive reruns.

  The central buffer pool now also reports bounded owner-tagged cumulative rent,
  requested-byte, and rented-byte counters. Every current rent site has an
  explicit owner, and application packet protection is separated from true
  handshake work. Source-backed c64 diagnostic run
  `quic-pressure-metrics-c64-gc-20260714b-quic-transport-v1-comparison` passed
  exact 12,800-stream and 838,860,800-byte validation with zero failures or
  timeouts. Of 12.59 GB of observed rented-byte increments, outbound stream
  payload staging accounted for 7.33 GB (58.21 percent), inbound datagrams
  1.80 GB (14.30 percent), outbound packet protection 1.61 GB (12.80 percent),
  receive segments 684.75 MB (5.44 percent), inbound packet protection
  641.85 MB (5.10 percent), and stream-write request ownership 409.78 MB
  (3.25 percent). True handshake work was 1.24 MB (0.01 percent), and sent-
  packet retention was 2.18 KB. This rejects sent-packet retention as the next
  byte-movement target for this workload and prioritizes eliminating redundant
  outbound payload staging and packet-protection copies. With every pool metric
  actively observed, the existing rent/return microbenchmark moved from 52.74
  to 58.58 ns (+11.1 percent), with zero allocation in both cases. That bounded
  diagnostic cost is retained explicitly; no zero-overhead tracing claim is
  made for observed owner attribution.

  In the paired c64 CPU traces, `RecordRuntimePressureSnapshot` fell from 6.87
  to 2.46 percent inclusive and from 1.20 to 0.14 percent exclusive. Metric
  tag construction and EventPipe allocation remained dominant, and the traced
  request rate was lower, so this run is diagnostic evidence only and makes no
  transport-throughput claim. No result was uploaded or published.

- 2026-07-14: completed STREAM reassembly spill and scratch lists now return to
  a two-slot, per-thread cache after `DataRead`, reset, connection cleanup, or
  replacement by a larger scratch list. The cache retains only cleared lists
  with capacity at most 64; larger fragmentation histories remain collectible.
  This preserves the existing two inline segments, geometric list growth,
  merge rotation, pooled payload ownership, receive accounting, and stream
  state lock. A permanent benchmark now drains 32 independent interleaved
  terminal streams rather than measuring only same-stream scratch reuse. Its
  Short allocation fell from 113.15 to 30.15 KB per operation (-73.4 percent),
  while the existing single hole-fill row fell from 4.31 to 1.72 KB and the
  repeated same-stream row remained 1.43 KB. Short-run timing was mixed and is
  not used as acceptance evidence.

  Focused receive, concurrency, thread-handoff, stream lifecycle, and RFC tests
  passed 39/39 before the final handoff test and 16/16 after it. Independent
  review found no correctness issue. The full test project completed 9,561
  passes with five intentional skips and only the standing incomplete-content
  close-notification timeout; that exact test then passed five consecutive
  reruns. The solution wrapper also retains a pre-existing reference to the
  absent `eng/tools/Incursa.Quic.TraceAnalysis` project, so full validation is
  reported from the actual test project rather than claiming a clean solution
  wrapper result.

  Source-backed c64 GC/counter run
  `quic-segment-list-cache-c64-gc-20260714a-quic-transport-v1-comparison`
  passed exact 12,800-stream and 838,860,800-byte validation with zero failures
  or timeouts. Against
  `quic-ordered-write-retry-c64-gc-20260713a-quic-transport-v1-comparison`, the
  sampled `List<BufferedSegment>` group fell from 47.22 MB to outside the top
  32 allocation groups, mean allocation rate fell from 51.40 to 33.69 MB/s,
  maximum GC heap fell from 685.27 to 465.90 MB, and sampled `byte[]` allocation
  fell from 624.87 to 455.43 MB. Peak pooled outstanding buffers fell from
  17,952 to 4,404 and bytes from 147.09 to 13.91 MB, but those pool and queue
  lifetime deltas remain trace-timing diagnostics rather than direct cache
  claims. The traced request rate was lower and queue-delay timing was mixed;
  no throughput claim is made from this instrumented run.

  Seven alternating uninstrumented c64 baseline/candidate pairs are retained
  as `quic-segment-list-cache-c64-ab-r{1-7}-{baseline|candidate}-20260714a-quic-transport-v1-comparison`.
  All 14 cells passed exact validation with zero failures or timeouts. Median
  same-pair deltas were -1.81 percent request rate, -1.22 percent p95 latency,
  and -2.25 percent mean latency, with wins in 3/7, 4/7, and 4/7 pairs. One
  candidate cell was a severe retained outlier; baseline and candidate request-
  rate relative ranges were 16.24 and 18.47 percent. Acceptance is therefore a
  bounded allocation reduction with median throughput inside the existing two-
  percent triage tolerance, not evidence of a throughput improvement. The
  post-change sent-packet dictionary array remained only 1.53 MB in the trace
  and still does not justify reviving either rejected whole-ledger design. No
  result was uploaded or published.

- 2026-07-14: flow-control-blocked stream writes now use a request-ordered
  retry queue instead of snapshotting, renting and insertion-sorting an array
  of every pending stream action, and rescanning it on each credit update. The
  existing reentrant monitor and pending-request dictionary remain the
  cancellation and terminal-lifecycle authority. Only writes that actually
  block on connection or stream credit enter the queue; cancellation removes
  the queued ID, one retry pass processes only the IDs present at its start,
  still-blocked writes requeue once, and terminal cleanup clears both
  structures. Focused ordering, cancellation, delayed-consumption, disposal,
  stream-credit, blocked-sender, and RFC tests passed 49/49. Independent diff
  review found no correctness issue. The all-up suite passed 9,559 tests with
  five intentional skips and reproduced only the standing incomplete-content
  close-notification and dropped-FIN timing failures; both exact tests then
  passed together in five consecutive reruns.

  The exact source-backed c64 GC/counter diagnostic
  `quic-ordered-write-retry-c64-gc-20260713a-quic-transport-v1-comparison`
  passed 12,800-stream and 838,860,800-byte validation with zero failures or
  timeouts. Against
  `quic-next-postread-c64-gc-20260713a-quic-transport-v1-comparison`,
  average packet/write queue delay fell from 135.9/152.9 ms to 57.6/87.3 ms,
  max shard queue depth fell from 2,606 to 634, sampled mean successful write
  completion fell from 1,901.5 to 85.4 ms, peak delayed application sends and
  application-send retained buffers fell from 367 to 267, peak pooled
  outstanding buffers fell from 34,251 to 17,952, and mean allocation rate
  fell from 126.35 to 51.40 MB/s. These are trace-instrumented shared-host
  diagnostics, not clean throughput claims. The paired CPU trace
  `quic-ordered-write-retry-c64-cpu-20260713a-quic-transport-v1-comparison`
  was neutral: `Monitor.Enter_Slowpath` moved from 9.42 to 8.96 percent and
  inclusive retry work moved from 0.89 to 0.95 percent, so acceptance does not
  claim a sampled-CPU reduction.

  Twenty-five uninstrumented source-backed baseline/candidate pairs used five
  alternating observations at c1, c4, c16, c32, and c64. Every run passed
  exact validation with zero failures or timeouts. Median same-pair throughput
  deltas were +4.21/+7.32/+3.03/+4.84/+2.85 percent; median p95 deltas were
  -11.31/-19.69/-4.29/-6.68/-3.17 percent; and median mean-latency deltas were
  -3.26/-4.82/-3.83/-3.29/-1.66 percent. Run IDs use
  `quic-ordered-write-retry-c{shape}-ab-r{1-5}-{baseline|candidate}-20260713a-quic-transport-v1-comparison`.
  c128 remains diagnostic-only: one candidate run lost exactly one 100-stream
  connection and failed exact validation, while three fresh valid pairs had
  mixed results with median +4.25 percent throughput, -0.64 percent p95, and
  -2.13 percent mean latency. The failed run and target-saturation warnings are
  retained; no c128 percentage is used to justify acceptance. This slice is
  accepted as a bounded retry-bookkeeping and queue-pressure reduction without
  an observed c1-c64 regression. No result was uploaded or published.

- 2026-07-13: a reusable open-addressed sent-packet store with backward-shift
  deletion was rejected at the microbenchmark gate. It used one entry array,
  tolerated sparse packet numbers, reused slots across a 10,000-packet
  advancing window, and passed 24/24 focused store, ownership, send-runtime,
  and retransmission tests. The production-shaped advancing-window benchmark
  showed that the large inline entry array and cluster reinsertion outweighed
  dictionary bucket savings: versus `Dictionary`, it was 20 percent slower at
  16 live packets, 2.78 times slower at 128, and 3.56 times slower at 2,304.
  Allocation fell 13 percent only at 16, then increased 85 percent at 128 and
  25 percent at 2,304. The candidate was reverted without a ProtocolLab run.
  Evidence is retained under
  `.artifacts/bdn/sent-packet-open-addressed-candidate-20260713a`. Do not repeat
  a whole-ledger open-addressed table with the full packet value inline; future
  sent-packet work needs a compact indirection or a direct small-dictionary
  path that avoids both per-packet dispatch and oversized sparse storage.

- 2026-07-13: a custom reentrant short-monitor processing barrier was also
  rejected. Unlike the `ReaderWriterLockSlim` design, it preserved same-thread
  completion callback reentrancy, synchronized cancellation and terminal
  sweeps with active processing, passed 25/25 focused tests, and passed the
  cancellation/reentrant-terminal race set ten consecutive times. It released
  the pending-action monitor during expensive write processing, but that let
  more writes accumulate without addressing shard service capacity. In the
  exact source-backed c64 diagnostic
  `quic-short-monitor-processing-c64-cpu-20260713a-quic-transport-v1-comparison`,
  average packet/write queue delay rose from the retained trace baseline's
  149.5/170.3 ms to 228.0/251.4 ms, max shard depth rose from 1,831 to 2,331,
  and mean write completion rose from 2.40 to 2.68 seconds. The single-run
  throughput improvement is not sufficient to accept worse backpressure.
  The runtime and candidate-only tests were reverted. Future work should
  reduce per-write service work or bound ingress rather than only widening
  pending-write admission.

- 2026-07-13: a `ReaderWriterLockSlim` processing barrier around pending stream
  actions was rejected before commit. It allowed new writes to enter a short
  dictionary monitor while a shard processed another write, and its focused
  cancellation, delayed-consumption, completion-pool, terminal-transition,
  and concurrency tests passed. Review found two unacceptable races: writer
  preference can deadlock a synchronous completion callback that queues a new
  write while cancellation waits as a writer, and terminal publication was
  not owned by the new barrier. The typed lock also required lifecycle disposal
  that could race late callbacks. Exact c64 validation passed in
  `quic-processing-gate-c64-cpu-20260713a-quic-transport-v1-comparison`, but
  the single diagnostic increased average packet/write queue delay to roughly
  200/210 ms and mean write completion to 2.70 seconds. A favorable unpaired
  throughput sample is not acceptance evidence. Retain this as a rejected
  design; a replacement must preserve monitor reentrancy, synchronize terminal
  sweep ordering, and release the monitor during expensive write processing.

- 2026-07-13: replacing only `pendingStreamActionRequestsGate` with .NET 10's
  dedicated `System.Threading.Lock` was rejected. The change preserved the
  existing reentrant lock scopes and passed 21/21 focused cancellation,
  disposal, delayed-consumption, completion-pool, and concurrent-stream tests,
  but it did not shorten the contended critical section. In the source-backed
  c64 CPU trace, `Monitor.Enter_Slowpath` fell from 9.42 percent to 5.56
  percent while `Lock.TryEnterSlow` added 4.82 percent, increasing combined
  lock-entry cost to about 10.38 percent. Exact c64 validation still passed,
  but the counter run increased average packet queue delay from 115.8 to
  157.1 ms, average stream-write queue delay from 124.0 to 176.5 ms, and mean
  write completion from 1.67 to 2.67 seconds. The one unpaired throughput
  sample improved, so it is retained only as evidence of shared-host variance,
  not as an acceptance signal. Candidate runs are
  `quic-lock-candidate-c64-counters-20260713a-quic-transport-v1-comparison`
  and `quic-lock-candidate-c64-cpu-20260713a-quic-transport-v1-comparison`.
  The production change was reverted. Do not repeat a lock-type-only
  substitution without first reducing lock hold time or retry work.

- 2026-07-13: ACK receipt tracking now uses a pooled ordered store with binary
  search, sparse insertion, and one bulk compaction for acknowledged ranges
  instead of `SortedList<ulong, QuicPacketReceipt>` growth plus per-packet
  removal. The store preserves packet-number ordering, duplicate replacement,
  inclusive range retirement, `ulong.MaxValue` handling, packet-space discard,
  and shard-serialized access. ACK-frame construction now also returns pooled
  range/frame resources if construction fails before ownership transfer.
  `QuicPacketReceiptStoreBenchmarks` measured the complete populate-and-retire
  lifecycle at 128/1,024/2,400 receipts: 6.830/160.626/1,004.000 microseconds
  and 7,312/64,800/261,578 B for `SortedList`, versus
  1.377/14.340/35.958 microseconds and 0/40/0 B for the pooled store. The
  source-backed c64 GC trace
  `quic-ack-receipt-store-c64-gc-20260713a-quic-transport-v1-comparison`
  passed exact 12,800-stream and 838,860,800-byte validation with zero failures
  or timeouts. Against
  `quic-next-postread-c64-gc-20260713a-quic-transport-v1-comparison`, mean
  allocation rate fell from 126.35 to 95.65 MB/s (-24.30 percent), sampled
  receipt arrays fell 18.67 percent, and paired `ulong[]` storage fell 19.19
  percent. Sixty untraced source-backed c1/c4/c16/c32/c64/c128 cells used five
  alternating baseline/candidate observations per shape; all passed exact
  validation with no generator saturation, failed requests, or timeouts.
  Median same-repetition throughput deltas were +6.08/+5.29/-0.32/+5.07/
  +1.69/+4.79 percent, while paired p95 deltas were -6.63/-4.52/-5.97/-6.63/
  -1.86/-2.96 percent. Two isolated shared-host outliers reinforce that these
  are diagnostic guardrails, not publishable percentage claims. Focused ACK
  tests passed 8/8, the broader ACK/recovery/congestion/RFC filter passed
  2,964/2,965 with its unrelated close-notification timeout passing five exact
  reruns, and the all-up suite passed 9,558 tests with five intentional skips
  and the standing incomplete-content peer-close timeout passing five exact
  reruns. The initial c128 control-plane request failure is retained under
  `quic-ack-receipt-c128-baseline-r1-20260713a-quic-transport-v1-comparison`;
  its fresh matched replacement and four further pairs all passed. This slice
  is accepted as a receipt-retirement allocation reduction with no observed
  throughput or latency regression across the tested load range. The touched
  production, benchmark, raw-server, and test projects built in Release with
  zero warnings. A broad `.slnx` build remains independently blocked by its
  reference to the absent `eng/tools/Incursa.Quic.TraceAnalysis` project and
  unrestored assets in three untouched sample/fuzz projects; this slice does
  not conceal or expand into that repository-hygiene issue.

- 2026-07-13: replacing the sent-packet dictionary's remove-then-insert path
  with a single `CollectionsMarshal.GetValueRefOrAddDefault` probe was
  rejected. The candidate was motivated by the c64 GC trace
  `quic-next-postread-c64-gc-20260713a-quic-transport-v1-comparison`, which
  sampled 50.3 MiB of sent-packet dictionary entry arrays, and the paired CPU
  trace showing insertion work on the send path. Focused send-ledger and
  retransmission tests passed 21/21, and concurrency/sharding tests passed
  14/14. Three alternating source-backed c64 baseline/candidate pairs all
  passed exact validation with zero failures or timeouts. Median throughput
  fell from 54.546 to 53.645 MiB/s (-1.65 percent), while median p95 latency
  rose from 6,715.066 to 7,018.287 ms (+4.52 percent). The implementation and
  its candidate-only tests were reverted. Do not repeat this single-probe
  design without a materially different ledger representation or stronger
  evidence that removes the observed latency cost. These are local shared-host
  diagnostics, not publishable throughput claims.

- 2026-07-13: internal terminal stream reads now use one reusable
  `IValueTaskSource<int>` completion per stream instead of allocating a
  `QuicStream.ReadCoreAsync` state machine plus `SemaphoreSlim` task node for
  every wait. The source remains busy until `GetResult`, so delayed consumption
  cannot reset the `ValueTask` token; overlapping or abandoned terminal reads
  conservatively fall back to the existing async path. Cancellation,
  disposal, expected terminal suppression, exception propagation, and public
  concurrent-read behavior remain unchanged. Focused read-lifecycle tests
  passed 30/30, the broader `QuicStream` filter passed 64/64, and the known
  incomplete-content HTTP/3 close-notification timeout passed five exact
  reruns. Two all-up Release runs each passed 9,554 tests with five intentional
  skips and reproduced only that existing full-suite-load close timeout; this
  is recorded as a residual suite flake rather than described as a fully green
  all-up result. In matched c1/c4/c16 source-backed raw upload campaigns, all 15
  baseline and 15 candidate cells passed exact validation with zero failures or
  timeouts. Candidate median throughput improved 11.57, 8.18, and 5.81 percent,
  while median p95 improved 14.48, 10.24, and 5.75 percent respectively. A
  separate c1 GC trace removed the prior 40.39 MB sampled
  `ReadCoreAsync` state-machine group and 27.39 MB `TaskNode` group; counter
  allocation rate fell from 11.78 to 10.28 MB/s (-12.75 percent). Matched run
  IDs are `quic-terminal-read-{baseline,candidate}-c{1,4,16}-r5-20260713*`;
  trace IDs are `quic-next-lowc-c1-gc-quic1035151b-20260713a` and
  `quic-terminal-read-source-c1-gc-quic1035151b-20260713a`. These are local
  shared-host diagnostics, not publishable throughput claims.

- 2026-07-13: the final current-source raw QUIC peer rerun completed against
  Incursa commit `1035151b`, ProtocolLab commit `fe44a78`, quic-go, and MsQuic.
  The diagnostic campaign covered stream throughput, duplex streams, and
  100-by-64-KiB multiplexing at c1/c4/c16/c32/c64/c128 with identical compiled
  `quic-go-raw-load`, Release targets, clean network profile, deterministic
  round-robin ordering, and five selected observations per implementation and
  shape. The selected ledger contains 270 rows in 54 groups with zero failed or
  timed-out requests. Duplex completed all 90 planned cells without repair.
  Transient empty load-tool results in the throughput and multiplex campaigns
  were handled conservatively: the affected repetition was discarded for all
  three implementations and replaced by one fresh matched round-robin
  observation for all three, never only for the failed peer. On stream
  throughput Incursa was roughly level with quic-go at c32 and within about
  3-10 percent at c16/c64/c128, but remained slower at c1/c4 and behind MsQuic
  at every shape. On duplex Incursa exceeded quic-go from c4 through c128 but
  remained behind MsQuic. On multiplex Incursa trailed quic-go at c1/c4,
  exceeded it by roughly 10-15 percent from c16 through c128, and remained
  materially behind MsQuic. Day-over-day absolute movement affected all peers,
  so old/new deltas are environment-sensitive and are not attributed to the
  Incursa source change. The provenance-rich summary is retained at
  `.artifacts/comparisons/raw-peer-current-quic1035151b-20260713a/peer-summary.{json,md}`;
  every constituent run retains its own evidence bundle under ProtocolLab
  `.artifacts/runs`. This is shared-host diagnostic evidence, not a publishable
  ranking or throughput claim.

- 2026-07-13: raising the HTTP/3 response QUIC write cap from 4 KiB to 8 KiB
  was rejected after exact large-payload and deterministic paired proof. All 30
  c16 cells across five baseline/candidate AB/BA pairs passed exact HTTP/3 and
  payload validation for 1 KiB, 64 KiB, and 1 MiB responses with zero failures
  or timeouts. The candidate's median paired request-rate deltas were +2.61
  percent at 1 KiB, +7.62 percent at 64 KiB, and only +0.95 percent at 1 MiB.
  Median paired p95 improved 6.47 and 9.11 percent at 1 KiB and 64 KiB, but
  regressed 3.86 percent at 1 MiB; the final pair also reversed at 1 KiB and
  64 KiB. The first baseline run showed a large cold-start artifact, reinforcing
  that the earlier block-order +1.75 percent signal was not decisive. Because
  the primary 1 MiB lane was effectively flat with worse latency, the candidate
  failed the broad large-response acceptance gate and was reverted. Evidence is
  retained under the
  `quic-h3-chunk8k-paired-p01b-*-20260713a-h3-local-v1` and
  `quic-h3-chunk8k-paired-p02-*-20260713a-h3-local-v1` through
  `quic-h3-chunk8k-paired-p05-*-20260713a-h3-local-v1` run families. Do not
  revisit a global response-write-cap increase without a materially different
  adaptive or workload-aware design. This is shared-host diagnostic evidence,
  not a publishable throughput claim.

- 2026-07-13: narrowing `pendingStreamActionRequestsGate` around stream-write
  processing was rejected after concurrency review and full-suite proof. The
  motivating c64 sampled-thread-time trace
  `quic-current-scaling-c64-cpu-retry-20260713a-quic-transport-v1-comparison`
  attributed the largest direct `Monitor.Enter` caller groups to stream-write
  chunking, pending-action registration, write handling, retry, and stream
  bookkeeping. A first claim/remove/requeue prototype passed focused tests and
  a 9,556-pass/5-skip full suite, but review showed that temporarily removing
  processing requests let disposal miss non-blocked writes. A second design
  kept requests visible with explicit `Pending`/`Processing` state and passed
  22/22 lifecycle tests plus 129/129 broader stream/flow-control tests, including
  cancellation, disposal, pooled-completion reuse, and same-thread completion
  reentrancy. It was still rejected: waiting for active processing during
  terminal cleanup deadlocked when the send path itself discarded the
  connection. The decisive full run stopped after 2,682 passes and one skip in
  `REQ_QUIC_RFC9001_S6P6_0004.RuntimeSendPathDiscardsConnectionWhenSuccessorConfidentialityLimitIsReached`;
  the hang dump is retained under
  `tests/Incursa.Quic.Tests/TestResults/bfde7ed5-d3ec-4849-a187-f87deb8a8e8d/`.
  All candidate code and tests were reverted. Do not repeat a monitor-wait or
  dictionary-membership ownership design; a materially different attempt must
  model reentrant terminal transitions directly and prove cancellation,
  disposal, retry ordering, delayed `ValueTask` consumption, and pooled-source
  lifetime before performance measurement. This is local diagnostic evidence,
  not a throughput claim.

- 2026-07-13: externalizing packet number and packet-number space from the
  packed sent-packet value into the existing packed dictionary key was
  rejected as insufficient leverage. A corrected like-for-like packed
  prototype reduced dictionary allocation versus the current value from 45.42
  to 42.69 KiB at 128 packets, 468.55 to 440.18 KiB at 1,024, and 2,075.98 to
  1,950.29 KiB at 8,192, about six percent. At the observed 43.5 MiB c32 entry
  allocation this would save only about 2.6 MiB, roughly 0.15 percent of total
  sampled allocation, while requiring packet reconstruction across ACK, loss,
  retransmission, discard, routing, and diagnostic paths. High-retention
  population time was neutral and the 128-packet ShortRun was noisy and slower
  than the direct packed value. The production candidate was not implemented;
  benchmark-only code was reverted. Evidence is retained under
  `.artifacts/bdn/sent-packet-externalized-identity-prototype-20260713a` and
  `.artifacts/bdn/sent-packet-externalized-identity-packed-prototype-20260713b`.
  Do not revisit identity externalization without a design that removes more
  retained state or a trace showing the reconstruction cost is independently
  useful.

- 2026-07-13: runtime shard packet work items now encode null and the three
  common one-hot ECN observations in the existing flags byte. Arbitrary
  full-width cumulative `QuicEcnCounts` values remain exact in a rare extended
  packet-state wrapper that also preserves owned-buffer release. This removes
  the always-inline 24-byte ECN field and reduces the work-item layout from 152
  to 128 bytes (-15.8 percent). Short BenchmarkDotNet evidence at 1,024 items
  reduced array allocation from 152.04 to 128.04 KiB and mean allocation time
  from 6.664 to 6.198 us. Focused shard, ECN, endpoint, listener, metrics, and
  ownership tests passed 184/184; explicit null and extended-wrapper buffer
  return guardrails passed 11/11. The full Release suite before those final
  guardrails passed 9,551 tests with five intentional skips, and the definitive
  suite after them passed 9,552 with the same five intentional skips.
  Independent review found no correctness defect and its residual null/release
  coverage concern was addressed by the final guardrails. A matched c32 GC trace passed exact
  validation with zero failures/timeouts and reduced sampled work-item array
  allocation from 5.22 to 3.51 MiB despite completing 12,800 streams versus
  9,600 in the baseline. Fresh uninstrumented shared-host guardrails were
  neutral at c1 (-0.74 percent request rate, -8.1 percent p95) and c4 (-0.50
  percent request rate, -0.81 percent p95). Five-pair deterministic
  round-robin runs were neutral at c16 (median request rate -0.94 percent,
  median p95 +0.53 percent) and positive at c32 (median request rate +2.8
  percent, median p95 -2.83 percent); every c16/c32 cell completed its exact
  stream count with zero failures/timeouts. BDN evidence is under
  `.artifacts/bdn/runtime-work-item-ecn-compact-candidate-20260713a`.
  ProtocolLab evidence is retained under the
  `quic-runtime-workitem-ecn-*-20260713a-quic-transport-v1-comparison` run
  families. All ProtocolLab results are local shared-host diagnostic evidence,
  not publishable peer-comparison claims.

- 2026-07-13: a hybrid sent-packet store that kept the first 256 application
  packets in a dictionary and then migrated to recyclable 256-entry
  `ArrayPool` segments was rejected. This was materially different from the
  earlier fixed segmented store because retired segment arrays were returned
  and reused across monotonically advancing packet ranges. Short
  BenchmarkDotNet evidence showed the intended high-retention benefit: at a
  2,304-packet live window, mean lifecycle time improved from 395.5 to 350.6
  us and allocation fell from 814.7 to 80.04 KiB. The 128-packet path was
  still worse, moving from 191.9 to 252.9 us and from 30.34 to 33.3 KiB. A
  source-backed c32/s100 GC trace passed exact validation for 12,800 streams
  with zero failures/timeouts and reduced sampled sent-packet storage from
  43.62 MiB of dictionary entries to 2.80 MiB of transition dictionary
  entries plus 2.04 MiB of pooled packet arrays, about 88.9 percent. The
  trace-instrumented request rate was neutral (+0.16 percent), peak working
  set fell 4.8 percent, p95 regressed 8.1 percent, and target CPU time rose
  2.5 percent. The decisive uninstrumented c1 guardrail used fresh baseline
  and candidate servers with three repetitions each: median request rate fell
  from 210.65 to 183.03 requests/s (-13.1 percent) and median p95 rose from
  543.37 to 614.61 ms (+13.1 percent), with no failures or timeouts. The
  candidate is rejected and reverted because it violates the low-concurrency
  non-regression gate; c4 and higher uninstrumented campaigns were not run.
  Benchmark evidence is under
  `.artifacts/bdn/sent-packet-hybrid-pooled-segments-candidate-20260713c`;
  ProtocolLab evidence is under
  `quic-sent-packet-hybrid-c32-gc-20260713a-quic-transport-v1-comparison`,
  `quic-sent-packet-hybrid-baseline-c1-repeat3-20260713a-quic-transport-v1-comparison`,
  and
  `quic-sent-packet-hybrid-candidate-c1-repeat3-20260713a-quic-transport-v1-comparison`.
  The negative-result record is retained under ProtocolLab `.artifacts`.
  Do not repeat a whole-ledger storage wrapper unless the ordinary small
  dictionary path remains direct and allocation reduction is introduced
  without adding per-packet dispatch overhead at low retention.

- 2026-07-13: sent-packet storage diagnostics now report application-data
  packet-number span and backing dictionary capacity alongside the existing
  retained packet, buffer, byte, and age measurements. A source-backed
  c32/s100 multiplex run passed exact validation for all 9,600 streams with no
  failures or timeouts. At the high-retention end, application packet-number
  span and retained packet count were nearly identical (P95 2,276 versus
  2,252; maxima 2,424 versus 2,400), showing that the live ledger is dense
  rather than sparse. Dictionary capacity still reached 3,368 entries for a
  2,400-packet maximum and remained elevated after bursts. The first capture
  exposed ProtocolLab's 100-histogram collection ceiling; a diagnostic rerun
  at 200 histograms captured the new series without the ceiling warning, and
  the collector default was raised accordingly. Evidence is retained under
  `quic-sent-packet-storage-h200-c32-counters-20260713c-quic-transport-v1-comparison`.
  This is local shared-host counter evidence and is not a throughput claim. It
  supports investigating recyclable sliding storage, but does not justify
  repeating the rejected fixed 256-slot segmented store.

- 2026-07-13: recovery packet-number-space ledgers now retain sent timestamps
  in their ordered value arrays and keep packet-protection level plus the full
  64-bit 1-RTT key-update epoch once as the current metadata default. Exact
  metadata for 0-RTT/1-RTT or key-update transitions is retained in a lazy
  side map, and the default is rebased when the prior phase drains. This
  preserves nullable and arbitrary internal values, duplicate updates,
  protection-level discard, full-width key epochs, ACK removal, loss removal,
  and packet-number ordering while replacing the common 24-byte value array
  with an 8-byte timestamp array. Short BenchmarkDotNet evidence at 1,024
  entries reduced allocation from 79.03 to 31.78 KiB and mean population time
  from 23.90 to 18.49 us; at 8,192 entries allocation fell from 639.28 to
  255.98 KiB and time from 329.62 to 172.52 us. A single metadata transition
  remained near the common result, while the deliberately adverse
  half-old/half-new transition allocated 16-29 percent more than the combined
  ledger; that uncommon transition cost is retained rather than hidden.
  Focused recovery/RFC tests passed 1,161/1,161, including a new interleaved
  ACK/loss guardrail after repeated metadata rebases. The full Release suite
  passed 9,541 tests with five intentional skips and one multiconnect failure
  caused by an overlapping Debug suite reaching the same temporary server;
  the exact failed test passed 1/1 after the competing run was stopped.
  Independent review found no actionable defect. The matched source-backed
  c32/s100 trace passed exact validation for 12,800 streams with zero
  failures/timeouts and removed the old recovery state array. Detailed stack
  attribution reduced the recovery ledger's sampled key/value arrays from
  11.68 MiB to 5.77 MiB, about 50.6 percent, with no recovery metadata side
  dictionary observed. Trace-instrumented throughput moved +1.58 percent and
  p95 moved -1.72 percent, both within the retained 2 percent neutral band.
  BDN evidence is under `.artifacts/bdn/recovery-split-metadata-candidate-20260713a`;
  trace and comparison evidence is under
  `quic-recovery-split-metadata-c32-gc-20260713a-quic-transport-v1-comparison`,
  `.artifacts/perf-analysis/quic-recovery-split-metadata-c32-gc-20260713a`,
  and `.artifacts/perf-triage/quic-recovery-split-metadata-c32-gc-20260713a`.
  This is local shared-host trace evidence and is not publishable.

- 2026-07-13: cumulative receive-side ECN counters now live once per packet
  number space instead of being repeated in every retained packet receipt.
  `QuicPacketReceipt` remains responsible for packet timing and the
  ACK-eliciting bit, while ACK_ECN generation preserves the latest cumulative
  snapshot across out-of-order packet numbers and acknowledged-range
  retirement and clears it when the packet number space is discarded. This
  reduces the receipt value from 48 bytes to 24 bytes without changing retained
  packet numbers or ACK ranges. Short BenchmarkDotNet evidence at 32, 128, and
  1,024 receipts reduced allocation from 1.86 to 1.11 KiB, 12.39 to 7.14 KiB,
  and 110.53 to 63.28 KiB; mean population time improved by roughly 16-20
  percent. Focused ACK/ECN and layout tests passed 81/81, the final duplicate
  packet guardrail passed in the focused rerun, and the full Release suite
  passed 9,538 tests with five intentional skips and zero failures. Independent
  review found no actionable defect. The matched source-backed c32/s100 trace
  passed exact validation with zero failures/timeouts and completed 12,800
  streams versus the retained baseline's 9,600. Sampled
  `QuicPacketReceipt[]` allocation fell from 18.23 MiB to 10.26 MiB, or from
  1,991 to 841 bytes per completed stream; sampled top-32 allocation per stream
  also fell about 13 percent. Trace-instrumented request rate and p95 moved from
  878.8 requests/s and 3,522 ms to 957.1 requests/s and 3,207 ms, but these
  shared-host values are diagnostic only and are not accepted as throughput
  claims. BDN evidence is retained under
  `.artifacts/bdn/packet-receipt-space-ecn-candidate-20260713a`; ProtocolLab
  evidence is retained under run
  `quic-packet-receipt-space-ecn-c32-gc-20260713a-quic-transport-v1-comparison`.
  The ProtocolLab evidence is local shared-host trace evidence and is not
  publishable.

- 2026-07-13: unordered application-send queues with a compact priority range
  now materialize directly into their rented output array using a stable linear
  priority distribution. The queue's existing per-priority sequence order
  preserves FIFO without comparison sorting; arbitrary priority ranges still
  fall back to the proven `Array.Sort` path. This is materially different from
  the retained rejected generic-comparer and `Span.Sort` experiments. In a
  fresh baseline and two repeated Short BenchmarkDotNet candidate runs,
  128-entry materialization improved from 8.95 us and 64 B to 2.11-2.22 us
  and 0 B, while 512 entries improved from 44.15 us and 64 B to 8.51-9.31 us
  and 0 B. End-to-end enqueue plus materialization improved from 13.38 us to
  5.70-6.14 us at 128 entries and from 63.79 us to 18.99-20.96 us at 512.
  Focused queue, scheduler, and metrics tests passed 52/52; a queue-only
  run passed 25/25 after adding extreme-priority fallback and unordered
  remove/replace/append ownership coverage. Independent review found no
  correctness defect. The full Release suite passed 9,534 tests with five
  intentional skips and one failure in
  `DoqFatalProtocolErrorTests.ClientWithMaxUnsolicitedResets_ClosesConnectionWhenLimitExceeded`;
  the exact test fails identically on clean `main` after a fresh restore, so it
  is retained as a pre-existing regression rather than attributed to this
  candidate. A matched source-backed c32/s100 GC trace rebuilt the
  candidate server from this worktree, passed exact validation for all 9,600
  completed streams with zero failures/timeouts, and removed the baseline
  `System.Comparison<PendingApplicationSendRequest>` allocation group that
  represented 17,515,312 estimated bytes. Trace-instrumented request rate was
  neutral within shared-host noise at 887.6 versus 878.8 requests/s, while p95
  moved from 3542 to 3522 ms. Those values are diagnostic only and are not
  accepted as throughput claims. BDN evidence
  is retained under `.artifacts/bdn/send-queue-priority-distribution-*`; the
  ProtocolLab runs are `quic-sent-packet-c32-gc-20260713a-quic-transport-v1-comparison`
  and `quic-send-queue-priority-distribution-final-c32-gc-20260713a-quic-transport-v1-comparison`.
  All ProtocolLab evidence is local shared-host trace evidence and is not
  publishable.

- 2026-07-13: contiguous STREAM receive spill segments now reserve 8 KiB
  after the initial 4 KiB block fills, while first, sparse, and out-of-order
  fragments retain the existing 4 KiB policy. A 64 KiB stream arriving in
  1,152-byte frames now retains 9 mixed blocks and 68 KiB of capacity instead
  of roughly 19 small blocks, without changing logical bytes, flow control,
  duplicate handling, FIN, reset, or pool ownership. Same-duration c64/s100
  counter evidence passed with zero failures/timeouts and reduced peak pooled
  buffers from 102,575 to 33,984, peak outstanding bytes from 403,283,968 to
  278,396,928, and maximum managed heap from 1,568.6 MiB to 1,098.8 MiB.
  Three-repeat c64 medians were neutral within shared-host variance: request
  rate -1.0 percent and p95 +0.35 percent. A three-repeat c1/c4/c16/c32 matrix
  passed all 24 baseline and candidate cells; median request-rate changes were
  +7.5, +6.1, +4.1, and -1.9 percent, while p95 changes were -2.3, +4.9,
  -0.9, and -1.4 percent. Focused receive/metrics tests passed 34/34, broader
  stream-read/flow-control tests passed 163/163, and the full suite passed
  9,533 tests with five intentional skips. Runtime packet queue peaks remained
  noisy and did not improve in the single counter pair, so queue scheduling
  remains open; this slice is accepted for the durable retention reduction.
  All ProtocolLab evidence is local shared-host diagnostic evidence and is not
  a publishable benchmark claim.

- 2026-07-13: staged sent-packet dictionary growth at 64, 256, and 1,024
  tracked packets was rejected after a matched source-backed c32/s100 GC trace.
  The candidate reduced sampled dictionary growth events from roughly 171 to
  135, but sampled sent-ledger resize allocation increased from about 42.9 MiB
  to 44.1 MiB and total sampled allocation also increased slightly. The code
  and focused capacity tests were reverted, and the ProtocolLab run plus
  negative-result record remain under `.artifacts/`. Do not repeat capacity
  staging without a materially different sent-packet storage design and a
  demonstrated byte-allocation reduction.

- 2026-07-13: a materially different 256-slot segmented sent-packet store was
  also rejected. Exact production-type BenchmarkDotNet evidence looked strong
  for a fixed snapshot: at 2,304 packets, population fell from 251.8 us and
  814.6 KiB to 87.1 us and 253.7 KiB. The live transport trace disproved that
  result as an end-to-end optimization because packet numbers continuously
  advance and empty chunks are retired. In matched source-backed c32/s100 GC
  traces, the candidate replaced 41.6 MiB of sent-packet `Dictionary.Entry[]`
  allocation with 240.3 MiB of `QuicConnectionSentPacket[]` allocation plus
  2.43 MiB of chunk objects. Both runs completed 9,600 streams with zero
  failures or timeouts; request rate moved only +0.7 percent, p95 regressed
  4.1 percent, and peak working set was effectively unchanged. The candidate
  passed 9,539 tests with five intentional skips and independent review found
  no correctness defect, but it is rejected for allocation churn. The code and
  candidate benchmarks were reverted. Do not repeat fixed packet-number chunks
  unless storage can be recycled across monotonically advancing packet ranges
  without allocating a large cleared value array per retired chunk. All run
  evidence is local shared-host diagnostic evidence and is not publishable.

- 2026-07-13: a bounded cooperative-fairness candidate yielded each runtime
  shard after 64 processed work items so asynchronously scheduled application
  reads could run before the shard drained its entire packet backlog. Focused
  FIFO, timer, metrics, and runtime-shard tests passed 39/39. The first c64
  ProtocolLab run is retained as inconclusive because the development alias
  launched a stale source-server binary; the source server was then rebuilt
  explicitly before the valid rerun. The rebuilt candidate passed exact
  c64/s100 validation and emitted roughly 14,900 cooperative yields across
  eight shards, but active-connection receive ownership remained about
  1,918-1,936 buffers with 5.30-5.36 MiB unread payload, while packet queue
  peaks remained 800-1,702. Those signals did not improve over the retained
  baseline of 1,882-1,898 buffers, roughly 5.25 MiB unread payload, and
  524-1,645 queued packets. The candidate is rejected and reverted; negative
  records are retained under ProtocolLab `.artifacts/negative-results/`. Do not
  repeat a generic shard `Task.Yield` budget without a materially different
  scheduling design.

- 2026-07-13: the remaining simple receive-window midpoint was also rejected.
  A source-backed 32 KiB per-stream window passed the one-shot protocol proof
  but the uninstrumented c64/s100 benchmark load exited nonzero, matching the
  previously retained 16 KiB failure. Together with the valid 64 KiB run that
  completed but did not reduce retained receive ownership, this closes
  arbitrary receive-window tuning as the current remedy: 16/32 KiB do not
  sustain the workload, while a 64 KiB window permits the complete 64 KiB
  request burst. The source server is restored to its original configuration,
  and the failed candidate is retained under ProtocolLab
  `.artifacts/negative-results/`.

- 2026-07-12: receive-retention diagnostics now distinguish owned STREAM
  receive segments, retained segment capacity, unread payload bytes, and
  streams with unread data. The counters use constant-time aggregates updated
  under the existing stream-state lock at rent, read, reset, and release
  boundaries; focused metrics and receive-buffer lifecycle tests pass 33/33,
  including duplicate-frame, partial-read, multi-stream, and reset coverage.
  A source-backed c64/s100 raw QUIC multiplex diagnostic run completed all
  12,800 streams with zero failures or timeouts and passed exact validation.
  It observed 90,071 outstanding 4 KiB buffers globally while active
  per-connection snapshots peaked at 1,882-1,898 owned receive segments and
  roughly 5.25 MiB unread payload. Packet-receive queues simultaneously peaked
  at 524-1,645 items per shard. This confirms receive-segment lifetime as the
  dominant 4 KiB retention source while preserving queue depth as a separate
  scheduling concern. The c128 diagnostic retained one timed-out 100-stream
  connection and is saturation evidence only. The earlier 16 KiB stream-window
  experiment is explicitly inconclusive: its child command launched the
  source-backed QUIC server, so the ProtocolLab-local window edit was never
  executed. Do not cite that run as accepting or rejecting smaller receive
  windows. Evidence is retained under ProtocolLab `.artifacts/runs/` and
  `.artifacts/negative-results/`; no throughput claim is made from counter-
  instrumented shared-host runs.

- 2026-07-12: queue-depth diagnostics now expose absolute observable gauges
  backed by active shard-owned registrations. Inbox depth comes directly from
  each channel, per-kind depth is maintained continuously with enqueue-before-
  publish ordering, late or reattached listeners see the current backlog, and
  disposed shards stop publishing instead of retaining stale series. Focused
  metrics tests pass 20/20, including late-listener and disposal-cardinality
  coverage. A matched untraced c32/s100 multiplex comparison passed all five
  baseline and five final-candidate cells; the final candidate median was
  1,011.10 requests/s versus the retained 970.14 baseline (+4.22 percent). This
  shared-host result is accepted only as no-regression evidence, not as a claim
  that depth tracking improves throughput. The final Release suite passed
  9,529/9,534 with five intentional skips. An earlier suite attempt had one
  duplicate-pseudo-header connection-close timeout; that exact test then passed
  5/5 focused repetitions before the clean full rerun. Core SpecTrace validation
  currently reports the same 2,644 pre-existing schema/relationship errors on
  both this branch and clean `main`; no SpecTrace artifacts changed in this
  slice. The corrected c128 trace showed peak packet queue depth of 9,003 and
  stream-write depth of 3,443 across eight
  balanced shards, versus 175,254 outstanding 4 KiB buffers. This disproves
  the earlier interpretation of interval depth deltas and shows that most
  retained 4 KiB buffers are stream receive storage rather than queued UDP
  datagrams. Three evidence-backed candidates were rejected and retained under
  ProtocolLab `.artifacts/negative-results`: raising the default shard cap to
  16 increased CPU/heap/timeout pressure without reducing queue depth; lowering
  only the raw target connection window to 1 MiB did not reduce peak buffer
  retention; and a bounded stream-write priority lane reduced trace write depth
  from 3,443 to 444 but increased peak buffer retention, retained the same 3/5
  c128 validation rate, and moved successful-run median throughput only +0.54
  percent. Do not repeat these candidates without a materially different
  design. Queue/backpressure work remains open around receive-segment lifetime,
  application read/write coupling, and sent-packet retention.

- 2026-07-15: a bounded per-shard listener send-queue candidate was rejected
  before ProtocolLab measurement. The accepted c64 CPU trace showed synchronous
  listener UDP send work inside runtime-shard packet service, so the candidate
  transferred detached datagram ownership to one ordered sender per shard,
  bounded each queue at 256 datagrams, and used an ordering-preserving
  producer drain when the bound was reached. Production and test projects built
  cleanly, and focused queue ordering and ownership tests were added during the
  experiment. However, the existing transient UDP-loss integration test
  `DroppedServerFinIsRecoveredAndShardContinuesProcessing` deterministically
  timed out twice while reading the 64 KiB response after one dropped send.
  The synchronous baseline keeps packet emission and recovery bookkeeping on
  the same shard service boundary; decoupling them changed that recovery timing
  enough to violate the existing five-second contract. The runtime, metrics,
  and test candidate was fully reverted. Do not repeat an asynchronous listener
  send queue without a design that couples actual socket emission to congestion
  and loss-recovery accounting.

- 2026-07-12: incomplete stream try-writes now return the runtime's pooled
  `ValueTask<bool>` directly instead of allocating
  `QuicStream.TryWriteCoreAfterRuntimeWriteAsync` for every suspended write.
  Completion callbacks release the per-stream write gate before delayed result
  consumption while preserving pooled token lifetime, cancellation, disposal,
  terminal failure, final-write closure, and write serialization. Focused
  write-request tests passed 17/17, the wider stream and HTTP/3 slice passed
  122 tests with one existing skip, the solution built with zero warnings, and
  the full suite passed 9,527/9,532 with five intentional skips. One shutdown
  ordering failure from the first full-suite run passed five consecutive exact
  reruns and the clean full-suite rerun. An independent concurrency review
  found no correctness defect; large multi-chunk writes retain their existing
  async sequencing helper and are the explicit residual test gap. The first
  profile attempt was rejected because an existing debug endpoint owned UDP
  port 5444, causing the new source target to exit while readiness probed the
  old endpoint. Corrected source-backed traces used a disposable same-commit
  ProtocolLab manifest on port 5544 and passed exact 64 KiB validation. The
  baseline trace sampled 271
  `TryWriteCoreAfterRuntimeWriteAsync` state-machine allocations with
  28,810,936 estimated bytes; the candidate sampled no matching or replacement
  `AwaitTryWrite` group. Matched untraced c16/s10 confidence runs passed all
  18 validation and benchmark cells across nine baseline and nine candidate
  repetitions. Median request rate was effectively flat at +0.20 percent,
  p95 improved 0.38 percent, and allocation rate improved 6.55 percent with no
  signal regressing beyond the two-percent triage tolerance. Retained evidence
  is under `.artifacts/perf-analysis/quic-incomplete-write-*`,
  `.artifacts/protocol-lab-runs/quic-incomplete-write-20260712a`, and
  `.artifacts/perf-triage/quic-incomplete-write-compare-stable-20260712a`.
  Treat all results as local shared-host diagnostic evidence, not publishable
  benchmark claims. The next priority is queue-depth and backpressure
  attribution using the retained c128 multiplex failures and target telemetry.

- 2026-07-10: STREAM receive storage now reserves eight backing slots on its
  first spill from the two inline segments, avoiding the immediate four-to-eight
  `BufferedSegment[]` growth observed in the retained duplex allocation trace.
  The focused receive-buffer, read-lifecycle, public stream-concurrency, and
  requirement-home slices passed 42/42 tests. In BDN Short, the 16-hole workload
  improved from 6.784 to 6.238 microseconds and from 4.43 to 4.28 KB per
  operation. The repeated four-segment workload improved from 5.707 to 5.595
  microseconds but increased from 1.27 to 1.40 KB, explicitly retaining the
  bounded 128-byte over-reservation tradeoff for streams that spill but never
  exceed four segments. A source-backed five-repetition raw duplex run passed
  validation and benchmark execution 5/5 with no failed or timed-out requests;
  its median improved from 135.50 to 189.11 operations per second and p95 from
  42.994 to 31.690 milliseconds against the retained receive-path run, but high
  local variance makes this no-regression evidence rather than a throughput
  claim. In a matched-shape GC trace, the candidate served 412 requests versus
  268 while `BufferedSegment[]` samples fell from 10 events and 1,072,760
  estimated bytes to 3 events and 325,224 estimated bytes, about 80 percent
  lower per request. Total sampled allocation per request fell about 23.5
  percent. Evidence is retained under
  `.artifacts/bdn/stream-first-spill-*`,
  `.artifacts/perf/stream-first-spill8-20260710`, and ProtocolLab runs
  `raw-incursa-duplex-first-spill8-source-20260710a` and
  `raw-incursa-duplex-first-spill8-gc-20260710a`. It remains local diagnostic,
  source-backed evidence with variance and publishability-readiness blockers.

- 2026-07-10: repeated raw stream-throughput stalls were traced to the 1-RTT
  key-update retention policy rather than stream capacity or FIN recovery. The
  server retained the previous packet-protection generation until a recovery
  PTO-derived deadline that could grow past 24 seconds, then refused a valid
  subsequent peer update even after its current-phase packet had been
  acknowledged. The runtime now authenticates the candidate next-phase packet
  before discarding the obsolete retained generation and installing the
  successor; unacknowledged or unauthenticated packets cannot force disposal.
  Focused key-update and scheduler coverage passed 21/21, and the broader
  RFC 9001 plus scheduler slice passed 362/362. The final uninstrumented
  three-repetition c1/s4 run completed 700/700, 696/696, and 716/716 measured
  1 MiB uploads with zero failures or timeouts at 46.25-47.55 MiB/s. Native
  comparison matched all three cells and changed each from failed validation
  and benchmark execution to passed/succeeded, removing every timeout and
  request-failure warning. Evidence is retained under
  `.artifacts/runs/quic-raw-stream-keytransition-repeat-20260710a-*`,
  `.artifacts/runs/quic-raw-stream-acked-retention-final-20260710a-*`,
  `.artifacts/runs/quic-raw-stream-acked-retention-committed-20260710a-*`, and
  `.artifacts/comparisons/quic-raw-stream-acked-retention-final-20260710a.json`
  in `protocol-lab-internal`. This remains local diagnostic evidence because
  variance and publishability-readiness gates are not satisfied.

- 2026-07-10: source-backed raw stream-throughput evidence isolated a missing
  connection-level flow-control recovery path. The runtime accepted
  `STREAM_DATA_BLOCKED` but did not parse valid `DATA_BLOCKED` frames, so a peer
  stalled behind a lost `MAX_DATA` grant could not trigger a replay. The
  runtime now acknowledges `DATA_BLOCKED` and replays the current `MAX_DATA`
  only when the peer reports an older connection limit. Focused RFC 9000 flow
  control tests passed 32/32. A three-repetition 5-second c1/s4 stress run then
  completed 628/628 measured uploads with 652/652 server stream summaries
  reaching full payload and write completion. A longer 15-second sample
  improved from predominantly partial-upload timeouts to 2/3 successful
  repetitions; its remaining failed repetition sent all 272 MiB and timed out
  waiting for response EOF, isolating the next issue to FIN/stream-close
  recovery rather than receive credit. Evidence is retained under
  `.artifacts/runs/quic-raw-stream-summary-20260710a-*`,
  `.artifacts/runs/quic-raw-stream-datablocked-fix-20260710a-*`, and
  `.artifacts/runs/quic-raw-stream-fin-summary-20260710a-*` in the
  `protocol-lab-internal` worktree. These remain local diagnostic runs.

- 2026-07-10: fresh package-backed local HTTP/3 peer cells now use the current
  ProtocolLab evidence-bundle pipeline for the official
  `http3.payload.bytes.1kb` scenario at c4/s4 with the same managed load tool,
  load profile, duration, warmup, and three repetitions. All 9/9 cells passed
  validation and benchmarking. The retained local report under
  `.artifacts/perf-peer-matrix-20260710/report/quic-peer-matrix-confidence-20260710`
  records medians of 8,176.11 req/s for `quic-dotnet-dev`, 3,438.05 req/s for
  nginx, and 3,257.82 req/s for quic-go. Quic-go reached `confidence` quality
  with 2.66% relative range; the combined Incursa/nginx bundle remained
  `diagnostic` because nginx reached 15.16% relative range. These are local,
  non-isolated comparison signals, not public rankings.

- 2026-07-10: the public API stream-transfer benchmark surface was revalidated
  against the current runtime. Focused eight-stream Incursa loopback correctness
  proof passed 1/1. BDN Short proof retained under
  `.artifacts/bdn/public-concurrent-closeout-20260710` completed both matched
  public implementations: Incursa measured 29.59 ms / 1,537.31 KB and
  `System.Net.Quic` measured 18.08 ms / 145.94 KB per eight-stream concurrent
  request/response operation. This closes the benchmark-coverage item while
  retaining the latency and allocation differences as optimization signals.

- 2026-07-10: current source-backed raw multiplex and H3 1 KiB c32 CPU
  sampling traces found no dominant project-owned scheduler, timer, send-queue,
  or crypto method. Runtime-shard inbox processing accounted for about 4.5 and
  4.6 percent inclusive time, synchronous UDP `Socket.SendTo` for about 1.8 and
  2.0 percent exclusive time, packet protection for less than 0.2 percent
  exclusive time, and async state-machine box creation for at most 0.22
  percent. Most samples were expected thread-pool waits, I/O completion waits,
  and monitor waits; metrics/counter startup also occupied about 6 percent of
  each short diagnostic trace. No scheduler or queue rewrite is justified by
  this evidence. The validated bundles, raw traces, and top-method reports are
  retained under `.artifacts/perf/cpu-attribution` and remain non-publishable
  local shared-host diagnostics.

- 2026-07-10: two trace-driven caching/allocation experiments were rejected and
  fully reverted. Replacing `Array.Sort`'s cached reference comparer with the
  generic span-sort struct comparer increased the existing per-sort allocation
  from 64 to 88 bytes and slowed the 8/128/512-entry rows from 195.8
  nanoseconds/4.470 microseconds/23.829 microseconds to 244.1
  nanoseconds/6.593 microseconds/40.242 microseconds. A dedicated byte-array
  pool through 64 KiB with 128 retained arrays per bucket increased the
  representative rent/return row from 47.63 to 59.77 nanoseconds. Its
  three-repetition raw multiplex comparison regressed median allocation rate
  about 2 percent, and matched traces increased sampled pool-miss bytes per
  request about 11 percent without materially reducing peak outstanding pool
  pressure. The existing comparer and `ArrayPool<byte>.Shared` remain the
  evidence-backed defaults. Negative-result records and benchmark/trace
  artifacts are retained under `.artifacts/perf/negative-results`,
  `.artifacts/bdn/send-queue-sort-comparer-*`, and
  `.artifacts/perf/dedicated-buffer-pool`.

- 2026-07-10: contiguous substantial STREAM receive chunks now reserve a 4 KiB
  pooled block and append later contiguous bytes into unused owned capacity.
  The policy starts at 1 KiB, leaves smaller control fragments and chunks of
  4 KiB or larger unchanged, and preserves exact logical lengths through
  partial reads, overlaps, and FIN processing. The Short four-contiguous-1-KiB
  benchmark improved from 1.111 microseconds and 2.75 KiB to 850.9 nanoseconds
  and 2.57 KiB. Opposite-order three-repetition raw multiplex comparisons
  passed validation and benchmark execution 6/6 on both sides. Median
  allocation-rate changes were -11.66 and -11.09 percent; median request-rate
  changes were +1.39 and +0.08 percent, and median p95 changes were -1.40 and
  -1.22 percent. A matched allocation trace reduced total sampled allocation
  from 20,698,776 to 19,049,288 bytes and receive-segment list allocation from
  3,726,576 to 2,018,344 bytes, about 45.8 percent. Sampled pool-rent bytes rose
  from 2,568,104 to 2,975,384 because fewer logical chunks use larger backing
  blocks; live combined `le_1kb` plus `le_4kb` peak pooled bytes were flat in
  one run order and 3.7 percent higher in the other. Opposite-order H3 1 KiB
  c32 comparisons passed 6/6 on both sides and kept normalized allocation per
  request effectively unchanged, while timing remained neutral-to-positive
  within shared-host variance. Focused stream tests passed 37/37 and the full
  suite passed 9,359 tests with 5 intentional skips. Evidence remains
  diagnostic because execution used a local shared host, dirty candidate
  source, and no linked publishability-readiness manifest. BDN, native
  comparisons, pool summaries, evidence bundles, and trace attribution are
  retained under `.artifacts/bdn/stream-receive-block-*` and
  `.artifacts/perf/stream-receive-block`.

- 2026-07-10: high-frequency datagram and byte totals now use two-slot
  client/server atomic accumulators exposed through `ObservableCounter<long>`.
  This preserves the four instrument names, units, and `role` tags while moving
  synchronous listener aggregation out of every receive/send call. The
  validated Short `QuicDatagramMetricsBenchmarks` comparison improved one
  received-plus-sent pair from 21.467 to 15.657 nanoseconds, about 27.1 percent,
  with no managed allocation in either run. Opposite-order three-repetition raw
  multiplex comparisons passed validation and benchmark execution 6/6 on both
  sides. Their median request-rate changes were +0.94 and +2.09 percent, median
  p95 changes were +0.09 and -4.19 percent, and median allocation-rate changes
  were -3.45 and -4.20 percent; treat timing as neutral-to-positive because one
  repetition regressed throughput by about 6 percent in both comparisons. A
  matched allocation trace held request rate within -0.19 percent and improved
  p95 about 1.8 percent. Sampled allocation fell from 23,237,984 to 21,363,696
  bytes; the baseline's 23 `RecordDatagramSent`/`RecordDatagramReceived`
  `ObjectSequence1` events and 2,442,576 estimated bytes disappeared from the
  candidate. Live counter output retained both role series and nonzero active
  server rates for all four metrics. Focused metric tests passed 4/4, and the
  full suite passed 9,358 tests with 5 intentional skips. Evidence remains
  diagnostic because execution used a local shared host, dirty candidate
  source, and no linked publishability-readiness manifest. BDN, native
  comparisons, counter output, evidence bundles, and trace attribution are
  retained under `.artifacts/bdn/datagram-metrics-*` and
  `.artifacts/perf/datagram-observable-metrics`.

- 2026-07-10: buffer-pool cumulative metrics now store per-size-bucket totals
  in atomic arrays and expose them through `ObservableCounter<long>` instead of
  constructing tags and dispatching seven synchronous counter updates on every
  rent/return. Instrument names, units, bucket tags, and the existing
  ProtocolLab summary contract are unchanged. The Short
  `QuicBufferPoolMetricsBenchmarks` result improved from 285.406 to 47.631
  nanoseconds per representative rent/return, with no managed allocation
  reported in either run. Two independent three-repetition raw multiplex
  comparisons, run in opposite candidate/baseline order, passed validation and
  benchmark execution 6/6 on both sides. Median request rate improved 14.14
  percent in both comparisons, median p95 latency improved 13.27 and 11.28
  percent, and median counter allocation rate improved 27.12 and 26.04 percent.
  A matched sampled-allocation trace reduced estimated allocation from
  34,708,184 to 22,919,136 bytes. The baseline attributed 106 events and
  11,265,776 bytes to `RecordBufferRent`, plus 36 events and 3,831,648 bytes to
  `RecordBufferReturn`; both groups disappeared from the candidate trace, with
  zero lost events. ProtocolLab emitted all nine buffer-pool metrics, all bucket
  groups, and no parse warnings. Focused metric tests passed 4/4. The full suite
  reached 9,357 passes and 5 intentional skips before one unrelated DoQ
  excessive-load lifecycle test observed an early connection termination; that
  test then passed 11 consecutive isolated reruns. Evidence remains diagnostic
  because the runs used a local shared host, dirty candidate source, and lacked
  a linked publishability-readiness manifest. BDN, native comparisons, evidence
  bundles, counter summaries, and trace attribution are retained under
  `.artifacts/bdn/buffer-pool-metrics-*` and
  `.artifacts/perf/buffer-pool-observable-metrics`.

- 2026-07-10: STREAM reassembly now rotates the populated merge scratch list
  into active segment storage instead of copying it through `AddRange`, then
  retains the previous active list as the next scratch buffer. When list-backed
  storage drains back to the two inline slots, the emptied list is retained and
  promoted on the next spill instead of allocating a replacement. The Short
  actual-state hole-fill benchmark reduced allocation from 5.52 KB to 4.43 KB
  per operation. A new repeated four-segment burst benchmark reduced allocation
  from 2.53 KB to 1.27 KB and mean time from 4.327 to 4.102 microseconds. In an
  isolated matched GC trace against correctness baseline `1285ff56`, requests
  were nearly identical at 1,602 versus 1,606 while combined
  `BufferedSegment[]` samples fell from 58 events and 6,188,072 estimated bytes
  to 35 events and 3,717,200 estimated bytes, about 39.9 percent. Both the
  `InsertReadableBytes` and `AddBufferedSegment` groups fell by roughly 40
  percent. A back-to-back three-repetition ProtocolLab comparison passed
  validation and benchmark execution 3/3 on both sides with no failed or
  timed-out requests; candidate medians improved request rate 3.34 percent, p95
  latency 1.99 percent, and allocation rate 18.63 percent. Counter-only
  exception deltas varied from a baseline 5/5/5 to candidate 7/6/5, while the
  traced baseline and candidate both reported five; retain that as a diagnostic
  caveat rather than an exception claim. The full suite passed 9,358 tests with
  5 intentional skips. Evidence remains diagnostic because the runs used a
  local shared host, dirty candidate source, and exceeded publishability
  variance/readiness gates. BDN, trace attribution, failed setup evidence,
  native comparisons, and completed run bundles are retained under
  `.artifacts/bdn/stream-*` and `.artifacts/perf/stream-list-reuse`.

- 2026-07-10: overlapping STREAM-frame reassembly now advances the merge
  cursor through an existing segment even when the incoming frame begins at
  exactly the same offset. The prior strict-offset check preserved payload
  ordering but could insert the already-buffered prefix again when one frame
  filled several later holes, inflating `BufferedReadableBytes` independently
  of the unique-byte range accounting. A focused regression seeds eight
  disjoint segments, fills every hole with one frame, verifies the exact
  first-arrival payload, and proves buffered-byte accounting returns to zero
  after the read. The actual-state `ReceiveInterleavedSegmentsThenFillHoles`
  benchmark records the previously uncovered workload; the correctness-only
  Short run measured 5.216 microseconds and 5.52 KB per operation. Baseline and
  corrected artifacts are retained under `.artifacts/bdn/stream-hole-fill-*`.

- 2026-07-10: listener and connected-endpoint receive loops now reuse the
  endpoint and two `SocketAddress` buffers consumed by the serial
  `ReceiveMessageFromAsync` path. The BCL previously serialized the supplied
  `IPEndPoint` into new address storage for every datagram and reconstructed a
  peer endpoint when needed. The reusable carrier preserves packet-information
  capture and updates its `IPEndPoint` state only for the first packet or an
  actual peer change. Real-socket tests cover repeated IPv4 receives, changing
  IPv4 peers, IPv6, and IPv4 over an IPv6 dual-mode socket. The Short
  `QuicReceiveEndPointBenchmarks` comparison reduced steady-state endpoint
  bookkeeping from 112 bytes and 48.89 nanoseconds per operation to zero bytes
  and 18.58 nanoseconds. In a matched raw multiplex GC trace, the prior
  receive-loop `SocketAddress`, backing-byte-array, and reconstructed
  `IPEndPoint` groups disappeared; project-attributed sampled allocation fell
  from 48,967,976 to 29,872,776 estimated bytes. The remaining receive-side
  `IPAddress` samples come from the packet-information object retained for
  local-path identity. A three-repetition native comparison passed validation
  and benchmark execution 3/3 with no failed or timed-out requests. Median
  allocation rate improved 45.74 percent and Gen0 collections fell from 3 to 1;
  median request rate improved 0.48 percent and p95 latency improved 1.32
  percent, which is neutral-to-positive timing evidence rather than a large
  throughput claim. The full suite passed 9,356 tests with 5 intentional skips.
  Evidence remains diagnostic because it is a dirty-source, local shared-host
  run and the evidence-quality gate still reports variance/readiness blockers.
  BDN, ProtocolLab, stack-attribution, and native-comparison artifacts are
  retained under `.artifacts/bdn/receive-endpoint-reuse-*` and
  `.artifacts/perf/receive-endpoint-reuse`.

- 2026-07-10: STREAM reassembly scratch now uses `List<T>.EnsureCapacity`
  instead of assigning the exact next capacity. Exact assignment defeated the
  list's geometric growth and caused repeated `BufferedSegment[]` allocation
  and copying as a stream accumulated segments. The Short side-by-side
  `QuicStreamBufferedSegmentBenchmarks` run reduced the current reusable-scratch
  row from 54.84 KB and 23.73 microseconds to 9.20 KB and 17.84 microseconds at
  64 segments, and from 11,825.52 KB and 4,628.46 microseconds to 96.37 KB and
  3,174.54 microseconds at 1,000 segments. The three-repetition raw multiplex
  candidate passed validation and benchmark execution 3/3 with no failed or
  timed-out requests; median throughput improved 7.03 percent, p95 regressed
  1.51 percent, and counter allocation rate regressed 4.40 percent against the
  preceding send-effect candidate while observed relative range remained 8.82
  percent. Treat those aggregate counter deltas as noisy rather than as an
  allocation win. A matched GC trace served 1.27 percent more requests while
  reducing `InsertReadableBytes` scratch-array samples from 56 to 45 and
  estimated bytes from 5,970,984 to 4,798,824, about 20.6 percent per request.
  Total buffered-segment array samples fell from 74 to 70 and estimated bytes
  from 7,884,184 to 7,460,816. The trace retained the same exception categories:
  two channel-close observations and five rather than three AEAD misses. The
  full suite passed 9,350 tests with 5 intentional skips. Evidence remains
  diagnostic because the candidate source was dirty, execution was local and
  shared-host, and variance exceeded the publishability threshold. BDN,
  ProtocolLab, native comparison, and stack-attribution artifacts are retained
  under `.artifacts/bdn/stream-scratch-geometric-*` and
  `.artifacts/perf/stream-scratch-geometric`.

- 2026-07-10: hosted runtime shards now carry high-volume application
  send-datagram effects as reusable value updates to the listener/client socket
  hosts. Direct runtime transitions still publish
  `QuicConnectionSendDatagramEffect` objects, and hosted transitions retain
  effect order through a singleton marker with a fail-closed marker/value match
  check. Corrected GC allocation trace
  `codex-raw-multiplex-send-effect-baseline-gc-bc1382f1-20260710a` attributed
  99 sampled events and 10,548,600 estimated bytes to send-datagram effect
  records. Candidate trace `codex-raw-multiplex-send-effect-candidate-gc-20260710a`
  contained no send-datagram effect group in its top 100; total allocation ticks
  fell from 624 to 491, estimated bytes from 66,673,840 to 52,335,360, and
  actionable estimated bytes from 59,268,592 to 44,958,272. Both trace runs
  passed validation and benchmark execution with zero failed or timed-out
  requests. The matched three-repetition native comparison retained throughput
  at -0.76 percent while improving p95 latency 7.53 percent. Counter aggregates
  reduced median allocation rate 35.25 percent, Gen0 collections from 5 to 3,
  and exception rate 16.67 percent. ProtocolLab commit `5772635` now compares
  retained counter allocation summaries and available exception top groups
  directly; the repaired native output reports all three allocation-rate deltas
  and keeps non-traced exception groups explicitly unavailable. The full suite
  passed 9,350 tests with 5
  intentional skips. Evidence remains diagnostic because it is local shared-host
  data, candidate source was dirty, variance exceeded the publishability gate,
  and no readiness manifest was linked. Bundles, stack attribution, and native
  comparison output are retained under
  `.artifacts/perf/raw-multiplex-send-effect`.

- 2026-07-10: pooled stream-open and datagram completion sources now use an
  interlocked completion guard instead of allocating a closure and `Action` for
  every `TrySetResult` or `TrySetException` call. The stream-open allocation
  trace had identified both objects in the successful public stream-open path.
  A matched 400-iteration established-stream profile reduced pass-two managed
  allocation from 7,000 to 6,949 B/op, while the stream-open await phase fell
  from 1,041 to 935 B/op. A 2,000-iteration confirmation measured 6,932 B/op in
  pass two. The Short public comparison completed both stream suites; the
  established Incursa request/response row measured 9,832 B/op and the small
  queued-write row measured 1,585 B/op. Focused completion, cancellation,
  concurrency, and datagram tests passed 714/714, and the full suite passed
  9,350 tests with 5 intentional skips. Local diagnostic artifacts are retained
  under `.artifacts/perf/public-stream-profile/codex-profile-stream-interlocked-completion-20260710a.json`,
  `.artifacts/perf/public-stream-profile/codex-profile-stream-interlocked-completion-2000-20260710a.json`,
  and `.artifacts/bdn/public-comparison/codex-interlocked-completion-20260710a`.

- 2026-07-10: production listener and client runtime shards now carry timer
  deadline changes as reusable value updates directly into the shard scheduler,
  while direct runtime callers retain the existing arm/cancel effect-object
  contract. Source-backed raw multiplex trace
  `codex-raw-multiplex-hosted-timer-values-20260710a` passed 1,588/1,588
  requests. Its stack attribution contained zero arm/cancel timer-effect groups;
  the matched baseline had 156 sampled events across four groups and 16,633,192
  estimated bytes. Three-repetition comparison
  `hosted-timer-values-confidence-20260710a` improved median throughput 6.23
  percent, p95 latency 4.68 percent, allocation rate 26.78 percent, and Gen0
  collections from 7 to 5. The counter-only candidate cells recorded six
  exceptions instead of the baseline's five, while the traced candidate retained
  the same three AEAD authentication failures and two channel-close exceptions
  as the traced baseline; treat that discrepancy as an unresolved diagnostic
  caveat rather than a proven regression or improvement. Release build and the
  full suite passed with 9,350 tests and 5 intentional skips. Evidence remains
  diagnostic because the candidate source tree was dirty, local shared-host
  variance exceeded the publishability threshold, and no readiness manifest was
  linked. Retained bundles and comparison artifacts are under
  `.artifacts/perf/raw-multiplex-attribution/codex-raw-multiplex-hosted-timer-values-20260710a`,
  `.artifacts/perf/raw-multiplex-attribution/codex-raw-multiplex-hosted-timer-values-confidence-20260710a`,
  and `.artifacts/perf-triage/hosted-timer-values-confidence-20260710a`.
  Clean post-commit run
  `codex-raw-multiplex-hosted-timer-values-clean-62064510-20260710a`
  retained the improvement at commit `62064510`: median throughput improved
  5.56 percent, p95 latency 6.06 percent, allocation rate 27.04 percent, and
  Gen0 collections from 7 to 5, with exception rate unchanged. That bundle
  remains diagnostic because relative range reached 30.07 percent, readiness
  was not linked, and ProtocolLab source-status capture still reported
  `working-tree-not-clean` even though the QUIC worktree was clean. Its buffer
  pool summary was unavailable because the expected counter signals were
  missing. Native comparison and triage artifacts are retained under
  `.artifacts/perf-triage/hosted-timer-values-clean-62064510-20260710a`.

- 2026-07-10: STREAM receive buffering now keeps the first two unread segments
  inline in each stream state before spilling to `List<BufferedSegment>`. The
  existing one-slot shape allocated a list and backing array as soon as a second
  contiguous frame arrived. The focused two-frame BenchmarkDotNet row reduced
  managed allocation from 2.66 KB to 2.57 KB per operation (about 96 bytes); its
  short-run timing was inconclusive. Three-repetition source-backed raw multiplex
  comparison `inline2-buffer-confidence-20260710a` matched all three cells and
  kept median throughput effectively flat at -0.37 percent while improving p95
  latency 6.39 percent, counter allocation rate 4.66 percent, and Gen0 collections
  from 7 to 6. Both evidence bundles remain diagnostic: candidate request-rate
  relative range was 9.3 percent, source was a dirty worktree, and publishability
  readiness was not linked. Retained native comparison and triage artifacts are
  under `.artifacts/perf-triage/inline2-buffer-confidence-20260710a`. A clean
  post-commit run at `a94acfb2`,
  `codex-raw-multiplex-inline2-clean-a94acfb2-20260710a`, improved median
  throughput 2.28 percent, p95 latency 5.87 percent, and allocation rate 4.42
  percent against the matched baseline while leaving exception rate unchanged.
  That comparison remains diagnostic because relative range reached 11.47
  percent, publishability readiness was not linked, and ProtocolLab's source
  status capture still emitted `working-tree-not-clean` even though the QUIC
  worktree was clean. Retained native artifacts are under
  `.artifacts/perf-triage/inline2-buffer-clean-a94acfb2-20260710a`.

- 2026-07-10: source-backed raw QUIC multiplex attribution reopened terminal
  exception cleanup for observer-style inbound accepts. Baseline trace
  `codex-raw-multiplex-attribution-a6affe27-20260710a` passed 1,494/1,494
  requests but captured three BCL AEAD authentication-tag failures and two
  `ChannelClosedException` throws from `TryAcceptInboundStreamSlowAsync`. A
  `WaitToReadAsync` plus `TryRead` candidate removed the channel-close throws in
  matched trace `codex-raw-multiplex-accept-no-channelclosed-20260710a`, which
  passed 1,397/1,397 requests. The candidate was rejected: the old implementation
  passed `Http3MinimalServerTests` 62/62, while repeated candidate runs produced
  varying peer-close timeout failures when multiple observer accepts were active.
  Negative-result evidence is retained at
  `.artifacts/perf/negative-results/inbound-accept-wait-to-read-20260710.json`;
  exception reduction alone was not a sufficient correctness result. The
  remaining AEAD failures pass through .NET decrypt APIs whose
  authentication-failure contract throws; removing them requires avoiding
  speculative decrypt attempts or changing the crypto boundary.

- 2026-07-10: current package-backed raw QUIC multiplex evidence now runs
  through the upgraded ProtocolLab bundle and comparison surfaces. Controller
  job `job-2fd1f052b29b48468e7213b7ca5b925b` used clean runtime commit
  `727300a2`, passed validation and benchmark execution for all 3 repetitions,
  and reported zero failed or timeout requests. The aggregate median was 97.10
  requests/sec, 6.36 MB/sec, p50 8.059 ms, and p95 19.527 ms. Evidence remains
  diagnostic: p50 relative range reached 8.24 percent against the 5 percent
  publishability threshold, no publishability-readiness manifest was linked,
  and allocation/exception attribution explicitly reports
  `trace-capture-disabled`. Native comparison against the prior single-repeat
  package run is retained under
  `.artifacts/perf-parity/codex-package-multiplex-727300a2-20260710a`.
  Follow-up commits `6413f500` and `d522b972` make both QUIC package builders
  capture the exact repository URL and full source commit in
  `protocol-lab.internal.json`, because the public v2 package schema correctly
  rejects internal source fields. Package
  `quic-dotnet-raw-dev.dev-20260710T062127Z-d522b972-clean` passed live
  controller admission, and package-reference-only smoke job
  `job-368ec5dbc9db41579c367f249778a479` passed validation and benchmark
  execution with zero failed or timeout requests. Its retained evidence is at
  `.artifacts/perf-parity/codex-package-multiplex-provenance-d522b972-20260710a`.

- 2026-07-10: pending public inbound stream accepts now map the channel's
  existing `ValueTask<ulong>` through a dedicated pooled
  `IValueTaskSource<QuicStream>` instead of allocating an
  `AcceptInboundStreamSlowAsync` state-machine box for every accepted stream.
  Public cancellation and terminal exception behavior remains covered by the
  existing API tests, while debug receive logging retains the readable async
  path. The 5,000-iteration established-connection profile reduced pass-two
  managed allocation from 7,650 to 7,582 B/op and held elapsed time at 0.330
  versus 0.332 ms/op. Matched 40,000-transfer GC traces reduced pass-two managed
  allocation from 7,675 to 7,617 B/op, removed the prior 154-event sampled
  `AcceptInboundStreamSlowAsync` group, and reduced sampled actionable bytes
  from 278,030,984 to 275,709,480. Evidence is retained under
  `.artifacts/perf/public-stream-allocation-trace/codex-established-stream-pooled-accept-20260710a`.

- 2026-07-10: sustained established-connection profiling exposed a torn
  cross-thread read of the large nullable active-path record in the public
  outbound stream-open readiness check. A focused concurrency regression test
  reproduced the contradictory `Phase=Active` / active-path rejection in 45 ms.
  Commit `f861b8a7` now uses the connection phase as the published application
  readiness invariant, matching neighboring public APIs; focused tests passed
  and the previously failing 40,000-transfer profile completed. A follow-up
  single-entry path-identity cache was rejected after changing allocation only
  from 7,650 to 7,646 B/op while elapsed time regressed from 0.332 to 0.370
  ms/op. ProtocolLab negative-result evidence is retained at
  `.artifacts/perf/negative-results/path-identity-cache-20260709.json`.

- 2026-07-09: public socket-host shutdown no longer relies on receive cancellation
  throwing through the listener and client endpoint loops. Both hosts register a
  cancellation wake-up that sends a one-byte datagram to their own bound socket,
  observe cancellation before classifying the datagram, and dispose the socket
  after the receive loop exits. Windows UDP sockets also disable
  `SIO_UDP_CONNRESET` reporting so peer `PORT_UNREACHABLE` messages do not become
  first-chance `SocketException` traffic on the shared listener. Focused socket,
  cancellation, listener, and concurrent-stream tests passed 34/34. Before the
  change, trace `concurrent-public-stream-exceptions-20260709d` captured 589
  exceptions across five groups and BDN reported `Exceptions: 2`; the intermediate
  wake-up-only trace `concurrent-public-stream-exceptions-20260709e` reduced that
  to 172 Windows UDP reset exceptions and `0.53125` exceptions/op. Final narrowed
  trace `concurrent-public-stream-exceptions-20260709g` captured 43,932 events with zero
  lost events and zero exceptions/groups, and dry BDN smoke
  `public-comparison-concurrent-icmp-smoke-20260709a` completed both implementations
  without an exception diagnostic row. The full test project passed 9,344 tests
  with five skips and reproduced two unrelated guard failures: the existing lock
  inventory omits `scheduledFlowControlCreditGate`, and the private-reflection
  quarantine omits existing use in `REQ-QUIC-API-0010.cs`. These remain local
  diagnostic measurements, but they close the identified public-stream teardown
  exception pressure.

- 2026-07-09: public API stream-transfer benchmarks now include an established-connection
  concurrent request/response stream shape, opening eight bidirectional streams
  over one loopback connection for both Incursa.Quic and `System.Net.Quic`.
  Focused correctness coverage `QuicPublicApiStreamConcurrencyTests` proves the
  supported Incursa loopback path can complete the same eight concurrent
  transfers. Dry BDN smoke `public-comparison-concurrent-smoke-20260709a`
  completed both implementations: Incursa measured 370.811 ms / 1,592.9 KB with
  BDN reporting `Exceptions: 2`, while `System.Net.Quic` measured 66.641 ms /
  197.55 KB. Treat this as a stable diagnostic lane and follow-up signal for
  public-stream concurrency pressure, not as a solved performance win.

- 2026-07-09: `Compare-QuicProtocolLabRuns.ps1` now preserves ProtocolLab
  native evidence-bundle comparison artifacts when both retained run roots have
  `evidence-bundle.json`. The local triage report still compares aggregate rows
  and highlights QUIC-side diagnostics, while the new
  `protocol-lab-native-comparison.json` and `.md` outputs carry ProtocolLab's
  current evidence-quality, validation/warning, source/package parity, and
  metric-delta interpretation. Smoke proof
  `codex-native-compare-wrapper-smoke-20260709a` matched one retained raw QUIC
  row and emitted both native artifacts.

- 2026-07-09: raw QUIC upload-only stream throughput now avoids artificial STOP_SENDING churn in the ProtocolLab raw load tool. `quic-go-raw-load` now reads the response side to EOF for `client-to-server` bidirectional streams and verifies zero response bytes instead of immediately canceling reads, and `IncursaRawQuicServer` now gracefully completes the write side for non-echo upload-only streams while only retaining completed echo streams for tail retransmission. Go package proof `go test ./cmd/quic-go-raw-load` passed. Source-backed c1/s4 `quic.transport.stream-throughput.1mb` single-repetition proof `codex-raw-stream-c1s4-clean-fin-summary-20260709a` passed validation and benchmark with 504/504 successful requests, 0 failed/timeouts, 33.53 req/s, 35.16 MB/s, and p95 145.02 ms. Counter-captured single-repetition proof `codex-raw-stream-c1s4-clean-fin-counter-summary-20260709a` also passed with 476/476 successful requests, 0 failed/timeouts, 31.62 req/s, 33.16 MB/s, and p95 154.88 ms. The repeated 9-repetition local c1/s4 counter run `codex-raw-stream-c1s4-clean-fin-confidence-20260709a` still had intermittent final-batch timeout/deadline failures on the shared host, so it was preserved as a ProtocolLab negative-result record rather than treated as a runtime optimization candidate.

- 2026-07-09: observer-only stream drains now treat peer stream abort as an expected terminal state. `QuicStream.TryReadTerminalAsync` suppresses `QuicError.StreamAborted` the same way it already suppresses expected connection/disposal terminal states, so HTTP/3 peer-stream observer cleanup can end quietly when a peer resets a stream. Focused lifecycle tests prove public reads still preserve stream-abort exceptions while terminal observer drains return end-of-stream, and disposal releases a pending read without hanging. Focused stream/runtime/HTTP/3 guard tests passed 56/56. Source-backed exception-attribution smoke `codex-h3-terminal-stream-abort-suppression-20260709a` passed validation and benchmark for `http3.payload.bytes.64kb` at c4-s4 and reported 0 exceptions / 0 groups.

- 2026-07-09: current 1KB HTTP/3 allocation scout `codex-h3-1kb-current-allocation-scout-20260709a` passed source-backed ProtocolLab counters and GC trace for `http3.payload.bytes.1kb` at c4-s4 for 3 seconds plus 1 second warmup. The diagnostic counter row measured 3,967.33 req/s, p95 6.29 ms, allocation rate 6,212,944 B/s, 1,566.03 B/request, and zero failed/timeout requests. Allocation attribution over the GC trace found 5 sampled allocation ticks across 4 groups, 549,424 estimated bytes, 0 project-attributed bytes, and 0 actionable bytes; all sampled groups were runtime/EventPipe metadata rows. Together with the current 64KB scout, the latest short traces do not justify another HTTP/3 allocation code change without a new actionable Incursa-attributed group.

- 2026-07-09: HTTP/3 client peer unidirectional stream observation now uses terminal-safe internal QUIC paths. `Http3Client` switched observer accept from public `AcceptInboundStreamAsync` to internal `TryAcceptInboundStreamAsync`, and observer-only peer stream drains now use `TryReadTerminalAsync`, matching the server observer cleanup shape. `QuicConnectionRuntime.TryAcceptInboundStreamSlowAsync` now waits with `WaitToReadAsync` plus `TryRead` so expected channel close can return `null` without first throwing `ChannelClosedException`. `Incursa.Quic.Http3` Release build passed; focused accept-cancellation, ProtocolLab source-guard, and HTTP/3 minimal-client tests passed 30/30. Source-backed exception-attribution smoke `codex-h3-client-terminal-observer-exceptions-20260709b` passed validation and benchmark for `http3.payload.bytes.64kb` at c4-s4 and reported 0 exceptions / 0 groups, improving the immediately preceding dirty-run smoke `codex-h3-client-terminal-observer-exceptions-20260709a` that still had one project-attributed `ChannelClosedException`.

- 2026-07-09: current 64KB HTTP/3 allocation smoke `codex-h3-64kb-current-allocation-smoke-20260709a` passed source-backed ProtocolLab counters and GC trace for `http3.payload.bytes.64kb` at c4-s4 for 3 seconds plus 1 second warmup. The diagnostic row measured 249.33 req/s, p95 121.33 ms, allocation rate 5,054,661.33 B/s, 20,272.71 B/request, and zero failed/timeout requests. The retained buffer-pool summary was available with 231 samples and captured requested-size counters: `incursa.quic.buffer_pool.requested_rents` total 255,077 and `incursa.quic.buffer_pool.bytes.requested` total 317,746,730. Allocation attribution over the GC trace found 6 sampled allocation groups, 638,944 estimated bytes, 0 project-attributed bytes, and 0 actionable bytes; all groups were runtime/EventPipe metadata startup rows. This is useful 64KB evidence for item 5, but it explicitly does not justify a runtime code change by itself.

- 2026-07-09: source-backed counters-only H3 smoke `codex-h3-buffer-pool-requested-metrics-smoke-20260709a` proved the requested-size buffer-pool metrics flow through ProtocolLab and the local H3 profile summary. The run used `http3.payload.bytes.1kb` at c4-s4 for 3 seconds plus 1 second warmup, passed the counter pass, emitted available `quic-buffer-pool-summary.json` with 224 samples, and captured both `incursa.quic.buffer_pool.requested_rents` and `incursa.quic.buffer_pool.bytes.requested`. This remains diagnostic smoke evidence only, but it closes the wiring risk for requested-size pool pressure before tuning defaults.

- 2026-07-09: `Summarize-IncursaH3ProfilePack.ps1` now surfaces the retained ProtocolLab `quic-buffer-pool-summary.json` artifact directly in `summary.md`, including availability/unavailable reasons, overall pool counters, per-bucket actual rent/return/oversized/outstanding totals, and requested-size rows when future captures include them. This makes buffer-pool evidence discoverable from the local H3 profile pack summary instead of requiring manual artifact spelunking.

- 2026-07-09: `QuicBufferPool` metrics now distinguish requested minimum buffer size from actual `ArrayPool<byte>` rent size. The metrics surface adds `incursa.quic.buffer_pool.requested_rents` and `incursa.quic.buffer_pool.bytes.requested` with bounded `requested_size_bucket` tags, while existing actual-size counters keep `size_bucket`. This gives ProtocolLab counter captures a direct way to tell true large buffer requests from normal pool over-return before changing default pool sizes. Treat this as buffer-pool diagnostic hardening, not a runtime throughput claim.

- 2026-07-09: `Invoke-QuicPerformanceLane.ps1` now accepts `-BaselineAggregatePath` and emits a `performanceGate` block in `lane-summary.json` plus the Markdown summary. The gate compares matching current ProtocolLab aggregate cells against a retained baseline, flags `extreme-metric-regression` when the primary throughput/request-rate metric drops by at least 50 percent or p95 latency rises by at least 100 percent, and keeps confidence lanes report-only unless `-FailOnPerformanceGate` is supplied. This closes the local threshold-rule source-control piece without pretending local noisy lanes are publishable evidence.

- 2026-07-09: `New-QuicPerformanceCloseout.ps1` records performance-slice closeout evidence under `.artifacts/perf-closeout/{runId}` with separate correctness and performance sections: requirement/spec artifacts, focused test commands, requirement-home test commands, full-suite commands, SpecTrace validation/backlog notes, ProtocolLab artifacts, local performance artifacts, git status, changed files, and artifact hashes where available. This gives future runtime optimization commits a repeatable traceability ledger without conflating correctness proof with benchmark evidence.

- 2026-07-09: `Compare-QuicProtocolLabRuns.ps1` now reads `evidence-bundle.json` next to retained ProtocolLab run roots when present and carries evidence quality, publishability blockers, qlog status, buffer-pool diagnostics, allocation/exception attribution status, hotspot trend counts, and top diagnostic groups into the local triage JSON and Markdown. Smoke proof `codex-evidence-bundle-triage-smoke-20260709a` exercised a current bundle-backed run, and `codex-no-bundle-triage-smoke-20260709a` verified older aggregate-only retained runs still report cleanly with an explicit missing-bundle note. This makes the QUIC-side triage command a better selector for the next runtime optimization without treating diagnostic or local evidence as publishable.

- 2026-07-09: `PublicApiStream` smoke lane `codex-public-stream-typed-workitems-20260709a` passed on clean commit `a31ee359` after the hosted stream-open/write typed work-item changes. The steady-state established-connection dry rows now measure Incursa request/response at 9.749 ms and 15.36 KB versus `System.Net.Quic` at 4.296 ms and 10.92 KB, and Incursa small queued-write at 10.196 ms and 6.67 KB versus `System.Net.Quic` at 2.401 ms and 5.79 KB. This materially improves the previous steady-state smoke row of 25.72 KB and 11.17 KB for Incursa, but full transfer/dispose dry rows remain setup/lifecycle dominated at roughly 1.48-1.56 MB for Incursa versus 151-194 KB for `System.Net.Quic`. Treat this as diagnostic smoke evidence only because the BDN job is Dry/single-iteration.

- 2026-07-09: hosted stream write and finish-write requests now use a typed shard work item, avoiding `QuicConnectionStreamActionEvent` allocation for the normal hosted public write/complete-write paths while preserving direct runtime event fallback for tests and local-dispatch instrumentation. `Incursa.Quic` Release build passed; focused write/complete/open/runtime-host/runtime-shard/public-stream/HTTP/3 tests passed 98/99 with the known 1 MB HTTP/3 body skip. Phase profile `codex-profile-stream-phases-streamwrite-workitem-20260709a.json` reduced start-side write buckets versus `codex-profile-stream-phases-streamopen-workitem-20260709a.json`: `client-write-start` 369 to 269 B/op, `client-complete-writes-start` 264 to 175 B/op, `server-write-start` 234 to 139 B/op, and `server-complete-writes-start` 245 to 146 B/op. Aggregate profile `codex-profile-stream-streamwrite-workitem-20260709a.json` measured pass-2 managed allocation at 7,849 B/op, down from 8,222 B/op in `codex-profile-stream-streamopen-workitem-20260709a.json`. Treat this as local diagnostic public-stream allocation evidence, not publishable throughput proof.

- 2026-07-09: hosted outbound stream opens now use a typed shard work item, avoiding the `QuicConnectionStreamActionEvent` allocation on the normal hosted public `OpenOutboundStreamAsync` path while preserving the explicit event fallback for direct runtime tests and later local-dispatch instrumentation. `Incursa.Quic` Release build passed; focused stream-open/runtime-host/runtime-shard/public-stream/HTTP/3 tests passed 89/90 with the known 1 MB HTTP/3 body skip. Phase profile `codex-profile-stream-phases-streamopen-workitem-20260709a.json` reduced `open-client-stream-start` from 262 to 167 B/op versus `codex-profile-stream-phases-flowcontrol-workitem-20260709a.json`; aggregate profile `codex-profile-stream-streamopen-workitem-20260709a.json` measured pass-2 managed allocation at 8,222 B/op, down from 8,255 B/op in `codex-profile-stream-flowcontrol-workitem-20260709a.json`. Treat this as a small local diagnostic public-stream allocation cleanup, not publishable throughput proof.

- 2026-07-09: hosted flow-control credit update scheduling now uses the same typed shard work-item fast path as stream-capacity release, avoiding a `QuicConnectionFlowControlCreditUpdatedEvent` allocation for hosted public stream reads while preserving the explicit event path for direct runtime tests. `Incursa.Quic` Release build passed; focused flow-control/stream-capacity/runtime-host/public-stream/HTTP/3 tests passed 102/103 with the known 1 MB HTTP/3 body skip. Phase profile `codex-profile-stream-phases-flowcontrol-workitem-20260709a.json` reduced `server-read-request` from 600 to 519 B/op and `client-read-response` from 634 to 591 B/op versus the capacity-work-item profile, while keeping EOF buckets in the same range. Aggregate profile `codex-profile-stream-flowcontrol-workitem-20260709a.json` measured pass-2 managed allocation at 8,255 B/op, down from 8,490 B/op in `codex-profile-stream-capacity-workitem-20260709a.json`. Treat this as local diagnostic public-stream allocation evidence, not publishable throughput proof.

- 2026-07-09: hosted stream-capacity release scheduling now uses a typed shard work item instead of allocating a `QuicConnectionStreamActionEvent` for the common public stream EOF/read-completion path. Direct runtime paths and tests still retain the existing event fallback. `Incursa.Quic` Release build passed; focused stream-capacity/runtime-host/public-stream/HTTP/3 tests passed 100/101 with the known 1 MB HTTP/3 body skip. The 400-iteration phase profile `codex-profile-stream-phases-capacity-workitem-20260709a.json` reduced `client-eof` from 985 to 873 B/op and `server-eof` from 787 to 693 B/op versus `codex-profile-stream-phases-baseline-rerun-20260709b.json`; aggregate profile `codex-profile-stream-capacity-workitem-20260709a.json` measured pass-2 managed allocation at 8,490 B/op versus 8,864 B/op in `codex-profile-stream-writefinal-wrapper-20260709a.json`. Treat this as local diagnostic public-stream allocation evidence, not publishable throughput proof.

- 2026-07-09: internal `QuicStream.WriteFinalAsync` now follows the same non-async fast-path shape as the public write and complete-write paths, only allocating an async state machine when the write gate or runtime final write actually waits. This is a supporting cleanup for final-write callers rather than the current public-stream benchmark bottleneck, because HTTP/3 response fast paths primarily use `TryWriteFinalAsync`. `Incursa.Quic` Release build passed; focused final-write/complete-write/HTTP/3 stream tests passed 73/74 with the known 1 MB HTTP/3 body skip. The 400-iteration Incursa-only public stream profile `codex-profile-stream-writefinal-wrapper-20260709a.json` measured pass-2 allocation at 8,864 B/op, effectively flat against the prior 8,842 B/op profile and retained as no-regression evidence rather than a performance win.

- 2026-07-09: public stream writes and complete-writes now avoid the extra async wrapper that converted the runtime's pooled `ValueTask<bool>` stream-action completion into a non-generic `ValueTask`. `StreamActionRequestCompletionSource` exposes a direct non-generic `ValueTask` for the public non-try paths while the boolean `Try*` paths stay unchanged. `Incursa.Quic` Release build passed; focused write/complete stream tests passed 93/93; broader stream/HTTP/3 public flow tests passed 142/143 with the known 1 MB HTTP/3 body skip. The 400-iteration Incursa-only public stream profile `codex-profile-stream-void-action-completion-20260709a.json` measured pass-2 allocation at 8,842 B/op versus 9,241 B/op in `codex-profile-stream-writecore-wrapper-20260709a.json`. Phase profile `codex-profile-stream-phases-void-action-completion-20260709a.json` showed start-side write/complete buckets moving down while EOF/read await buckets remain the next likely target.

- 2026-07-09: added `--profile-stream-phases` to the allocation harness so the established Incursa public stream request/response profile can be broken into open/write/complete/read/EOF/dispose phase buckets, with open/write/complete split into API-start versus await-completion. The 400-iteration diagnostic artifact `codex-profile-stream-phases-split-20260709a.json` showed the largest remaining buckets at `open-client-stream-await` 1,150 B/op, `client-eof` 997 B/op, `server-eof` 799 B/op, `client-complete-writes-await` 709 B/op, `client-read-response` 622 B/op, `server-complete-writes-await` 592 B/op, `server-read-request` 592 B/op, `client-write-await` 575 B/op, and `server-write-await` 508 B/op; start-side costs were smaller, with `client-write-start` 504 B/op and other start buckets below 400 B/op. A candidate `ReadCoreAsync` wrapper split was tried and reverted after two 400-iteration profiles measured 9,322 and 9,348 B/op versus the prior committed 9,240 B/op; the non-committed experiment is recorded under `.artifacts/negative-results/codex-profile-stream-readcore-wrapper-20260709-negative-result.json`.

- 2026-07-09: buffer-pool tuning smoke `codex-buffer-pool-tuning-smoke-20260709a-h3-local-v1` used the new ProtocolLab `quic-buffer-pool-summary.json` evidence path on `http3.payload.bytes.1kb` at c4-s4 with counter capture. Validation and benchmark passed, evidence remained diagnostic, and the pool summary reported zero outstanding buffers/bytes at sample time. The high `oversized_rents` count was concentrated in `le_1kb` and `le_4kb` buckets and reflects `ArrayPool<byte>` returning larger arrays than requested minimums, not retained memory or large requested buffers. No runtime pool-size change is justified from this smoke alone; the next useful pool work is richer requested-size distribution or repeated traces before tuning defaults.

- 2026-07-09: committed public stream open/write allocation cleanups were rechecked through the `PublicApiStream` smoke lane `codex-public-stream-runtime-cleanups-20260709a`, which passed both `QuicPublicApiStreamTransferBenchmarks` and `QuicPublicApiSteadyStateStreamBenchmarks` Dry slices. The steady-state request/response row measured Incursa at 11.591 ms and 25.72 KB versus `System.Net.Quic` at 4.017 ms and 11.25 KB; the small queued-write row measured Incursa at 5.925 ms and 11.17 KB versus `System.Net.Quic` at 1.993 ms and 6.12 KB. Treat this as benchmark smoke and direction-setting evidence only; Dry rows are single-iteration and the full transfer/dispose rows remain cold-start dominated.

- 2026-07-09: public `QuicStream.WriteAsync(ReadOnlyMemory<byte>, CancellationToken)` now routes through a non-async `WriteCoreAsync` wrapper and only allocates an async continuation when the write gate or runtime write actually waits. `Incursa.Quic` Release build passed, focused write/read/open lifecycle tests passed 131/134 with three existing skips, and 400-iteration Incursa-only public stream profile `codex-profile-stream-writecore-wrapper-20260709a.json` measured pass-2 allocation at 9,241 B/op versus 9,361 B/op after the stream-open completion-source cleanup. Treat this as a small public stream allocation cleanup; elapsed time remained local/noisy and did not improve in this sample.

- 2026-07-09: public outbound stream opens now return the pooled stream-open completion source as a `ValueTask<QuicStream>` directly instead of forcing `QuicConnectionRuntime.OpenOutboundStreamAsync` through an async wrapper that awaited a stream ID and then constructed the public facade. The pooled source now owns cancellation registration disposal and materializes the `QuicStream` in `GetResult`, preserving blocked-open, cancellation, and terminal-state behavior. `Incursa.Quic` Release build passed, focused stream/open lifecycle tests passed 86/86, focused HTTP/3 public stream tests passed 74/75 with the existing 1 MB body skip, and 400-iteration Incursa-only public stream profile `codex-profile-stream-open-completion-direct-20260709a.json` measured pass-2 allocation at 9,361 B/op versus 12,545 B/op in the immediately preceding scratch-reuse profile. Treat this as local diagnostic allocation evidence for the public stream facade, not a publishable throughput claim.

- 2026-07-09: `Http3Server.WriteResponseAsync` now uses a non-async wrapper for common complete fixed-response and headers-only response writes, preserving the existing async path only for streaming or multi-write responses. `Incursa.Quic.Http3` Release build passed, the focused HTTP/3/QPACK/RFC 9114/RFC 9204 test filter passed 1160/1161 with the known 1 MB body skip, and source-backed H3 proof `codex-h3-1kb-response-fastpath-wrapper-current-h3-local-v1` passed ProtocolLab validation and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests. GC trace analysis `codex-h3-1kb-response-write-wrapper-fastpath-allocations-20260709a` sampled five runtime-only allocation groups, zero project-attributed/actionable groups, and no `Http3Server.WriteResponseAsync` allocation row. Treat this as targeted allocation-stack cleanup; the proof remains diagnostic and non-publishable because it is a single local run.

- 2026-07-09: baseline reporting now auto-discovers repo-local controller aggregate wrappers from `artifacts/protocol-lab/results` when no explicit `-AggregateResultPath` is supplied, with `-SkipRepoAggregateResults` available for exact retained-run-only rollups. Smoke report `codex-baseline-auto-repo-aggregates-20260709a` scanned 188 run roots plus 5 aggregate wrapper files, matched 177 rows, and surfaced clean package-backed `quic-dotnet-raw-dev` rows for `quic.transport.stream-throughput.1mb`, `quic.transport.multiplex.100x64kb`, and `quic.transport.duplex-streams`; each package-backed row had validation 3/3 and benchmark succeeded 3/3 while still retaining variance/local-environment blockers. Opt-out smoke report `codex-baseline-skip-repo-aggregates-20260709a` scanned 0 aggregate wrapper files. This does not replace or hide older `incursa-raw-quic-adapter-v1` local rows; it makes the cleaner package-backed evidence visible in default-style local baseline reports.

- 2026-07-09: inspected controller publication dry-run output `codex-package-backed-raw-publication-dryrun-20260709c` for the three current package-backed raw confidence jobs. Jobs `job-bcb049b36892490ca2949dcb6d8dcc00`, `job-c1f45316b0ef4d3d85e179c794682c0c`, and `job-875a89f8926e45b6b93cf7ce806434f4` all recorded `dry-run-succeeded`, exit code 0, no stderr, and 10 would-be public objects each: `artifacts-index.json`, package provenance, run-plan provenance, JSON/Markdown evidence report, publication manifest, skipped/warnings docs, report index entry, and report index. This closes dry-run bundle inspection for these confidence jobs only; real upload/import remains intentionally gated by controller secrets, public dashboard target verification, and the existing variance/provenance blockers.

- 2026-07-09: submitted fresh package-backed raw stream-throughput parity job `job-a2cedd4d2e44416e991c2f1b489abf32` on `plab-worker-sut-01` so the run would include the new `evidence-bundle.json` format. The job completed with validation passed, benchmark succeeded, attribution artifacts emitted, and local copies under `.artifacts/perf-parity/codex-source-package-raw-stream-20260709a/package`. Native ProtocolLab compare output `.artifacts/perf-parity/codex-source-package-raw-stream-20260709a/run-comparison.{json,md}` matched 0 cells because existing source-backed raw runs use implementation ID `incursa-raw-quic-adapter-v1`, while package-backed raw runs use `quic-dotnet-raw-dev`. Treat this as a real source/package parity blocker: either the local source lane needs a `quic-dotnet-raw-dev` implementation identity, or readiness policy needs an explicit reviewed mapping between the old source adapter ID and the package target. Do not claim source/package parity from the current comparison.

- 2026-07-09: `QuicConnectionSendRuntime` now starts its sent-packet dictionary at 64 entries instead of 16 so normal HTTP/3 request bursts do not immediately resize packet tracking during send-path hot work. `Incursa.Quic` Release build passed; a broad send/recovery/ACK-filtered test run hit one unrelated HTTP/3 QPACK close-path flake, and the exact failed test reran cleanly. Source-mode H3 profile pack `codex-h3-1kb-sent-packet-capacity64-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with validation 1/1, benchmark 1/1, zero failed/timeout requests, counters captured, 5,857 req/s, p95 55.864 ms, allocation-rate median 10,285,578 B/sec, and exception-rate median 42.667/sec. Evidence quality remains diagnostic and non-publishable because this was a single local repetition with missing variance, shared-host/load-generator warnings, and no linked publishability readiness manifest. Allocation attribution `codex-h3-1kb-sent-packet-capacity64-source-allocations-20260709a` no longer shows the prior sampled `QuicConnectionSendRuntime.TrackSentPacket` dictionary-resize row from `codex-h3-1kb-receive-ring-prealloc-source-allocations-20260709a`; the new GC trace sampled only six runtime-only allocation groups and zero project-attributed/actionable groups. Treat this as targeted first-growth allocation cleanup, not a publishable throughput claim.

- 2026-07-09: client and server socket hosts now opt into receive-buffer ring preallocation while `QuicReceiveBufferPool` keeps lazy allocation as the default for lower-memory/test callers. This moves the fixed ring buffer allocation out of the socket receive hot path without changing rent/return counters or fallback behavior. `Incursa.Quic` Release build passed, the focused receive-buffer/shard/endpoint/HTTP3 test slice passed 96/97 with the known 1 MB body skip, and source-mode H3 profile pack `codex-h3-1kb-receive-ring-prealloc-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with validation 1/1, benchmark 1/1, zero failed/timeout requests, counters captured, 4,569.8 req/s, p95 66.972 ms, allocation-rate median 8,114,828 B/sec, and exception-rate median 42/sec. Evidence quality remains diagnostic and non-publishable because this was a single local repetition with missing variance, shared-host/load-generator warnings, and no linked publishability readiness manifest. Allocation attribution `codex-h3-1kb-receive-ring-prealloc-source-allocations-20260709a` no longer shows the prior sampled `QuicReceiveBufferPool.Rent()` `System.Byte[]` row from `codex-h3-1kb-packet-workitem-source-allocations-20260709a`; remaining top rows are HTTP/3 async state machines, central `QuicBufferPool` growth, stream state, timer/send effects, packet receipt storage, and framework endpoint materialization. Treat this as a targeted receive-loop allocation cleanup, not a publishable throughput claim.

- 2026-07-09: routed datagrams now enter the runtime shard through a packet-specific `QuicConnectionRuntimeShardWorkItem` and value `QuicConnectionPacketReceivedContext`, avoiding a `QuicConnectionPacketReceivedEvent` allocation for the endpoint-routed network hot path while preserving the existing event API for direct runtime tests and non-sharded posting. Owned receive-buffer release still happens in the shard `finally`/drain path, with a new focused test proving the packet-work-item path returns transferred buffers exactly once. `Incursa.Quic` Release build passed, focused shard/timer ownership tests passed 5/5, and a broader runtime/routing/HTTP3 slice passed 90/91 with the known 1 MB body skip. Source-mode H3 profile pack `codex-h3-1kb-packet-workitem-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with validation 1/1, benchmark 1/1, zero failed/timeout requests, counters captured, 5,904 req/s, p95 48.753 ms, allocation-rate median 10,112,086 B/sec, and exception-rate median 42.667/sec. Evidence quality remains diagnostic and non-publishable because of single repetition, local/shared host, missing variance, and readiness-link blockers. Allocation attribution `codex-h3-1kb-packet-workitem-source-allocations-20260709a` removed the prior sampled `QuicConnectionPacketReceivedEvent` rows from `QuicConnectionRuntimeEndpoint.TryPostPacketReceived`/`ReceiveDatagram`; the top trace dropped from 316 sampled allocation ticks in `codex-h3-1kb-readrequest-bufferpool-source-allocations-20260709a` to 69 in this local run. Treat the row removal as the durable claim, not the single-run throughput or allocation-rate movement.

- 2026-07-09: HTTP/3 server request reading now uses `QuicBufferPool` for its pooled frame-read buffer instead of calling `ArrayPool<byte>.Shared` directly, keeping request-read scratch ownership on the central QUIC buffer abstraction. `Incursa.Quic.Http3` Release build passed; the focused HTTP/3 client/server/dispatcher/RFC 9114/RFC 9204 test filter passed 118/120 with one known 1 MB body skip and one close-path observation flake, and the exact failed test rerun passed 1/1. Source-mode H3 profile pack `codex-h3-1kb-readrequest-bufferpool-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with validation 1/1, benchmark 1/1, zero failed/timeout requests, counters captured, 6,129.6 req/s, p95 45.281 ms, allocation-rate median 11,432,653 B/sec, and exception-rate median 42.667/sec. The updated ProtocolLab evidence bundle classified this as diagnostic and non-publishable because of single repetition, local/shared host, missing variance, and readiness-link blockers. Allocation attribution `codex-h3-1kb-readrequest-bufferpool-source-allocations-20260709a` removed the prior direct `Http3Server.ReadRequestAsync` `System.Byte[]` row; remaining first-use byte-array growth is attributed to `QuicBufferPool.RentBytes`.

- 2026-07-09: HTTP/3 peer unidirectional stream observers now rent their drain scratch buffers from `QuicBufferPool` and return them in `finally` on both server and client paths. `Incursa.Quic.Http3` Release build passed, the focused HTTP/3 client/server/dispatcher/RFC 9114/RFC 9204 test filter passed 119/120 with the known 1 MB body skip, and source-mode H3 profile pack `codex-h3-1kb-unidirectional-buffer-pool-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests, counters captured, 5,639.6 req/s, p95 55.489 ms, allocation-rate mean 9,401,680 B/sec, and 32 exceptions/sec. The updated ProtocolLab run emitted `evidence-bundle.json` and `artifact-manifest.json` for counter, CPU-trace, and GC-trace cells. Allocation attribution `codex-h3-1kb-unidirectional-buffer-pool-source-allocations-20260709a` moved the prior sampled `Http3Server.ObservePeerUnidirectionalStreamAsync` direct `System.Byte[]` row into `QuicBufferPool.RentBytes`; this is targeted scratch-buffer ownership cleanup, not a claim that underlying pool growth is eliminated.

- 2026-07-09: added a first-class `RawQuicStreamThroughput` performance-lane surface for ProtocolLab `quic.transport.stream-throughput.1mb` with the existing raw send/scheduler/parsing BenchmarkDotNet companions, and surfaced it in the perf README, benchmark README, readiness command list, and script preflight test. Dry-run proof `codex-raw-stream-throughput-surface-dryrun-20260709a` emitted the expected BDN commands plus the raw QUIC ProtocolLab command. Source-backed smoke proof `codex-raw-stream-throughput-surface-smoke-20260709a` passed the raw QUIC stream-throughput ProtocolLab cell with validation passed 1/1, benchmark succeeded 1/1, no failed or timeout requests, `quic-go-raw-load`, and a local single-run throughput sample of 494,033.773 bytes/sec. Counter-capture smoke proof `codex-raw-stream-throughput-counters-smoke-20260709a` also passed validation and benchmark execution, captured target process metrics, load-generator process metrics, and dotnet counters with `countersMissingCount=0`, including throughput, allocation rate, GC deltas, exception rate, and CPU fields. Treat this as diagnostic lane coverage and validation proof only; publishability remains blocked by single repetition and local shared-host evidence.
- 2026-07-09: repeated raw stream-throughput confidence run `codex-raw-stream-throughput-confidence-counters-20260709a` passed validation and benchmark execution for all 9 repetitions with zero failed or timeout requests, captured target process metrics and dotnet counters for all 9 repetitions, and reported median throughput 2,685,246.754 bytes/sec, median allocation rate 3,082,234.545 B/sec, median exception rate 0.098/sec, median CPU 23.473%, and median p95 418.057 ms. The lane still reports `performance-instability`; publishability remains blocked by variance above threshold, with throughput/request relative range 1.514 and p95 relative range 17.133. Treat this as repeated local regression evidence and a clear next target for raw-lane stability, not a publishable benchmark claim.
- 2026-07-09: wider raw stream-throughput diagnostic run `codex-raw-stream-throughput-c1s4-confidence-20260709a` used the same scenario with `-RawQuicStreamsPerConnection 4`, passed validation and benchmark execution for all 9 repetitions, captured counters for all 9 repetitions, and had no failed or timeout requests. Compared with the c1/s1 confidence run, median throughput improved to 5,889,703.164 bytes/sec and throughput relative range dropped from 1.514 to 0.200, but p95 remained unstable with relative range 1.056 and publishability still blocked by `variance-above-publishable-threshold`. Treat c1/s4 as a better local diagnostic shape for transport throughput triage, not a replacement for the canonical single-stream scenario or publishable evidence.
- 2026-07-09: package-backed raw stream-throughput smoke proof `job-aab2a89fae1a4807ab989ebb8df37f52` completed on `plab-worker-sut-01` using `quic-dotnet-raw-dev@dev-20260709T094345Z-14e8d5a2-clean` plus binary-backed `protocol-lab-quic-go-raw-load@dev-20260709T095500Z-14e8d5a2-clean-binraw` and `protocol-lab-raw-quic-scenarios@dev-20260709T095500Z-14e8d5a2-clean-binraw`. It passed validation 1/1, benchmark succeeded 1/1, produced readable controller artifacts, and measured a single-run throughput sample of 7,313,722.042 bytes/sec with p95 308.285 ms. Treat this as package-boundary validation evidence only; publishability remains blocked by `repeat-count-below-publishable-minimum`, local shared-host execution, no CPU/network isolation, missing runtime counters, and one repetition.
- 2026-07-09: package-backed raw stream-throughput confidence proof `job-bcb049b36892490ca2949dcb6d8dcc00` reused the same admitted package references and completed 3 repetitions on `plab-worker-sut-01`. It passed validation 3/3, benchmark succeeded 3/3, had zero failed or timeout requests, captured target and load-generator process metrics, and produced readable controller artifacts. Median throughput was 7,070,152.333 bytes/sec with best/worst 7,605,253.432 / 6,714,902.639 bytes/sec; median p95 was 344.01 ms with best/worst 306.859 / 351.797 ms. Treat this as repeated package-boundary regression evidence, not publishable evidence; publishability remains blocked by `variance-above-publishable-threshold`, local shared-host/single-machine execution, no CPU/network isolation, missing runtime counters, and process-mode load-tool caveats.
- 2026-07-09: package-backed raw multiplex and duplex confidence proofs completed through the same admitted `quic-dotnet-raw-dev`, `protocol-lab-quic-go-raw-load`, and `protocol-lab-raw-quic-scenarios` package references. `job-c1f45316b0ef4d3d85e179c794682c0c` proved `quic.transport.multiplex.100x64kb` with validation 3/3, benchmark succeeded 3/3, zero failed or timeout requests, median throughput 6,083,503.045 bytes/sec, and median p95 19.438 ms. `job-875a89f8926e45b6b93cf7ce806434f4` proved `quic.transport.duplex-streams` with validation 3/3, benchmark succeeded 3/3, zero failed or timeout requests, median throughput 6,054,715.481 bytes/sec, and median p95 18.611 ms. Treat these as clean package-backed regression rows only; publishability remains blocked by local shared-host execution and variance above threshold.
- 2026-07-09: baseline reporting now accepts explicit `-AggregateResultPath` inputs, including controller artifact wrapper files with inline aggregate JSON. Package-backed raw baseline report `codex-package-backed-raw-baseline-20260709a` scanned the three current controller aggregate wrappers, matched 3 `quic-dotnet-raw-dev` rows, and selected clean validation/benchmark rows for `quic.transport.stream-throughput.1mb`, `quic.transport.multiplex.100x64kb`, and `quic.transport.duplex-streams`; all three remain attention rows only because of `variance-above-publishable-threshold`.
- 2026-07-09: source-backed raw stream-throughput now records the package-compatible `quic-dotnet-raw-dev` implementation identity. ProtocolLab internal has a source-mode alias manifest for the same raw QUIC adapter project, and quic-dotnet performance helpers pass through `-LoadProfileId` so source and package runs can use the same `smoke` profile. Source proof `codex-raw-source-package-parity-smoke-20260709b-quic-transport-v1-comparison` passed validation and benchmark for `quic.transport.stream-throughput.1mb` from clean ProtocolLab commit `f7574c1`. Native compare output `.artifacts/perf-parity/codex-source-package-raw-stream-smoke-parity-20260709b/run-comparison.{json,md}` matched 1 cell and reported source/package parity satisfied 1/1, blocked 0/1. This is still diagnostic single-repetition evidence, not publishable benchmark proof.
- 2026-07-09: raw multiplex and duplex now have the same source/package parity shape. Fresh package-backed jobs `job-0eccd6f849084edd9177116c01d4946f` and `job-35a45c8220b34b92a671d9cc6d1abc30` produced controller-readable `evidence-bundle.json` artifacts for `quic.transport.multiplex.100x64kb` and `quic.transport.duplex-streams`. Matching source proofs `codex-raw-source-package-parity-multiplex-smoke-20260709a-quic-transport-v1-comparison` and `codex-raw-source-package-parity-duplex-c1s1-smoke-20260709a-quic-transport-v1-comparison` passed validation and benchmark. Native compare outputs under `.artifacts/perf-parity/codex-raw-source-package-parity-raw-extra-20260709a/{multiplex,duplex}/run-comparison.{json,md}` each matched 1 cell and reported source/package parity satisfied 1/1, blocked 0/1. These are still diagnostic single-repetition local/package smoke checks, not publishable benchmark proof.
- 2026-07-09: `scripts/perf/Invoke-QuicProtocolLabPublication.ps1` now provides a dry-run-first bridge from completed package-backed controller jobs to the existing ProtocolLab publication endpoint. It defaults to `dryRun=true`, records controller publication attempts in `.artifacts/perf-publication/{runId}/publication-results.json`, and requires explicit `-Publish` before the controller upload/enqueue path is used. Dry-run proof `codex-package-backed-raw-publication-dryrun-20260709c` succeeded for the three current raw package-backed confidence jobs with attempts `pub_06df61dfe72b43d9874e31a7d2236c6d`, `pub_af33afc5a1f4433e9ff40d045c8b5661`, and `pub_4d828601d51f4d68908679854306b84d`. This makes durable dashboard bundle readiness repeatable while preserving the current local/shared-host and variance blockers.
- 2026-07-09: `QuicConnectionEffectAccumulator` now keeps up to eight transition effects inline before spilling to a `List<QuicConnectionEffect>`, preserving order and existing overflow behavior while avoiding the prior mid-sized transition-list allocation path. Focused accumulator tests passed 2/2, the broader runtime/timer/HTTP3/RFC 9114/RFC 9204 test slice passed 1120/1121 with one existing skip, and source-backed H3 profile pack `codex-h3-1kb-effect-accumulator-inline8-current-20260709b` passed ProtocolLab proof 1/1 and benchmark 1/1 for `http3.payload.bytes.1kb` at c16-s10 with zero failed/timeout requests and counters captured. Allocation attribution `codex-h3-1kb-effect-accumulator-inline8-current-allocations-20260709b` no longer shows the previous `QuicConnectionEffect[]`/list-constructor spill row in the top sampled groups. Treat this as targeted allocation-stack cleanup only; remaining top rows are X25519 arrays, HTTP/3 request/write state machines, stream state, timer effects, and runtime events.
- 2026-07-09: managed X25519 now uses an allocation-free managed radix-51 field implementation instead of `BigInteger` limb arrays for scalar multiplication. `Incursa.Quic` Release build passed, focused X25519/RFC 7748 tests passed 6/6, and `QuicTlsX25519Benchmarks` Dry evidence `codex-x25519-radix51-dry-20260709a` reported zero managed allocation for public-key derivation, shared-secret derivation, and full exchange. Compared with `codex-x25519-current-dry-20260709b`, public-key derivation moved from 10.77 ms / 444.38 KB to 10.02 ms / 0 B, shared-secret derivation moved from 11.35 ms / 462.43 KB to 10.50 ms / 0 B, and full exchange moved from 13.92 ms / 1,350.91 KB to 17.92 ms / 0 B. Source-mode H3 profile pack `codex-h3-1kb-x25519-radix51-source-20260709a` passed ProtocolLab proof 1/1 and benchmark 1/1 with zero failed/timeout requests, counters captured, 6,510.2 req/s, p95 47.287 ms, allocation rate 13,109,851 B/sec, and 64 exceptions/sec. Allocation attribution `codex-h3-1kb-x25519-radix51-source-allocations-20260709a` no longer shows `QuicTlsX25519`, `BigInteger`, or X25519 `System.UInt32[]` rows in the top 60 sampled groups. Treat this as a crypto allocation-pressure fix; the full-exchange Dry timing is a follow-up tuning target, not a publishable regression claim.
- 2026-07-09: local flow-control credit publication now coalesces pending producer-side `TryQueueFlowControlCreditUpdate` notifications, preserving the highest pending MAX_DATA/MAX_STREAM_DATA values while posting at most one local flush event until the runtime drains it. `Incursa.Quic` Release build passed, focused flow-control/stream-action tests passed 13/13, and source-mode H3 profile pack `codex-h3-1kb-flow-credit-event-coalesce-source-20260709b` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with 27,569/27,569 successful requests, zero failed/timeout requests, counters captured, 5,513.8 req/s, p95 46.591 ms, allocation-rate mean 11,195,137 B/sec, and 64 exceptions/sec. Allocation attribution `codex-h3-1kb-flow-credit-event-coalesce-source-allocations-20260709b` sampled only one `QuicConnectionFlowControlCreditUpdatedEvent` row at 104,704 bytes and did not retain the dictionary churn introduced by the first coalescer attempt. Treat this as targeted event-allocation cleanup only; single-run H3 throughput remains local/noisy.
- 2026-07-09: peer stream-capacity release publication now posts a single generic pending-release flush event while producer-side stream IDs are scheduled, preserving direct stream-specific release events for tests and deterministic transitions. The scheduled and pending release sets are pre-sized to avoid first-use hash-table churn. `Incursa.Quic` Release build passed, focused stream-capacity/flow-control tests passed 14/14, and source-mode H3 profile pack `codex-h3-1kb-stream-capacity-event-coalesce-source-20260709b` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with 31,290/31,290 successful requests, zero failed/timeout requests, counters captured, 6,258 req/s, p95 45.130 ms, allocation-rate mean 12,103,996 B/sec, and 64 exceptions/sec. Allocation attribution `codex-h3-1kb-stream-capacity-event-coalesce-source-allocations-20260709b` reduced the `TryQueueStreamCapacityRelease` `QuicConnectionStreamActionEvent` row to one sampled event at 106,424 bytes and had no scheduled-release `HashSet` initialization row. Treat this as targeted event-allocation cleanup only; single-run H3 throughput remains local/noisy.
- 2026-07-09: nullable inbound stream accept now waits with `ChannelReader.ReadAsync(cancellationToken)` instead of a custom `WaitToReadAsync` plus `TaskCompletionSource` cancellation race and follow-up `TryRead`, preserving null-on-cancel and null-on-close behavior while removing the helper task/registration path. `Incursa.Quic` Release build passed, focused accept-cancellation tests passed 2/2, the focused HTTP/3 server/client filter passed 70/72 with two existing close-path timeout flakes and exact reruns passed 2/2, and source-mode H3 profile pack `codex-h3-1kb-accept-readasync-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests, counters captured, 6,688 req/s, p95 46.396 ms, allocation-rate mean 12,804,193 B/sec, and 42.667 exceptions/sec. Allocation attribution `codex-h3-1kb-accept-readasync-source-allocations-20260709a` remained single-run noisy and still sampled accept and request-handler async boxes, so treat this as code-path simplification plus validation evidence, not a measured throughput or allocation-rate win.
- 2026-07-09: ACK generation, sender flow control, sender recovery, and recovery timing now pre-size their per-packet-number-space ordered packet maps to thirty-two entries, and the connection send runtime pre-sizes its sent-packet dictionary to sixteen entries. This avoids zero-capacity `SortedList`/ACK-frame/sent-packet dictionary first-growth churn in the common early packet history. `Incursa.Quic` Release build passed, the focused ACK/recovery/congestion/loss/RFC 9002/RFC 9000 S13/S19 test slice passed 2895/2897 with two HTTP/3 loopback flakes and exact reruns passed 2/2, and source-mode H3 profile pack `codex-h3-1kb-packet-map-capacity32-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests, counters captured, 6,005.8 req/s, p95 54.086 ms, allocation-rate mean 10,230,038 B/sec, and 25.6 exceptions/sec. Allocation attribution `codex-h3-1kb-packet-map-capacity32-source-allocations-20260709a` no longer shows sampled `PacketReceipt[]`, sender `SentPacketState`, ACK `SentAckFrameState`, or `QuicConnectionSentPacketKey` growth rows; it only retains expected constructor/pre-size rows for the packet maps. Treat this as targeted allocation-stack cleanup only; single-run throughput remains local/noisy.
- 2026-07-09: HTTP/3 QPACK request/response header decode now returns a completed `ValueTask` for cached or non-blocked field sections and only allocates an async continuation when waiting for peer settings or blocked QPACK decode. `Incursa.Quic.Http3` Release build passed, the focused HTTP/3/QPACK/RFC 9114/RFC 9204 test filter passed 1158/1161 with one skip and two known close-path timeout flakes, and exact reruns of the failed tests passed 2/2. Source-mode H3 profile pack `codex-h3-1kb-qpack-decode-valuetask-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests, counters captured, 5,548.8 req/s, p95 49.818 ms, allocation-rate mean 10,795,574 B/sec, and 42.667 exceptions/sec. Allocation attribution did not show request/response decode methods as sampled top allocation groups either before or after this change, so treat this as targeted synchronous-completion cleanup plus validation evidence, not a measured top-row or throughput claim.
- 2026-07-09: incoming stream sequence bookkeeping now tracks the highest peer-created bidirectional and unidirectional stream indexes with inline fields instead of a two-entry `Dictionary<QuicStreamType, ulong>`, removing a per-connection dictionary allocation and two lookups from implicit peer stream opens. `Incursa.Quic` Release build passed, the rebuilt focused stream-state/stream-limit test filter passed 59/59, and source-mode H3 profile pack `codex-h3-1kb-incoming-stream-index-inline-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests, counters captured, 6,543.2 req/s, p95 43.516 ms, allocation-rate mean 12,503,477 B/sec, and 42.667 exceptions/sec. Allocation attribution `codex-h3-1kb-incoming-stream-index-inline-source-allocations-20260709a` does not show a sampled `QuicStreamType` dictionary row and still shows `StreamState` plus stream dictionary growth as the larger remaining design costs, so treat this as code-review-backed bookkeeping allocation hygiene plus validation evidence.
- 2026-07-09: HTTP/3 stream dispatcher state now stores its private mutable stream state directly in the dispatcher dictionary as a struct and uses by-reference dictionary value lookup for stream-type/control-stream mutations, removing the per-registered-stream private `StreamState` wrapper object while preserving the public `Http3StreamInfo` return object. `Incursa.Quic.Http3` Release build passed, the rebuilt focused HTTP/3 dispatcher/settings/QPACK/RFC 9114 test filter passed 81/81, and source-mode H3 profile pack `codex-h3-1kb-dispatcher-state-struct-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests, counters captured, 5,644 req/s, p95 52.629 ms, allocation-rate mean 10,805,095 B/sec, and 42.667 exceptions/sec. Allocation attribution `codex-h3-1kb-dispatcher-state-struct-source-allocations-20260709a` removed the sampled `Http3StreamDispatcher.RegisterBidirectionalStream` private `StreamState` allocation row seen in `codex-h3-1kb-incoming-stream-index-inline-source-allocations-20260709a`; public `Http3StreamInfo` allocation rows remain.
- 2026-07-09: HTTP/3 stream dispatcher registration now separates public materializing registration from internal state-only registration, so server/client hot paths that ignore registration return values no longer allocate `Http3StreamInfo` just to record a stream. Dispatcher state keeps primitive stream mapping fields and lazily caches immutable `Http3StreamInfo` objects only when public APIs request them. `Incursa.Quic.Http3` Release build passed, the rebuilt focused HTTP/3 dispatcher/settings/QPACK/RFC 9114/minimal-server/client filter passed 145/146 with the known 1 MB body skip, and source-mode H3 profile pack `codex-h3-1kb-dispatcher-info-lazy-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests, counters captured, 6,527.6 req/s, p95 52.168 ms, allocation-rate mean 12,235,239 B/sec, and 42.667 exceptions/sec. Allocation attribution `codex-h3-1kb-dispatcher-info-lazy-source-allocations-20260709a` no longer shows sampled `Http3StreamInfo` or dispatcher registration allocation rows, where `codex-h3-1kb-dispatcher-state-struct-source-allocations-20260709a` still sampled both bidirectional and unidirectional `Http3StreamInfo` registration rows. Treat the throughput/allocation-rate counters as single-run local evidence; the sampled row removal is the durable claim.
- 2026-07-09: stream bookkeeping now re-applies its existing capped tracked-stream capacity estimate when peer MAX_STREAMS credit arrives, so client-side request stream tracking grows once after transport-parameter stream limits instead of waiting for the request-open hot path. `Incursa.Quic` Release build passed, focused stream-state/stream-limit/API tests passed 116/116, the focused HTTP/3 filter passed 98/102 with three close-path timeout flakes plus one skip and exact reruns passed 3/3, and source-mode H3 profile pack `codex-h3-1kb-stream-dictionary-ensure-source-20260709a` passed ProtocolLab proof and benchmark for `http3.payload.bytes.1kb` with zero failed/timeout requests, counters captured, 5,842.8 req/s, p95 52.759 ms, allocation-rate mean 11,334,988 B/sec, and 42.667 exceptions/sec. Allocation attribution reduced the `TryOpenIncomingStreamSequence` dictionary resize row compared with `codex-h3-1kb-packet-map-capacity32-source-allocations-20260709a`, but did not eliminate all stream dictionary growth. Treat this as partial targeted cleanup; retaining closed stream state remains the larger design issue.
- 2026-07-09: public `QuicStream.CompleteWritesAsync` now mirrors the write path's fast-path shape: it returns synchronously when writes are already closed, waits on the write gate only when contended, and only creates an async continuation when the runtime FIN request has not completed. `Incursa.Quic` and benchmark Release builds passed, focused stream/API lifecycle tests passed 109/112 with three existing skips in the selected filter, and source-backed 200-iteration public stream profiles `codex-profile-stream-target-incursa-completewrites-fastpath-sourcebacked-20260709a.json` and `codex-profile-stream-target-incursa-completewrites-fastpath-sourcebacked-20260709c.json` measured pass-2 allocation at 11,302-11,331 B/op versus 11,379 B/op in `codex-profile-stream-target-incursa-finish-valuetask-sourcebacked-20260709a.json`. Treat this as a modest public stream completion fast-path allocation reduction only; elapsed time remains single-run noisy.
- 2026-07-09: runtime FIN completion now uses the same pooled `StreamActionRequestCompletionSource` `ValueTask<bool>` path as stream writes instead of forcing `CompleteStreamWritesAsyncCore` through a `Task<bool>` async state machine and local cancellation-registration lifetime. `Incursa.Quic` and benchmark Release builds passed, focused stream/API lifecycle tests passed 107/107, and source-backed 200-iteration public stream profile `codex-profile-stream-target-incursa-finish-valuetask-sourcebacked-20260709a.json` reduced pass-2 allocation from 11,600 B/op in `codex-profile-stream-target-incursa-valuetask-writecore-sourcebacked-20260709a.json` to 11,380 B/op. Treat this as a targeted public stream FIN-path allocation reduction, not a throughput claim.
- 2026-07-09: public `QuicStream.WriteAsync(ReadOnlyMemory<byte>, CancellationToken)` now returns the stream write `ValueTask` path directly instead of wrapping a `Task`-returning core, while the legacy byte-array `WriteAsync` overload keeps its `Task` compatibility wrapper. Read/write gate lazy initialization also avoids the `LazyInitializer` helper allocation that appeared in retained public-stream attribution by using `Volatile.Read` plus `Interlocked.CompareExchange` and disposing loser semaphores on races. `Incursa.Quic` and benchmark Release builds passed, focused stream/read/write lifecycle tests passed 92/92, and source-backed 200-iteration public stream profile `codex-profile-stream-target-incursa-valuetask-writecore-sourcebacked-20260709a.json` measured pass-2 allocation at 11,600 B/op versus the immediately preceding retained 200-iteration range of 11,642-11,737 B/op. Treat this as modest public stream allocation cleanup only; verbose GC allocation traces for this benchmark remained too expensive even at 50 iterations, so retained trace attribution was used for site selection.
- 2026-07-09: managed X25519 now skips six redundant ladder-local modular reductions per bit for values that are immediately consumed by a later field square, multiplication, or final reduction, while keeping coordinate outputs reduced at the existing field boundaries. `Incursa.Quic` Release build passed, focused X25519/RFC 7748 tests passed 6/6, and `QuicTlsX25519Benchmarks` Dry evidence `codex-x25519-remove-redundant-mods-20260709a` reduced managed allocation versus `codex-x25519-reduced-inner-mod-20260709a` from 555.87 KB to 444.38 KB for public-key derivation, 574.28 KB to 462.43 KB for shared-secret derivation, and 1,687.24 KB to 1,350.91 KB for a full exchange. Source-backed H3 profile pack `codex-h3-1kb-x25519-redundant-mods-20260709a` passed ProtocolLab validation for `http3.payload.bytes.1kb` at c16-s10 with zero failed/timeout requests; its GC trace reduced the sampled `QuicTlsX25519.Mod` row from 7,886,928 bytes / 74 events in `codex-h3-1kb-request-handler-valuetask-source-allocations-20260709a` to 2,981,408 bytes / 28 events, but total sampled H3 bytes remained single-run noisy, so treat this as targeted crypto allocation evidence only. The larger fixed-limb X25519 rewrite remains open.
- 2026-07-09: HTTP/3 request stream handling now returns `ValueTask` from the detached server request handler and dispatches bidirectional/unidirectional streams through explicit branches, reducing the sampled `Http3Server.HandleRequestStreamAsync` async-state-machine allocation row in same-source ProtocolLab GC traces from 5,098,024 bytes / 48 events in `codex-h3-1kb-request-handler-task-source-baseline-allocations-20260709a` to 958,888 bytes / 9 events in `codex-h3-1kb-request-handler-valuetask-source-allocations-20260709a`. Source-backed profile pack `codex-h3-1kb-request-handler-valuetask-source-20260709a` passed ProtocolLab validation for `http3.payload.bytes.1kb` at c16-s10 with zero failed/timeout requests, and its counters sample measured 2,018.77 B/request versus 2,062.68 B/request in the same-source `Task` baseline. `Incursa.Quic.Http3` Release build passed, the broad HTTP/3 test filter passed 1,090/1,093 with one existing skip and two known close-path timeout flakes, and exact rerun of those two failures passed 2/2. Treat this as targeted allocation-pressure evidence only; request-rate movement was single-run noisy and not a throughput claim.
- 2026-07-09: public stream benchmark/profile helpers now write through `Stream.WriteAsync(ReadOnlyMemory<byte>, CancellationToken)` / `QuicStream.WriteAsync(ReadOnlyMemory<byte>, CancellationToken)` instead of legacy array overloads, and Incursa benchmark paths call the cancellation-aware `CompleteWritesAsync` directly instead of wrapping the parameterless `ValueTask` in `AsTask().WaitAsync(...)`. Benchmark Release build passed, `--profile-stream 5 --target all` smoke passed, 200-iteration Incursa-only proof `codex-profile-stream-target-incursa-memory-write-overload-20260709a.json` measured pass-2 allocation at 11,483 B/op, verbose Incursa-only allocation trace `codex-public-stream-incursa-only-memory-write-overload-allocations-20260709a` still shows real runtime write async work but no legacy array-write profile row, and BDN Dry proof `codex-public-stream-memory-write-overload-20260709a` passed all 12 touched public stream transfer/steady-state cells. Treat this as benchmark/profile hygiene plus a small allocation improvement; the runtime write state machine remains the next real target.
- 2026-07-09: runtime deadline schedulers now start their timer heap and registration map with a modest capacity of 16 entries, avoiding first-growth array/dictionary churn as active connection timers are armed. `Incursa.Quic` and benchmark Release builds passed, focused timer/recovery tests passed 317/317, verbose Incursa-only allocation trace `codex-public-stream-incursa-only-scheduler-capacity-allocations-20260709a` no longer sampled the prior `QuicConnectionRuntimeDeadlineScheduler.Arm` `Array.Resize` row, and 200-iteration Incursa-only proof `codex-profile-stream-target-incursa-scheduler-capacity-20260709a.json` measured pass-2 allocation at 11,703 B/op. Treat this as small scheduler capacity hygiene, not a material throughput claim.
- 2026-07-09: `QuicAllocationHarness` EOF validation now returns `ValueTask` and completes synchronously when the EOF probe read is already complete, removing another harness-only async-state-machine row from Incursa-only public stream allocation traces. Benchmark Release build passed, `--profile-stream 5 --target all` smoke passed, verbose Incursa-only allocation trace `codex-public-stream-incursa-only-eof-valuetask-allocations-20260709a` no longer sampled the prior `QuicAllocationHarness.EnsureEofAsync` row, and 200-iteration Incursa-only proof `codex-profile-stream-target-incursa-eof-valuetask-20260709a.json` measured pass-2 allocation at 11,566 B/op. Treat this as measurement cleanup only; public stream open/write/complete async state machines remain real runtime work.
- 2026-07-09: public stream benchmark/profile helpers now read through the modern `Stream.ReadAsync(Memory<byte>, CancellationToken)` overload instead of the legacy array overload, avoiding artificial `Task<int>` allocation noise when `QuicStream` can complete reads synchronously through its `ValueTask<int>` path. Benchmark Release build passed, `--profile-stream 5 --target all` smoke passed, verbose Incursa-only allocation trace `codex-public-stream-incursa-only-memory-read-overload-allocations-20260709a` no longer sampled the prior `QuicStream.ReadAsync(byte[], int, int, CancellationToken)` / `Task.FromResult` row, and 200-iteration Incursa-only proof `codex-profile-stream-target-incursa-memory-read-overload-20260709a.json` measured pass-2 allocation at 11,522 B/op. Treat this as benchmark hygiene; real async read waiters still appear when a stream read genuinely waits.
- 2026-07-09: client endpoint outbound sends now cache the parsed remote `IPEndPoint` and serialized `SocketAddress` by exact `QuicConnectionPathIdentity`, mirroring the listener pending-connection cache and avoiding repeated remote address parse/serialize work on stable paths while preserving migration correctness through path-identity matching. Focused endpoint-host/path tests passed 21/21, `Incursa.Quic` and benchmark Release builds passed, verbose Incursa-only allocation trace `codex-public-stream-incursa-only-endpoint-address-cache-allocations-20260709a` no longer sampled the prior listener-side `IPEndPoint.Serialize` row from the immediately preceding scratch-reuse trace, and 200-iteration Incursa-only proof `codex-profile-stream-target-incursa-endpoint-address-cache-20260709a.json` measured pass-2 allocation at 11,665 B/op. Treat this as bounded hot-path hygiene and allocation-trace cleanup; framework receive-side endpoint materialization still appears in smaller samples and remains a separate target.
- 2026-07-09: `--profile-stream` now reuses caller-owned request, response, and EOF probe buffers inside the measured request/response operation, so the non-BDN public-stream profile no longer attributes harness validation buffers to Incursa runtime allocation. Incursa-only trace `codex-public-stream-incursa-only-scratch-reuse-allocations-20260709a` no longer sampled the prior `RunIncursaRequestResponseStreamAsync` `System.Byte[]` buffer row, and the 200-iteration Incursa-only proof `codex-profile-stream-target-incursa-scratch-reuse-20260709a.json` measured pass-2 allocation at 12,545 B/op. Treat this as measurement hygiene that makes the remaining runtime event/effect rows easier to target.
- 2026-07-09: `QuicAllocationHarness --profile-stream` now accepts `--target incursa|systemnet|all`, making allocation traces isolate Incursa public stream work without `System.Net.Quic` comparison noise. The Incursa-only trace `codex-public-stream-incursa-only-allocations-20260709a` exposed the next stream-constructor allocation row, so `QuicStream` now lazily materializes its read-side `SemaphoreSlim` only after a read actually has to wait and rechecks the stream state after creating the gate to avoid a lost wake-up. Focused stream/read validation passed 1,414/1,417 with 3 existing skips, post-change trace `codex-public-stream-incursa-only-lazy-read-gate-allocations-20260709a` no longer sampled the `QuicStream..ctor` `SemaphoreSlim` row, and 200-iteration Incursa-only proof `codex-profile-stream-target-incursa-lazy-read-gate-20260709a.json` measured pass-2 allocation at 14,683 B/op. Treat this as a targeted public-stream allocation reduction plus cleaner future trace evidence.
- 2026-07-09: hot-path `QuicConnectionTransportState` flag checks now use direct bitwise tests instead of `Enum.HasFlag`, removing the sampled enum-boxing allocation row in `TrySelectRecoveryTimer`. Focused runtime validation passed with `dotnet build .\src\Incursa.Quic\Incursa.Quic.csproj -c Release --no-restore` and a recovery/path/endpoint-host test filter passing 620/620. Short post-change allocation trace `codex-public-stream-transport-flags-no-hasflag-allocations-20260709a` no longer sampled the prior `QuicConnectionTransportState` row and measured `--profile-stream 20` Incursa pass-2 allocation at 15,502 B/op. Treat this as small hot-path hygiene backed by sampled allocation evidence.
- 2026-07-09: public client endpoint receive now opts out of routed datagram observer callbacks, preserving the endpoint host's default routed-observer behavior for tests/harnesses while avoiding an unnecessary `datagram.ToArray()` on steady-state routed client receive packets. The direct allocation trace `codex-public-stream-profile-allocations-20260709c` identified the routed observer copy through `QuicConnectionEndpointHost.ReceiveLoopAsync`, the post-change trace `codex-public-stream-profile-client-observer-optout-allocations-20260709a` no longer sampled that row, and the 200-iteration `--profile-stream` proof `codex-public-stream-profile-client-observer-optout-20260709a.json` reduced Incursa pass-2 managed allocation from 17,135 B/op in `codex-public-stream-profile-20260709a.json` to 15,732 B/op. `Incursa.Quic` and benchmark Release builds passed, and focused endpoint-host tests cover both default routed observer delivery and the new opt-out path. Treat this as a targeted public-client allocation reduction; the remaining public stream allocation gap is still open.
- 2026-07-09: expanded `QuicPublicApiStreamTransferBenchmarks` from one request/response workload to four public-facade stream-transfer workloads: client upload, server download, bidirectional request/response, and eight sequential request/response streams over one connection. `dotnet build .\benchmarks\Incursa.Quic.Benchmarks.csproj -c Release --no-restore` passed, BDN Dry evidence `codex-public-api-stream-expanded-20260709a` executed all 8 Incursa/System.Net.Quic cells, and `PublicApiStream` smoke lane `codex-public-api-stream-expanded-smoke-20260709a` passed through the normal lane wrapper. The lane proof measured Incursa single-stream allocations at 404.68-413.41 KB versus System.Net.Quic 150.47-168.28 KB; the sequential reuse workload was 550.63 KB for Incursa versus 195.2 KB for System.Net.Quic. Treat this as public API baseline coverage and a measured gap, not a runtime fix.
- 2026-07-09: `PublicApiStream` now also runs `QuicPublicApiSteadyStateStreamBenchmarks`, so the lane covers both full transfer lifecycle workloads and established-connection stream workloads. Smoke proof `codex-public-api-stream-steady-lane-20260709a` passed the transfer and steady-state slices. Established-connection Dry evidence measured Incursa request/response at 13.892 ms and 41.89 KB versus System.Net.Quic at 5.572 ms and 11.48 KB; the small queued-write case was closer at 8.565 ms and 7.31 KB versus 1.926 ms and 5.99 KB. Treat this as evidence that a meaningful part of the public API gap remains in per-stream request/response work after setup is removed.
- 2026-07-09: added `QuicAllocationHarness --profile-stream` to provide a faster non-BDN allocation probe for established public request/response streams. Diagnostic run `codex-public-stream-profile-20260709a.json` used 200 iterations over one connected pair per implementation. Pass 2 measured Incursa at 0.536 ms and 17,135 managed B/op versus System.Net.Quic at 10.316 ms and 5,810 managed B/op, showing the remaining actionable gap is allocation-heavy Incursa per-stream public API work rather than raw elapsed time in this local harness.
- 2026-07-09: `PublicApiStream` smoke lane proof `codex-public-api-stream-smoke-20260709a` passed on clean commit `401db2296ad5c955431bcfabfb50c2263b0b4a67`, running `QuicPublicApiStreamTransferBenchmarks` through `Invoke-QuicPublicComparison.ps1 -Job Dry`. The diagnostic Dry comparison measured the bounded 1 KB public-facade request/response stream workload at 374.56 ms and 412.87 KB for Incursa.Quic versus 80.39 ms and 145.62 KB for `System.Net.Quic`. Treat this as a baseline gap and lane proof, not an optimized result or publishable comparison.
- 2026-07-09: managed X25519 now avoids two mathematically redundant inner modular reductions inside each Montgomery ladder step while preserving the same outer field reductions. Focused X25519/RFC 7748 tests passed 6/6. `QuicTlsX25519Benchmarks` Dry evidence `codex-x25519-reduced-inner-mod-20260709a` reduced allocation from the `codex-crypto-core-smoke-20260709a` smoke baseline from 580.8 KB to 555.87 KB for public-key derivation, 592.14 KB to 574.28 KB for shared-secret derivation, and 1,754.95 KB to 1,687.24 KB for a full exchange. This is a bounded `BigInteger` cleanup; the larger fixed-limb X25519 rewrite remains open.
- 2026-07-09: CRYPTO buffer insertion scratch storage now grows geometrically instead of exact-fitting `insertScratch` capacity as shuffled frame entry counts rise. Focused RFC 9000 CRYPTO-buffer tests passed 9/9. `QuicCryptoBufferBenchmarks` Dry evidence `codex-crypto-buffer-scratch-growth-20260709a` reduced `BufferAndDrainMinimumCryptoStream` allocation further to 19.55 KB without overlap and 23.59 KB with overlap. Dry-mode timing was noisy, so treat this as local allocation evidence only.
- 2026-07-09: CRYPTO buffer insertion now defers copying until retained frame segments are known, avoiding the prior whole-frame copy before insertion then per-segment copy inside `TryInsertFrameData`. Focused RFC 9000 CRYPTO-buffer tests passed 9/9. `QuicCryptoBufferBenchmarks` Dry evidence `codex-crypto-buffer-span-insert-20260709a` reduced `BufferAndDrainMinimumCryptoStream` allocation from the `codex-crypto-core-smoke-20260709a` smoke baseline from 152.39 KB to 144.97 KB without overlap and from 159.02 KB to 151.07 KB with overlap. Treat this as local diagnostic microbenchmark evidence, not end-to-end throughput proof.
- 2026-07-09: added `QuicTlsX25519Benchmarks` and a `CryptoCore` performance-lane surface to make the managed X25519 public-key, shared-secret, full-exchange, and adjacent packet-protection paths measurable before attempting any replacement of the current `BigInteger` ladder. This is benchmark coverage and crypto-safety groundwork only; it does not claim a runtime speedup.
- 2026-07-09: connection stream bookkeeping now pre-sizes its tracked-stream dictionary from bounded initial local and peer stream budgets, and pre-sizes the incoming stream-type index map for the two QUIC stream directions. `Incursa.Quic.Tests` Release build passed and the focused stream-state/stream-capacity/max-streams/read-buffer test filter passed 119/119. Source-backed H3 profile pack `codex-h3-1kb-stream-state-presize-20260709a` passed ProtocolLab validation for `http3.payload.bytes.1kb` at c16-s10 with zero failed/timeout requests. Allocation analysis reduced the sampled `TryOpenIncomingStreamSequence` dictionary resize rows from 3,038,856 bytes / 21 events plus 641,136 bytes / 6 `Int32[]` events in `codex-h3-1kb-headers-only-handler-fastpath-allocations-20260709a` to 1,933,568 bytes / 15 events plus 528,464 bytes / 5 `Int32[]` events in `codex-h3-1kb-stream-state-presize-allocations-20260709a`. Local triage showed allocation rate -4.06% and gen0 collections 8 -> 5, but request rate and p95 were slightly noisier in the wrong direction in this one-run sample, so treat this as allocation-pressure evidence only.
- 2026-07-09: HTTP/3 handlers can now opt into a headers-only request fast path via `IHttp3HeadersOnlyRequestHandler`, allowing GET requests with no DATA payload to avoid materializing a full `Http3Request` before handler dispatch. `Http3InMemoryRouteHandler`, the TechEmpower sample handler, and the source-backed ProtocolLab Incursa HTTP/3 adapter use the fast path while existing `IHttp3RequestHandler` implementations keep the previous fallback behavior. `Incursa.Quic.Tests` Release build passed, focused fast-path/sample tests passed 6/6, and the broader HTTP/3/sample filter passed 79/82 with 1 skip before the two known close-path timeout flakes passed on exact rerun. Source-backed ProtocolLab run `codex-h3-1kb-headers-only-handler-fastpath-20260709a` passed validation for `http3.payload.bytes.1kb` at c16-s10 with zero failed/timeout requests; local triage versus `codex-h3-1kb-complete-response-frame-cache-20260709a` showed request rate +2.81%, p95 -5.09%, CPU mean -2.04%, but allocation-rate and gen0 counters noisier. Allocation analysis `codex-h3-1kb-headers-only-handler-fastpath-allocations-20260709a` no longer samples the prior `Incursa.Quic.Http3.Http3Request` row, so treat this as targeted allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: cached small fixed HTTP/3 responses now cache complete HEADERS+DATA frame bytes and write them with one final stream write when the combined frame bytes fit the existing response write chunk size. `Incursa.Quic.Tests` Release build passed, direct cache-path tests passed 2/2, the broader focused HTTP/3 filter passed 175/177 with 1 skip and one known close-path timeout flake whose exact rerun passed 2/2, and source-backed ProtocolLab run `codex-h3-1kb-complete-response-frame-cache-20260709a` passed validation for `http3.payload.bytes.1kb` at c16-s10 with zero failed/timeout requests. The counters pass sampled 7,290.1 req/s and p95 38.313 ms, while the GC-trace pass sampled 7,460.2 req/s and p95 32.524 ms; treat those as local single-run evidence only. Allocation analysis still samples `Http3Server.<WriteResponseAsync>`, but the prior two-write `QuicConnectionRuntime.WriteStreamAsyncCore` stream-action row dropped from 88 sampled events in `codex-h3-1kb-listener-bound-endpoint-cache-allocations-20260709a` to 19 in `codex-h3-1kb-complete-response-frame-cache-allocations-20260709a`, consistent with the intended one-write response path.
- 2026-07-09: `QuicListenerHost` now captures the socket's concrete bound local endpoint once after `Bind` and reuses it in the listener receive/send hot paths instead of repeatedly querying `socket.LocalEndPoint`. `Incursa.Quic.Tests` Release build passed, focused listener-host/sample tests passed 67/67, and source-backed H3 profile pack `codex-h3-1kb-listener-bound-endpoint-cache-20260709a` passed ProtocolLab validation for `http3.payload.bytes.1kb` at c16-s10 with 5,371.4 req/s, p95 56.651 ms, and zero failed/timeout requests. GC-trace analysis still shows the larger listener endpoint/address rows from framework packet-information and remote-endpoint materialization, so treat this as code-review-backed hot-path hygiene, not a measured top-row reduction.
- 2026-07-09: HTTP/3 request stream dispatch now removes completed bidirectional request streams from `Http3StreamDispatcher` under the existing dispatcher lock, so the dispatcher map tracks active/control streams instead of every historical request on a long-lived connection. The dispatcher also starts with a modest stream/control capacity to avoid early growth. `Incursa.Quic.Tests` Release build passed, focused dispatcher/RFC 9114 stream-mapping tests passed 32/32, and source-backed H3 GC-trace analysis `codex-h3-1kb-dispatcher-cleanup-allocations-20260709a` no longer samples the request-registration `Entry[ulong,Http3StreamDispatcher.StreamState][]` resize row that was visible in `codex-h3-1kb-dispatcher-capacity-allocations-20260709a`; only the intentional constructor capacity allocation remains. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 5,495.7 req/s, p95 53.98 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: HTTP/3 static response helpers now use immutable-response construction in two caller-owned cases: `Http3InMemoryRouteHandler` copies route bodies once at registration, then stores a cache-enabled immutable response, and the TechEmpower sample borrows its private static payload arrays instead of defensively copying response bodies on every request. `Incursa.Quic.Tests` Release build passed, and focused route/sample tests passed 6/6. A source-backed ProtocolLab H3 profile pack `codex-h3-1kb-immutable-response-bodies-20260709a` also passed validation with zero failed/timeout requests, but it exercises the ProtocolLab adapter path rather than the TechEmpower sample, so treat this as code-review-backed allocation hygiene plus focused tests, not publishable throughput proof.
- 2026-07-09: stream runtime observers now support an internal interface callback so production `QuicStream` facades register themselves without allocating an instance-method `Action<QuicStreamNotification>` delegate, while the existing action-based internal test hook remains available. `Incursa.Quic`/test Release builds passed, focused stream-observer/API tests passed 17/17, broader stream/write tests passed 80/80, and source-backed H3 GC-trace analysis `codex-h3-1kb-stream-observer-interface-allocations-20260709a` no longer sampled the `QuicStream..ctor` `System.Action<QuicStreamNotification>` row seen in `codex-h3-1kb-write-gate-fastpath-allocations-20260709a`. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 5,219.6 req/s, p95 52.025 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: uncontended stream writes now use a lightweight interlocked write-gate fast path and lazily materialize the `SemaphoreSlim` wake signal only when a second writer contends for the stream. `Incursa.Quic`/test Release builds passed, focused stream/write requirement tests passed 20/20, broader stream/write tests passed 80/80, and source-backed H3 GC-trace analysis `codex-h3-1kb-write-gate-fastpath-allocations-20260709a` no longer sampled the `QuicStream.TryWriteCoreAsync`/`get_WriteGate` `SemaphoreSlim` rows seen in `codex-h3-1kb-inline-buffered-segment-allocations-20260709a`; remaining stream `SemaphoreSlim` rows are the existing read gate and inbound accept path. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 4,972.8 req/s, p95 69.446 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: stream receive buffering now stores the common single buffered segment inline in `StreamState` and allocates the overflow `List<BufferedSegment>` only when a stream has multiple buffered segments. `Incursa.Quic` Release build passed, focused receive/read/stream requirement tests passed 232/232, and source-backed H3 GC-trace analysis `codex-h3-1kb-inline-buffered-segment-allocations-20260709a` no longer sampled the `List<BufferedSegment>` stream-creation row seen in `codex-h3-1kb-byte-range-struct-allocations-20260709a`; remaining stream-state rows are the owning `StreamState` objects and dictionary growth. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 6,174.7 req/s, p95 43.392 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: stream state now embeds sent/received `QuicByteRangeSet` trackers as mutable struct fields instead of allocating two heap tracker objects per stream. `Incursa.Quic` Release build passed, focused byte-range/stream-state/send tests passed 254/254, and source-backed H3 GC-trace analysis `codex-h3-1kb-byte-range-struct-allocations-20260709a` no longer sampled the `QuicByteRangeSet` object allocation rows seen in `codex-h3-1kb-byte-range-snapshot-inline-allocations-20260709a`; remaining stream-state rows are the owning `StreamState` objects and collection growth. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 6,755.3 req/s, p95 32.240 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: stream send-state rollback snapshots now store empty and single sent byte ranges inline in `QuicByteRangeSetSnapshot`, avoiding the common one-range `QuicByteRange[]` allocation before each reserved stream write while preserving multi-range array snapshots for uncommon fragmented ranges. `Incursa.Quic` Release build passed, focused byte-range/stream-send/rollback tests passed 224/224, and source-backed H3 GC-trace analysis `codex-h3-1kb-byte-range-snapshot-inline-allocations-20260709a` no longer sampled the `QuicByteRangeSet.CaptureSnapshot` `QuicByteRange[]` row seen in `codex-h3-1kb-stream-observer-inline-allocations-20260709a`; remaining `QuicByteRangeSet` rows are stream-state object creation. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 6,446.4 req/s, p95 38.317 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: stream observer registrations now store the common single observer inline in `QuicStreamObserverDirectory`, allocating an observer array only when a stream has multiple observers and removing the per-stream `QuicStreamObserverSet` plus private lock object. `Incursa.Quic` Release build passed, focused stream observer/API tests passed 25/25 with 3 existing skips, and source-backed H3 GC-trace analysis `codex-h3-1kb-stream-observer-inline-allocations-20260709a` no longer sampled the `QuicStreamObserverSet`, `QuicStreamObserverDirectory.GetOrAdd`, or `RegisterStreamObserver` allocation rows seen in `codex-h3-1kb-shard-reusable-timer-allocations-20260709a`; the remaining stream-observer cost is the per-stream `Action<QuicStreamNotification>` delegate. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 6,490.5 req/s, p95 35.682 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: runtime shard deadline waits now use a reusable shard-owned timer wake-up instead of allocating `Task.Delay`, `Task.WhenAny`, and `WaitToReadAsync().AsTask()` work on each timed idle wait. `Incursa.Quic` Release build passed, focused CRT scheduler/shard tests passed 13/13, and source-backed H3 GC-trace analysis `codex-h3-1kb-shard-reusable-timer-allocations-20260709a` no longer sampled the `QuicConnectionRuntimeShard.<ConsumeInboxAsync>` `Task<Task>`, `OperationCanceledException`, `ValueTaskSourceAsTask<bool>`, or `WaitingReadAsyncOperation` rows seen in `codex-h3-1kb-adapter-target-span-allocations-20260709a`; the only remaining `DelayPromise` hit is from receive-buffer-pool diagnostics sampling. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 6,467.4 req/s, p95 33.544 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: ProtocolLab Incursa HTTP/3 adapter request-target parsing now uses a readonly value-type target model and span-based `/bytes/{size}` parsing, avoiding per-request `RequestTarget` object materialization and a substring allocation on fixed payload scenarios. The source-backed adapter Release build passed, focused `IncursaHttp3AdapterConformanceTests` passed 5/5, and source-backed H3 GC-trace analysis `codex-h3-1kb-adapter-target-span-allocations-20260709a` no longer sampled the `RequestTarget.Parse` allocation row or `IncursaHttp3RequestHandler.HandleGet` substring row seen in `codex-h3-1kb-adapter-cache-no-closure-allocations-20260709a`. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 6,413.1 req/s, p95 40.515 ms, and zero failed/timeout requests. Treat this as harness-allocation cleanup and trace hygiene.
- 2026-07-09: ProtocolLab Incursa HTTP/3 adapter static binary response caching now avoids a hot-path `ConcurrentDictionary.GetOrAdd` closure and delegate allocation for cached `/plaintext`, `/json`, and fixed `/bytes/*` responses. `Incursa.ProtocolLab.Adapters.IncursaHttp3` Release source-backed build passed with `PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT=C:\shared\src\incursa\quic-dotnet`, and focused `IncursaHttp3AdapterConformanceTests` passed 5/5. Source-backed H3 GC-trace analysis `codex-h3-1kb-adapter-cache-no-closure-allocations-20260709a` removed the sampled `IncursaHttp3RequestHandler.Binary` display-class and `Func` allocation rows seen in `codex-h3-1kb-stream-trywrite-valuetask-allocations-20260709a`; ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 6,137.5 req/s, p95 44.564 ms, and zero failed/timeout requests. Treat this as harness-allocation cleanup and trace hygiene, not a quic-dotnet runtime throughput claim.
- 2026-07-09: stream-level try-write now avoids the `TryWriteCoreAsync` async state machine when the per-stream write gate and runtime write complete synchronously, leaving suspended writes on smaller helper paths that still own gate release. `Incursa.Quic` Release build passed, focused stream/write/send-runtime tests passed 1,382/1,382, and source-backed H3 GC-trace analysis `codex-h3-1kb-stream-trywrite-valuetask-allocations-20260709a` removed the sampled `QuicStream.<TryWriteCoreAsync>` async-state-machine row seen in `codex-h3-1kb-write-core-valuetask-allocations-20260709a`; the remaining delayed-write helper row sampled 61 events versus the prior 78-event stream try-write row. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 5,987 req/s, p95 44.709 ms, and zero failed/timeout requests. Two full-suite attempts only hit non-deterministic HTTP/3 close-path timeout cases, and each exact failed-case rerun passed. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: stream API write requests now return the runtime's pooled `IValueTaskSource<bool>` directly on the common single-chunk try-write path instead of wrapping it in an allocating `WriteStreamAsyncCore` async state machine; the pooled completion source owns cancellation registration until result consumption. `Incursa.Quic` Release build passed, rebuilt focused stream/write/send-runtime tests passed 1,382/1,382, and full `Incursa.Quic.Tests` passed 9,322/9,327 with 5 skips after stale ECN/path-validation and lock-field structural assertions were aligned with prior runtime changes. Source-backed H3 GC-trace analysis `codex-h3-1kb-write-core-valuetask-allocations-20260709a` removed the sampled `QuicConnectionRuntime.<WriteStreamAsyncCore>` async-state-machine row seen in `codex-h3-1kb-flow-payload-pool-allocations-20260709b`. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 5,929.125 req/s, p95 48.930 ms, and zero failed/timeout requests. Overall sampled bytes increased in this single local trace, so treat this as targeted allocation-stack evidence, not publishable throughput proof.
- 2026-07-08: `152fda3c` removed disabled application-send diagnostic string allocations on the stream write hot path. Source-backed ProtocolLab profile pack `codex-h3-1kb-post-log-handler-20260708a` showed `http3.payload.bytes.1kb` request rate +2.24%, p95 -0.92%, allocation rate -29.97%, and bytes/request -31.51% versus `codex-h3-1kb-post-data-frame-20260708a`.
- 2026-07-08: `7c083271` added a queued inbound stream accept fast path. Source-backed ProtocolLab profile pack `codex-h3-1kb-post-accept-fastpath-20260708a` showed request rate +11.28%, p95 -18.03%, and bytes/request -1.17% versus `codex-h3-1kb-post-log-handler-20260708a`; allocation rate rose +9.98% while total throughput increased.
- 2026-07-08: exception attribution run `codex-exception-attribution-post-accept-fastpath-20260708a` for `http3.payload.bytes.64kb` passed ProtocolLab validation and benchmark with 22,992 EventPipe events, zero lost events, and zero first-chance exceptions.
- 2026-07-08: CoreProtocolLab smoke lane now defaults HTTP/3 to `http3.core.status` and raw QUIC to `quic.transport.multiplex.100x64kb`. Smoke run `codex-core-lane-status-smoke-20260708a` passed both ProtocolLab cells; the heavier `http3.payload.bytes.64kb` managed-load run remains a confidence/profile pressure scenario after surfacing premature-response shutdown noise under the one-second smoke window.
- 2026-07-08: baseline reporting now supports `-ImplementationId` filtering so Incursa current baselines can be reviewed separately from peer implementation/declaration inventory rows.
- 2026-07-08: allocation hotspot rollup `codex-h3-1kb-hotspots-20260708a` compared the post-data-frame, post-log-handler, and post-accept-fastpath 1KB H3 profile packs. The latest row held bytes/request roughly flat at 11,613 B while increasing request rate to 4,661 req/s and lowering p95 to 69.85 ms.
- 2026-07-08: `07bbc6d` in `protocol-lab-internal` fixed source-backed H3 benchmark builds so implementation targets are built with `PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT` already set, and hardened managed H3 load deadlines so started requests drain under `HttpClient.Timeout`. `505bef2f` in `quic-dotnet` enforced path maximum datagram size for stream sends, aborts failed HTTP/3 response writes instead of disposing partial responses as FIN, and raised HTTP/3 response QUIC write chunks to 4 KiB. Source-backed repeat run `codex-h3-64kb-c1s1-source-repeat-20260708a` passed 3/3 `http3.payload.bytes.64kb` cells with 4,217/4,217 requests and 0 failures.
- 2026-07-08: exception attribution wrapper now uses the generic source-backed ProtocolLab benchmark path for both HTTP/3 and raw QUIC, emits `incursa.quic.exception-attribution-run.v2` run metadata with commit/source-mode/load-shape fields, and analyzes every emitted `trace.nettrace`. Smoke evidence: `codex-exception-attribution-generic-h3-20260708d` passed `http3.payload.bytes.64kb` with 1 trace, 28,830 events, 0 lost events, and 2,387 first-chance exceptions; `codex-exception-attribution-generic-raw-20260708a` passed `quic.transport.stream-throughput.1mb` with 1 trace, 17,875 events, 0 lost events, and 354 first-chance exceptions.
- 2026-07-08: duplicate FIN completion over already closed send states is now idempotent inside the runtime while post-FIN data writes still throw. Focused requirement test `REQ_QUIC_RFC9000_S2P4_0004` passed, and raw QUIC attribution run `codex-exception-attribution-raw-finish-idempotent-20260708b` passed `quic.transport.stream-throughput.1mb` with 1 trace, 16,546 events, 0 lost events, and 17 first-chance exceptions; the previous `The writable side is already completed.` group disappeared.
- 2026-07-08: inbound stream and DATAGRAM queues now complete without faulting while preserving stored terminal exceptions for public API translation. Focused API/stream tests passed, and H3 attribution run `codex-exception-attribution-h3-nonfaulting-queues-20260708a` passed `http3.payload.bytes.64kb` with 1 trace, 30,742 events, 0 lost events, and a single runtime `OperationCanceledException` group with no Incursa frame; the prior Incursa-attributed terminal accept/read groups disappeared.
- 2026-07-08: the raw ProtocolLab server now uses the internal non-throwing stream accept/read APIs through explicit friend access, preserving public API terminal exceptions for user code while keeping the source-backed performance harness off the public exception path. Focused raw-server build and package-template test passed; raw attribution run `codex-exception-attribution-raw-try-server-20260708a` passed `quic.transport.stream-throughput.1mb` and removed the prior terminal `AcceptInboundStreamSlowAsync` and `ReadCoreAsync` groups from the raw server trace.
- 2026-07-08: outbound ECN marking is now gated on receive-side ECN metadata support, and socket-option failures that prove an ECN option unsupported are cached process-wide. Focused ECN/recovery tests passed, and raw attribution run `codex-exception-attribution-raw-ecn-disabled-20260708a` passed `quic.transport.stream-throughput.1mb` with 1 trace, 14,745 events, 0 lost events, and 1 first-chance exception; the prior `QuicSocketEcnControl.TrySetSocketOption` group disappeared.
- 2026-07-08: performance lane runs now emit `lane-summary.json` with schema `incursa.quic.performance-lane-summary.v1`, preserving lane identity, git state, load shape, selected commands, ProtocolLab run roots, validation/benchmark health, failure categories, metric medians/ranges, relative ranges, and publishability blockers. Dry-run proof `codex-lane-json-dryrun-20260708g` emitted failure category `none` and a UTC `generatedAtUtc` timestamp; source-backed core smoke proof `codex-lane-json-smoke-20260708a` passed HTTP/3 `http3.core.status` and raw QUIC `quic.transport.multiplex.100x64kb`, each with validation passed, benchmark succeeded, observed repetitions 1/1, and failure category `none`.
- 2026-07-08: connection runtime inbox shutdown and internal stream-accept cancellation now use non-throwing completion paths while preserving the public accept cancellation exception contract. Focused tests passed, and H3 attribution improved from `codex-exception-attribution-h3-current-20260708a` at 7,631 first-chance exceptions to `codex-exception-attribution-h3-tryaccept-cancel-20260708a` at 1 first-chance exception for the same source-backed `http3.payload.bytes.64kb` load shape.
- 2026-07-08: HTTP/3 lifecycle diagnostics now have an optional fast path for metrics-only sinks, and the ProtocolLab Incursa HTTP/3 adapter uses it for active request counters. Focused HTTP/3 diagnostics tests passed. Short source-backed profile pack `codex-h3-1kb-lifecycle-fastpath-20260708b` passed H3 protocol proof for `http3.payload.bytes.1kb`; GC TopN no longer lists `EmitRequestStartedDiagnostic` as an allocation source, while `Http3Server.EmitFrame(...)` remains a separate diagnostic-event allocation target. This was a single local validation sample, not publishable benchmark evidence.
- 2026-07-08: HTTP/3 diagnostics now support kind-aware filtering, and the ProtocolLab Incursa HTTP/3 adapter suppresses frame, QPACK, settings, stream, and response lifecycle diagnostics it does not consume. Focused filter/lifecycle diagnostics tests passed. Short source-backed profile pack `codex-h3-1kb-diagnostic-filter-20260708a` passed H3 protocol proof for `http3.payload.bytes.1kb`; GC TopN no longer lists `EmitFrame`, lifecycle diagnostic helpers, or `Http3DiagnosticEvent` allocations. The next observed allocation lead is unidirectional stream handling/string construction. This was a single local validation sample, not publishable benchmark evidence.
- 2026-07-08: server-side unidirectional stream type parsing now lets `Http3StreamDispatcher` report consumed stream-type bytes, avoiding the previous server-side stream-type buffer/copy before handing initial payload to control/QPACK stream handling. Focused dispatcher/server tests passed; a first broad server-class run saw close-path timeouts under load, but the affected close-path tests passed when rerun directly. Short source-backed profile pack `codex-h3-1kb-uni-stream-type-20260708a` passed H3 protocol proof for `http3.payload.bytes.1kb`; GC TopN no longer lists the previous `String.Concat` allocation entry, while the short-run allocation rate stayed effectively flat versus `codex-h3-1kb-diagnostic-filter-20260708a`.
- 2026-07-08: `Http3ServerResponse.CreateFromImmutableBodyAndHeaders` now lets callers with immutable header collections avoid the defensive header copy, and the ProtocolLab Incursa HTTP/3 adapter uses it for per-response benchmark headers. Focused response factory tests and source-backed adapter build passed. Short source-backed profile pack `codex-h3-1kb-response-header-borrow-20260708a` passed H3 protocol proof for `http3.payload.bytes.1kb`; GC TopN no longer lists the previous `Enumerable.ICollectionToArray` or response-header copy entries, while the short-run allocation rate remained roughly flat.
- 2026-07-08: performance triage script `Compare-QuicProtocolLabRuns.ps1` now compares two retained ProtocolLab aggregate runs by implementation/scenario and emits markdown plus JSON for validation, benchmark status, throughput/request rate, latency, allocation, GC, exceptions, CPU, warnings, repetitions, qlog/counter presence, and evidence quality changes.
- 2026-07-08: `Invoke-QuicPerformanceLane.ps1` now accepts explicit HTTP/3 and raw QUIC connection/stream load-shape overrides so confidence lanes can run high-concurrency small-payload scenarios such as `http3.payload.bytes.1kb` at c32 without editing the script.
- 2026-07-08: confidence run `codex-lane-h3-c32-confidence-20260708a` proved `http3.payload.bytes.1kb` at c32 with 9/9 validation and benchmark success, median 6,759.981 requests/s, p95 5.845 ms, and captured counters for all repetitions. The paired raw QUIC cell failed 3/9 repetitions, so the lane wrapper now supports `-SkipHttp3ProtocolLab` and `-SkipRawQuicProtocolLab` to produce focused confidence evidence without coupling unrelated instability.
- 2026-07-08: exception attribution run `codex-exception-attribution-h3-c32-20260708a` for the same H3 c32 small-payload shape passed validation with 19,148 trace events, zero lost events, and zero first-chance exceptions. Treat the confidence-lane counter exception-rate field as suspect for this shape unless a matching exception trace reproduces it.
- 2026-07-08: raw QUIC attribution run `codex-exception-attribution-raw-multiplex-c1-20260708a` passed validation for `quic.transport.multiplex.100x64kb` with 102,866 trace events, zero lost events, and 21,211 first-chance exceptions. The dominant cancellation group had no Incursa frame; Incursa-attributed groups were 3 AES-GCM authentication tag misses and 2 remote-close socket exceptions. Do not treat this as a proven quic-dotnet hot-path fix until a trace points the cancellation group at an Incursa call path.
- 2026-07-08: exception attribution schema v2 now classifies groups as project-attributed, external-attributed, runtime-only, or runtime-only-cancellation and reports actionable exception counts separately from total first-chance exceptions. Reanalysis of retained H3 64KB trace `codex-exception-attribution-h3-64kb-current-20260708a` found 2,392 first-chance exceptions, all `runtime-only-cancellation`, with zero actionable/project-attributed exceptions. This keeps channel cancellation noise visible without treating it as a quic-dotnet hot-path fix.
- 2026-07-08: schema v2 reanalysis of retained raw QUIC trace `codex-exception-attribution-raw-multiplex-c1-20260708a` found 21,211 first-chance exceptions, but only 5 actionable/project-attributed exceptions: 3 authentication tag misses and 2 remote-close socket exceptions. The remaining 21,206 were runtime-only cancellation. Treat broad exception-count work as mostly closed for this slice; future cleanup should target newly project-attributed groups, not aggregate cancellation totals.
- 2026-07-08: `d18bd3b` in `protocol-lab-internal` caches immutable Incursa HTTP/3 adapter responses for `/plaintext`, `/json`, and fixed `/bytes/{1kb,64kb,1mb}` benchmark paths so the harness no longer rebuilds response objects and headers for every static payload request. Focused source-backed smoke `codex-h3-1kb-static-response-cache-smoke-20260708a` passed validation and benchmark execution for `http3.payload.bytes.1kb` at c16-s10 with 4,138 req/s and p95 86.9 ms; this is validation evidence only, not a publishable performance comparison.
- 2026-07-08: `492eafeb` made immutable `Http3ServerResponse` instances lazily cache their encoded HEADERS frame so static benchmark responses do not re-run QPACK field-section encoding and HTTP/3 HEADERS frame allocation on every request. Focused response factory tests and source-backed profile pack `codex-h3-1kb-response-owned-headers-frame-cache-profile-20260708a` passed. Versus `codex-h3-1kb-static-response-cache-profile-20260708a`, the local single-run sample reduced bytes/request from 10,795.93 B to 10,435.61 B and p95 from 70.40 ms to 59.66 ms, while request rate fell from 4,959.75 to 4,533.13 req/s. Treat this as allocation/latency evidence, not a publishable throughput claim.
- 2026-07-08: immutable small fixed-body responses now cache the complete single DATA frame when the body fits within one response write chunk, avoiding one per-request frame allocation and one response-body write call for 1KB static payloads. Focused response factory tests and source-backed profile pack `codex-h3-1kb-small-data-frame-cache-profile-20260708a` passed. Versus `codex-h3-1kb-response-owned-headers-frame-cache-profile-20260708a`, the local single-run sample reduced bytes/request from 10,435.61 B to 9,374.16 B and allocation rate from 47.31 MB/s to 41.72 MB/s, with request rate down 1.83% and p95 higher. A 3-repetition source-backed repeat `codex-h3-1kb-small-data-frame-cache-repeat-20260708a` passed validation and benchmark execution 3/3, with median 4,433 req/s, median p95 78.19 ms, and median allocation rate 40.76 MB/s; variance blocked publishable claims.
- 2026-07-08: ACK processing now streams ACK ranges directly instead of materializing a per-ACK `HashSet<ulong>` plus `List<ulong>` before acknowledging sent packets. Focused ACK/ACK-codec tests and source-backed profile pack `codex-h3-1kb-ack-streaming-profile-20260708a` passed. Versus `codex-h3-1kb-small-data-frame-cache-profile-20260708a`, the local single-run sample removed the prior `HandleAckFrame` allocation groups from allocation attribution, reduced bytes/request by 22.86%, reduced allocation rate by 16.00%, reduced p95 by 14.81%, and raised request rate by 8.89%. Treat this as local diagnostic evidence, not publishable benchmark evidence.
- 2026-07-08: deadline scheduler stale-entry compaction now clears and rebuilds the existing priority queue instead of allocating a new queue during compaction. Focused CRT deadline scheduler tests and source-backed profile pack `codex-h3-1kb-scheduler-clear-profile-20260708a` passed. Versus `codex-h3-1kb-ack-streaming-profile-20260708a`, the local single-run sample removed the prior `CompactStaleEntriesIfNeeded` priority-queue array allocation group, reduced allocation rate by 17.71%, and reduced bytes/request by 12.78%; request rate and p95 moved the wrong way in the same single sample, so treat this as allocation-only diagnostic evidence.
- 2026-07-08: AES header protection now reuses the packet-protection context's ECB encryptor and fixed scratch buffers instead of calling one-shot `Aes.EncryptEcb` for each packet. Focused packet-protection/RFC 9001 tests and source-backed profile pack `codex-h3-1kb-aes-hp-reuse-profile-20260708a` passed. Versus `codex-h3-1kb-scheduler-clear-profile-20260708a`, the local single-run sample removed the prior `TryGenerateHeaderProtectionMask` `BasicSymmetricCipherLiteBCrypt` and `SafeKeyHandle` allocation groups, reduced bytes/request by 1.28%, and raised request rate by 3.43%; allocation rate rose 2.10% with the higher request rate, so treat this as local diagnostic evidence.
- 2026-07-08: ACK generation now scans `SortedList` receipts by indexed keys/values instead of key/value enumeration for ACK scheduling and ECN selection. Focused ACK/RFC 9000 tests and source-backed profile pack `codex-h3-1kb-ackgen-indexed-profile-20260708a` passed. Versus `codex-h3-1kb-aes-hp-reuse-profile-20260708a`, the local single-run sample reduced bytes/request by 2.20%, reduced p95 by 2.92%, and raised request rate by 2.68%; the GC trace lost managed stack attribution, so treat the missing ACK-generation enumerator group as weaker evidence than the metric movement.
- 2026-07-08: HTTP/3 header validation now returns a readonly value-type `Http3HeaderValidationResult` instead of allocating a tiny reference object for every successful request/response header validation. Focused HTTP/3/RFC 9114/RFC 9220 tests and source-backed profile pack `codex-h3-1kb-header-validation-result-struct-profile-20260708b` passed. Versus `codex-h3-1kb-ackgen-indexed-profile-20260708a`, local triage `codex-h3-1kb-header-validation-result-struct-compare-20260708b` showed request rate +4.25%, p95 -12.79%, allocation rate -4.71%, CPU mean -13.52%, gen0 collections 10 -> 6, and gen1 collections 2 -> 0; the counter exception-rate field and gen2 count moved the wrong way in this single sample, and the CPU TopN report hit an EventPipe read error, so treat this as local diagnostic evidence rather than publishable performance proof.
- 2026-07-08: `Http3FrameReader.Read` now avoids the temporary `List<Http3Frame>` for zero-frame and single-frame reads while preserving the public array return contract. Focused HTTP/3 frame/RFC 9114 tests passed. Short BenchmarkDotNet artifacts `codex-h3-frame-reader-single-array-baseline-20260708a` and `codex-h3-frame-reader-single-array-20260708a` showed single plaintext HEADERS reads dropping from 224 B to 136 B allocated, JSON HEADERS from 216 B to 128 B, fragmented plaintext HEADERS from 408 B to 288 B, and server-like headers-only request reads from 952 B to 864 B. Source-backed ProtocolLab spot check `codex-h3-1kb-frame-reader-single-array-profile-20260708a` passed `http3.payload.bytes.1kb` at c16-s10 with 4,865.25 req/s, p95 66.35 ms, 28,747,391.33 B/s allocation rate, and 0 failed/timeout requests. Treat timing movement as microbenchmark/local diagnostic evidence only.
- 2026-07-08: static `QPackDecoder.DecodeFieldSection(ReadOnlySpan<byte>)` now decodes directly from the caller span instead of copying the encoded field section to a temporary array before decoding. Focused QPACK/HTTP/3 field-section tests passed. Short BenchmarkDotNet artifacts `codex-qpack-static-decode-span-baseline-20260708a` and `codex-qpack-static-decode-span-20260708a` showed common static response decode allocations dropping from 792 B to 696 B and Appendix B.1 static-name-reference decode allocations dropping from 656 B to 568 B. Treat timing movement as microbenchmark evidence only; the server hot path already uses sink-based QPACK decoding.
- 2026-07-08: client response sequence validation now has an internal owned-header path so decoded QPACK response headers can be retained without a second defensive `ToArray()` copy, matching the existing request validator pattern while preserving the public copy-on-receive behavior. Focused HTTP/3 header/client/RFC 9114 tests passed. Short BenchmarkDotNet artifact `codex-response-sequence-owned-headers-20260708a` added direct client response validator coverage and measured the public defensive-copy path at 152 B/op versus 48 B/op for the owned path. Treat timing movement as microbenchmark evidence only.
- 2026-07-08: CRYPTO buffer dequeue now allocates the retained-entry list lazily, so fully consumed contiguous drain paths clear or remove consumed entries without allocating a temporary retained list. Focused CRYPTO buffer/RFC 9000/RFC 9002/CRT tests passed. Short BenchmarkDotNet artifacts `codex-crypto-buffer-lazy-retained-baseline-20260708a` and `codex-crypto-buffer-lazy-retained-20260708a` showed `BufferAndDrainMinimumCryptoStream` allocations dropping from 158.97 KB to 156.91 KB without overlap and from 177.31 KB to 175.24 KB with overlap. Treat timing movement as noisy local microbenchmark evidence only.
- 2026-07-08: CRYPTO buffer insertion now reuses a per-buffer scratch entry list instead of allocating a temporary `List<Entry>` for every frame insert. Focused CRYPTO buffer/RFC 9000/RFC 9002/CRT tests passed. Short BenchmarkDotNet artifacts `codex-crypto-buffer-lazy-retained-20260708a` and `codex-crypto-buffer-insert-scratch-20260708a` showed `BufferAndDrainMinimumCryptoStream` allocations dropping from 156.91 KB to 152.39 KB without overlap and from 175.24 KB to 159.02 KB with overlap. Timing moved in the right direction in this local short run, but treat timing movement as local microbenchmark evidence only.
- 2026-07-08: server-side HTTP/3 unidirectional stream handling now passes the initial payload slice as `ReadOnlyMemory<byte>` instead of copying it to a temporary array before immediate control/QPACK processing. `Incursa.Quic.Http3` Release build passed, the four close-path HTTP/3 tests that timed out in a broad filtered run passed on exact rerun, and source-backed smoke lane `local-quic-perf-20260708171756` passed HTTP/3 `http3.core.status` ProtocolLab validation and benchmark execution. Treat this as a correctness/proof cleanup for a small allocation site, not a publishable performance claim.
- 2026-07-08: H3 profile-pack trace passes now stop before the ProtocolLab target process tears down and propagate trace collection failures into the wrapper exit code instead of silently accepting truncated traces. The previous retained trace `codex-h3-1kb-current-profile-20260708a` failed `dotnet-trace` stop with `ServerNotAvailableException`, produced a conversion `Read past end of stream`, and parsed zero managed methods. Verification run `codex-h3-1kb-gctrace-symbolized-c16-20260708a` completed `dotnet-trace` with exit code 0; allocation analysis `codex-h3-1kb-gctrace-symbolized-c16-allocations-20260708a` parsed 800 managed methods, attributed 155,220,416 sampled bytes to project frames, and produced actionable Incursa/QPACK stack groups. This is tooling-quality evidence, not a runtime performance claim.
- 2026-07-08: pending stream-write retry now rents its sorted snapshot from `ArrayPool` instead of using LINQ `ToArray()` while mutating the pending request dictionary. `Incursa.Quic` Release build passed, focused stream/runtime tests passed 156/156, and source-backed H3 GC-trace analysis removed the prior sampled `TryRetryPendingStreamWriteRequests` `KeyValuePair<long, StreamActionRequestCompletionSource>[]` group seen in `codex-h3-1kb-gctrace-symbolized-c16-allocations-20260708a` from the post-change top 60 in `codex-h3-1kb-pending-write-pool-allocations-20260708a`. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: pending stream flow-control credit flush now rents its mutation-safe snapshot from `ArrayPool` instead of using LINQ `ToArray()`. `Incursa.Quic` Release build passed, focused stream/runtime/flow-control tests passed 255/255, and source-backed H3 GC-trace analysis removed the prior sampled `TryFlushPendingFlowControlCreditUpdates` dictionary enumerator allocation seen in `codex-h3-1kb-pending-write-pool-allocations-20260708a` from the post-change top 60 in `codex-h3-1kb-flow-credit-pool-allocations-20260708a`. The same trace still shows `QuicConnectionSendDatagramEffect` allocation from the flow-control send path, so this closes only the snapshot allocation. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: readable stream buffering now bypasses the scratch merge list when inserting the first segment or appending after the current buffered tail. `Incursa.Quic` Release build passed, focused stream/runtime/flow-control tests passed 537/537, and source-backed H3 GC-trace analysis reduced the sampled `InsertReadableBytes` `BufferedSegment[]` scratch-capacity group from 57 events in `codex-h3-1kb-flow-credit-pool-allocations-20260708a` to 28 events in `codex-h3-1kb-buffered-direct-paths-allocations-20260708a`. The group still exists for overlapping/interleaved inserts, so this is a partial allocation reduction. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: combined flow-control credit flush no longer uses LINQ `First()` to pick the pending stream-credit frame. `Incursa.Quic` Release build passed, focused stream/runtime/flow-control tests passed 255/255, and source-backed H3 GC-trace analysis removed the sampled `TryFlushPendingFlowControlCreditUpdates` `Enumerator<ulong, QuicMaxStreamDataFrame>` group seen in `codex-h3-1kb-buffered-direct-paths-allocations-20260708a` from `codex-h3-1kb-flow-credit-no-linq-first-allocations-20260708a`. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: pending stream-write retry now uses a local insertion sort over its rented snapshot instead of `Array.Sort(..., IComparer)`. `Incursa.Quic` Release build passed, focused stream/runtime/flow-control tests passed 255/255, and source-backed H3 GC-trace analysis removed the sampled `TryRetryPendingStreamWriteRequests` `System.Comparison<KeyValuePair<long, StreamActionRequestCompletionSource>>` group seen in `codex-h3-1kb-flow-credit-no-linq-first-allocations-20260708a` from `codex-h3-1kb-pending-retry-insertion-sort-allocations-20260708a`. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: sender ACK processing now removes acknowledged packets by indexed `SortedList` scan instead of allocating a temporary acknowledged-packet-number list after enumeration. `Incursa.Quic` Release build passed and focused ACK/congestion tests passed 81/81. Source-backed H3 GC-trace analysis removed the sampled `QuicSenderFlowController.TryProcessAckFrame` `Enumerator<ulong, SentPacketState>` group seen in `codex-h3-1kb-pending-retry-insertion-sort-allocations-20260708a` from `codex-h3-1kb-sender-ack-indexed-removal-allocations-20260708a`. A broader RFC9000/RFC9002 filter still surfaced two existing ECN path-validation test failures unrelated to this ACK path. Treat this as sampled allocation-stack evidence, not a publishable throughput claim.
- 2026-07-08: `QuicByteRangeSet` now keeps empty and single-range state inline instead of allocating a `List<Range>` backing store and first `Range[]` for the common contiguous stream coverage case. `Incursa.Quic` Release build passed, focused byte-range/stream/flow-control tests passed 138/138, and source-backed H3 GC-trace analysis removed the sampled `QuicByteRangeSet.Add` `Range[]` growth group and `QuicByteRangeSet.CaptureSnapshot` `QuicByteRange[]` group seen in `codex-h3-1kb-sender-ack-indexed-removal-allocations-20260708a` from `codex-h3-1kb-byte-range-single-inline-allocations-20260708a`. The larger inline owner object is still visible in allocation attribution, so treat this as a targeted storage-allocation reduction, not a broad throughput claim.
- 2026-07-08: `QuicStream` now tracks read/write closed state separately from lazily-created public `ReadsClosed`/`WritesClosed` tasks, so `CanRead`, `CanWrite`, abort checks, disposal, and normal close paths no longer allocate a `TaskCompletionSource` just to test closure. `Incursa.Quic` Release build passed, focused lifecycle/API tests passed 61/61, and source-backed H3 GC-trace analysis removed the sampled `QuicStream.get_WritesClosedTcs` `TaskCompletionSource<object?>` group seen in `codex-h3-1kb-byte-range-single-inline-allocations-20260708a` from `codex-h3-1kb-close-task-lazy-allocations-20260708a`. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-08: `QuicAddressFormatting` now keeps a tiny bounded per-thread cache of recently formatted address text so path identity construction can reuse remote/local address strings across repeated datagrams without retaining arbitrary peer addresses globally. `Incursa.Quic` Release build passed, focused formatting tests passed 3/3, and exact rerun of the HTTP/3 class timeout failures passed 5/5 after a broader class run showed existing close-path flakes. Source-backed H3 GC-trace analysis removed the sampled `QuicAddressFormatting.Format` string allocation group seen in `codex-h3-1kb-close-task-lazy-allocations-20260708a` from `codex-h3-1kb-address-format-cache-allocations-20260708b`. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-08: send-effect append now only clones `QuicConnectionSendDatagramEffect` when the current ECN marking differs from the effect's existing marking, avoiding a redundant record clone on the common unchanged-marking path. `Incursa.Quic` Release build passed and focused ECN/send-path tests passed 146/146. Source-backed H3 GC-trace analysis removed the sampled `QuicConnectionSendDatagramEffect.<Clone>$` group seen in `codex-h3-1kb-address-format-cache-allocations-20260708b` from `codex-h3-1kb-send-effect-no-clone-allocations-20260708a`. The actual send-effect allocation rows remain; this only removes the redundant clone. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-08: ACK frames now use a tiny per-thread runtime pool on hot parse/build paths, generated additional ACK ranges use `ArrayPool`, and ACK piggyback/send paths dispose frames after marking them sent. `Incursa.Quic` Release build passed. Focused ACK/flow-control/congestion/retransmission/stream tests passed 1820/1820 before the final failure-path disposal tightening; the final rerun of the same broad filter hit two existing HTTP/3 close-path timeout flakes, and exact rerun of those failed cases passed 3/3. Source-backed H3 GC-trace analysis `codex-h3-1kb-ack-frame-pool-allocations-20260708b` removed sampled `QuicAckFrame` and `QuicAckRange` allocation groups from the top 60 where `codex-h3-1kb-send-effect-no-clone-allocations-20260708a` had separate parse/build `QuicAckFrame` rows. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-08: HTTP/3 server request reading now has a diagnostics-safe headers-only fast path for a single complete static HEADERS frame, and lazily creates the fallback frame reader/request validator only when the general frame path is needed. `Incursa.Quic.Http3` Release build passed. The broad focused HTTP/3/QPACK/RFC 9114/RFC 9220 test filter passed 246, skipped 1, and hit two known close-path timeout flakes; exact rerun of the two failed cases passed 2/2. Source-backed H3 GC-trace analysis `codex-h3-1kb-request-fastpath-direct-allocations-20260709a` removed the sampled `Http3FrameReader.Read` payload-copy, `Http3Frame[]`, fallback `Http3FrameReader`, fallback `Http3RequestMessageValidator`, and intermediate fast-path `Http3RequestMessageValidator` allocation rows seen across `codex-h3-1kb-ack-frame-pool-allocations-20260708b` and `codex-h3-1kb-request-fastpath-lazy-allocations-20260709a`. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 5,797.5 req/s, p95 41.377 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-08: acknowledged stream-data inspection now copies distinct stream IDs into caller-provided span storage before allocating overflow, so reset-stream retransmission suppression no longer allocates a `ulong[]` for the common small stream-ID set. `Incursa.Quic` Release build passed and focused frame-inspector/send-runtime/retransmission/stream-data tests passed 389/389. Source-backed H3 GC-trace analysis `codex-h3-1kb-stream-id-span-allocations-20260709a` removed the sampled `QuicFramePayloadInspector.GetStreamDataStreamIds` `System.UInt64[]` allocation row seen in `codex-h3-1kb-request-fastpath-direct-allocations-20260709a`. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 5,386.875 req/s, p95 52.586 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-08: small HTTP/3 response write helpers now return direct `QuicStream.TryWrite*Async` `ValueTask<bool>` results for single-chunk headers, payloads, and cached DATA frames instead of allocating wrapper async state machines. `Incursa.Quic.Http3` Release build passed. The broad focused HTTP/3/RFC 9114/RFC 9220 test filter passed 193, skipped 1, and hit two known close-path timeout flakes; exact rerun of the two failed cases passed 2/2. Source-backed H3 GC-trace analysis `codex-h3-1kb-write-helper-fastpath-allocations-20260709a` removed the sampled `Http3Server.WriteFinalFrameBytesAsync`, `Http3Server.WriteFixedResponseDataFramesAsync`, and `Http3Server.WriteFrameBytesAsync` async-state-machine rows seen in `codex-h3-1kb-stream-id-span-allocations-20260709a`; the higher-level `WriteResponseAsync` and lower-level stream/runtime write state machines remain. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with 5,637.5 req/s, p95 56.242 ms, and zero failed/timeout requests. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-08: readable stream buffering now has a direct tail-extension path when an overlapping STREAM frame adds bytes beyond the current buffered tail, avoiding the scratch merge list for that common retransmission/reordering shape. `Incursa.Quic` Release build passed and focused stream receive/read/RFC 9000 stream tests passed 26/26. Source-backed H3 GC-trace analysis `codex-h3-1kb-buffered-tail-extend-allocations-20260709a` reduced the sampled `InsertReadableBytes` `BufferedSegment[]` scratch-capacity group from 19 events in `codex-h3-1kb-write-helper-fastpath-allocations-20260709a` to 14 events; other merge shapes still use the scratch path. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with zero validation failures. Treat this as partial sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: short Huffman-encoded QPACK literals now use a tiny bounded per-thread decode cache so repeated request literals can reuse decoded string instances without changing public decode semantics. `Incursa.Qpack` and `Incursa.Quic.Tests` Release builds passed, focused QPACK/HTTP3/RFC 9204 tests passed 111/111, and source-backed H3 GC-trace analysis `codex-h3-1kb-qpack-huffman-cache-allocations-20260709a` removed the sampled `QPackHuffman.Decode` `System.String` allocation group that had 22 events in `codex-h3-1kb-buffered-tail-extend-allocations-20260709a`. ProtocolLab validation passed for `http3.payload.bytes.1kb` at c16-s10 with zero validation failures. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: per-connection HTTP/3 request QPACK state now caches small Required Insert Count zero field sections by exact encoded bytes, so repeated static/literal request headers can reuse the decoded field-line list while dynamic table-dependent sections still decode normally. `Incursa.Quic.Http3` and `Incursa.Quic.Tests` Release builds passed, focused HTTP/3/QPACK/RFC 9114/RFC 9204 tests passed 129/129, and source-backed H3 GC-trace analysis `codex-h3-1kb-field-section-cache-allocations-20260709a` removed the sampled `Http3FieldLineBuffer`, `Http3FieldLineList`, and request QPACK `QPackFieldLine[]` allocation rows seen in `codex-h3-1kb-qpack-huffman-cache-allocations-20260709a`. Overall sampled bytes increased in this single local run, so treat this only as targeted allocation-stack evidence.
- 2026-07-09: peer stream-capacity release scheduling now suppresses duplicate pending `ReleaseCapacity` stream-action events per stream while preserving retry after event-post failure and deferred release flushing. `Incursa.Quic` and `Incursa.Quic.Tests` Release builds passed, focused release-capacity/stream-capacity tests passed 33/33, and source-backed H3 GC-trace analysis `codex-h3-1kb-release-capacity-hashset-allocations-20260709a` reduced the sampled `TryQueueStreamCapacityRelease` `QuicConnectionStreamActionEvent` group from 32 events in `codex-h3-1kb-field-section-cache-allocations-20260709a` to 14 events without adding a visible `HashSet<ulong>` allocation row. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: pending peer stream-capacity release flushing now rents its mutation-safe stream-id snapshot from `ArrayPool<ulong>` instead of allocating a fresh `ulong[]` through `HashSet<ulong>.ToArray()`, matching the existing pending flow-control credit flush pattern. `Incursa.Quic` and `Incursa.Quic.Tests` Release builds passed, focused release-capacity/stream-capacity tests passed 33/33, and source-backed H3 GC-trace analysis `codex-h3-1kb-peer-capacity-pool-allocations-20260709a` passed ProtocolLab validation for `http3.payload.bytes.1kb`. The prior and current traces did not sample this tiny snapshot as a visible `System.UInt64[]` row, so treat this as code-review-backed allocation hygiene plus validation evidence, not a measured top-row reduction.
- 2026-07-09: client and server socket receive loops now reuse the last concrete packet-information local endpoint instead of allocating a new `IPEndPoint` for every datagram with the same local packet address and port. `Incursa.Quic` and `Incursa.Quic.Tests` Release builds passed, focused INT endpoint-host tests passed 20/20, and source-backed H3 GC-trace analysis `codex-h3-1kb-local-endpoint-cache-allocations-20260709a` removed the sampled `QuicSocketPacketInformationControl.ResolveLocalEndPoint` `System.Net.IPEndPoint` row seen in `codex-h3-1kb-peer-capacity-pool-allocations-20260709a`. Remaining listener endpoint/address rows are attributed to framework socket endpoint materialization and address parsing. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: small retransmittable flow-control credit and peer stream-capacity release payloads now rent their padded plaintext buffers from `QuicBufferPool` and transfer ownership into sent-packet tracking, preserving exact logical payload lengths while allowing the retained plaintext buffer to return to the pool when packet tracking releases it. `Incursa.Quic` Release build passed, focused flow-control/stream-capacity/send-runtime tests passed 594/594, and source-backed H3 GC-trace analysis `codex-h3-1kb-flow-payload-pool-allocations-20260709b` removed the sampled `TryCreatePaddedApplicationPayload`, `TryBuildOutboundMaxStreamsPayload`, and `TryBuildOutboundFlowControlCreditPayload` `System.Byte[]` rows seen in `codex-h3-1kb-local-endpoint-cache-allocations-20260709a`. Treat this as sampled allocation-stack evidence, not publishable throughput proof.
- 2026-07-09: fresh source-backed H3 exception attribution `codex-exception-attribution-h3-64kb-current-20260709a` passed ProtocolLab validation and benchmark for `http3.payload.bytes.64kb` at c16-s10. The trace had 48,799 events, zero lost events, 7,366 first-chance exceptions, one group, zero actionable exceptions, zero project-attributed exceptions, and all exceptions classified as runtime-only `OperationCanceledException` cancellation noise. This keeps terminal-exception cleanup closed for project-attributed Incursa throw sites; future work should target only newly actionable groups.
- 2026-07-09: local baseline report `codex-baseline-report-current-20260709a` scanned 182 retained ProtocolLab runs and matched 158 Incursa rows. It produced current rows for `http3.payload.bytes.1kb`, `http3.payload.bytes.64kb`, `quic.transport.stream-throughput.1mb`, `quic.transport.duplex-streams`, and `quic.transport.multiplex.100x64kb`, including validation/benchmark status, primary metric, p95, allocation rate, exception rate, repetitions, previous/best comparisons, evidence quality, and publishability blockers. The report also shows all current rows remain local evidence, variance blocks publishable claims, and the selected raw multiplex current row still has validation failures.

## 1. Finish Expected Terminal Exception Cleanup

Status: closed for project-attributed terminal exceptions. Current retained and fresh HTTP/3 traces no longer show terminal `Incursa.Quic.QuicException` throw sites attributed to Incursa code. The remaining short-run exception pressure is runtime-only cancellation noise with no Incursa frame.

Reopen this item only when a new trace shows an actionable project-attributed or external-attributed exception group on a successful ProtocolLab run.

Closure evidence:

- Source-backed ProtocolLab `http3.payload.bytes.64kb` exception attribution runs now identify remaining exception groups by type, message, attribution frame, stack top frame, and first project frame.
- Expected internal HTTP/3 request, stream, accept, write, read, and cleanup paths have non-throwing terminal-flow evidence in retained attribution runs.
- Public API terminal behavior still throws where the public contract requires it, with focused tests preserved alongside the runtime changes.
- The latest H3 run has zero actionable/project-attributed exception groups; aggregate exception counters can still include runtime-only cancellation/tool shutdown noise.

## 2. Build Permanent Trace-Site Attribution

Status: closed for the local development workflow. `scripts/perf/Invoke-QuicExceptionAttribution.ps1` runs source-backed ProtocolLab scenarios with EventPipe exception capture, and `eng/tools/Incursa.Quic.TraceAnalysis` emits stable JSON and Markdown summaries grouped by exception type, message, attribution frame, stack top frame, and first project frame. `scripts/perf/Analyze-QuicExceptionTrace.ps1` handles retained traces without rerunning ProtocolLab.

Keep improving this item only if a future lab/publishable lane needs richer cross-run trend reporting or site publication of exception-attribution results.

## 3. Add Stable ProtocolLab Performance Lanes

Status: partially closed. The local `Smoke` and `Confidence` lanes exist, emit
`lane-summary.json`, label evidence quality, preserve failure categories, and
can run HTTP/3 plus raw QUIC source-backed ProtocolLab slices. ProtocolLab now
also emits evidence bundles, artifact manifests, failure reason codes,
source/package parity gates, variance-aware quality, and publishability
readiness blockers. The remaining gap is an actual isolated hosted run that
satisfies those gates, not missing runner infrastructure.

Remaining work:

- Run the same lane/surface vocabulary on an isolated hosted worker.
- Capture and satisfy explicit CPU, memory, network, host isolation,
  load-generator, package identity, and readiness controls in that run.
- Keep local lanes diagnostic/report-only unless publishability gates pass.

## 4. Establish Baseline Dashboards For Key Scenarios

Status: partially closed for local file-based reporting, controller publication
dry-run handoff, and public report import. `scripts/perf/New-QuicProtocolLabBaselineReport.ps1`
rolls retained ProtocolLab runs plus explicit or auto-discovered repo-local
controller aggregate artifact wrappers into JSON and Markdown reports for the
current core scenarios. `scripts/perf/Invoke-QuicProtocolLabPublication.ps1`
can dry-run the existing controller publication endpoint for completed
package-backed jobs so public-bundle readiness is repeatable before upload.
ProtocolLab site/import now carries evidence quality, hotspot trends, artifact
links, source/package provenance, and diagnostic-only wording through the public
report path. Current local evidence still has variance and isolation blockers.
The stale raw-multiplex validation blocker has a clean package-backed
replacement row in `codex-package-backed-raw-baseline-20260709a`, and that
replacement is now visible in default-style reports such as
`codex-baseline-auto-repo-aggregates-20260709a`.

Current local coverage:

- `http3.payload.bytes.1kb` high-concurrency local confidence row is present.
- `http3.payload.bytes.64kb` local repeat row is present.
- `quic.transport.stream-throughput.1mb` raw QUIC row is present.
- `quic.transport.duplex-streams` raw stream fanout row is present.
- `quic.transport.multiplex.100x64kb` package-backed confidence row is clean for validation and benchmark execution, but still variance-blocked for publishable claims.
- Reports include validation, benchmark status, primary metric, p95, allocation rate, exception rate, repetitions, previous/best comparisons, evidence quality, and publishability blockers.

Remaining work:

- Promote only intentionally selected diagnostic reports through upload/import after operator review; the import path exists, but publication policy should stay explicit.
- Decide whether local baseline reports need a separate dashboard path or should remain development-only rollups beside controller public reports; repo-local controller aggregate wrappers are now discoverable in the development rollup either way.
- Keep publishability blockers visible until lab variance and provenance gates are resolved.

## 5. Reduce HTTP/3 Allocation Pressure

Status: closed for the current local trace-driven allocation pass. The latest
short source-backed 1KB and 64KB HTTP/3 allocation traces both have zero
project-attributed/actionable allocation groups; they only sampled
runtime/EventPipe metadata rows. Earlier trace-driven work in this file already
targeted request/response frame handling, buffer ownership, QPACK field
materialization, and per-request object churn. Reopen this item when a fresh
ProtocolLab allocation trace shows a new actionable Incursa-attributed group, or
when isolated lab evidence contradicts the local diagnostic traces.

The next likely gains are in request/response frame handling, buffer ownership, QPACK field materialization, and per-request object churn.

Done when:

- Allocation traces identify the top HTTP/3 allocation sites for 1KB and 64KB payload scenarios. Current traces have no actionable project-attributed groups; prior trace-driven top rows were either fixed or folded into the explicit no-change rationale above.
- At least the top three avoidable allocation sources have targeted fixes or are explicitly accepted with rationale. The current top sampled groups are accepted as runtime/EventPipe metadata noise, not runtime code targets.
- Benchmarks show lower allocation rate without throughput or correctness regressions. Current local evidence is diagnostic and non-publishable, but the sequence of committed allocation cleanups has retained ProtocolLab validation and focused correctness tests while reducing public-stream and HTTP/3 sampled allocation hot rows.
- Full HTTP/3 tests pass after each allocation-focused change. Focused HTTP/3 and requirement-home slices are recorded in the progress notes for each runtime change; current no-code scout has ProtocolLab validation and benchmark proof.

## 6. Tighten Stream Lifecycle Cleanup

Status: closed for the current local stream terminal-cleanup pass. Stream
observer drains now use non-throwing terminal paths for expected connection
termination, disposal, cancellation, operation abort, and peer stream abort.
Stream read lifecycle tests cover normal EOF, waiting read cancellation, peer
read abort, terminal observer drain suppression, and disposal release. Existing
runtime tests cover idempotent capacity-release scheduling and post-failure
retry. The latest source-backed HTTP/3 shutdown/observer exception-attribution
smoke reports zero exception groups, so there is no current actionable terminal
cleanup exception pressure.

Reopen this item when a fresh trace shows a project-attributed terminal cleanup
exception group, or when a new lifecycle scenario lacks focused public/internal
coverage.

Stream disposal, final-write completion, read-side completion, and observer notification are still complicated. They are likely hiding both exception pressure and extra work.

Done when:

- Stream disposal has non-throwing internal cleanup paths for expected terminal states. Current disposal cleanup is best-effort, unregisters stream observers, releases pending reads, and focused tests cover pending-read disposal release.
- Stream observer unregister, capacity release, and read/write completion are idempotent and covered by focused tests. Capacity-release duplicate suppression/retry tests and read/write closed completion paths are covered by the focused stream/runtime slice.
- ProtocolLab shutdown traces do not show repeated terminal cleanup exceptions. `codex-h3-terminal-stream-abort-suppression-20260709a` reported zero exception groups.
- Stream lifecycle tests cover normal EOF, reset, connection close, disposal, and cancellation separately. Current focused coverage includes EOF, reset/read-abort, terminal observer drain, connection terminal notification via requirement-home tests, disposal, and cancellation.

## 7. Add Raw QUIC Performance Proof

HTTP/3 tells us end-to-end behavior, but raw QUIC scenarios are needed to isolate transport performance from QPACK and HTTP/3 framing.

Status: partially closed for local smoke-lane coverage. `RawQuicStreamThroughput`,
`RawQuicMultiplex`, and `RawQuicDuplex` now expose distinct source-reference
raw QUIC ProtocolLab surfaces. The stream-throughput lane has successful
single-repetition smoke proof with optional counter capture for throughput,
allocation, GC, exception-rate, CPU, and validation fields. Upload-only
bidirectional stream measurement now uses clean FIN/EOF semantics rather than
client-side STOP_SENDING cancellation, and current c1/s4 single-repetition
source-backed runs pass with and without counter capture. Connection-level
partial-upload stalls caused by dropped flow-control credit now have a bounded
`DATA_BLOCKED`/`MAX_DATA` replay fix. The remaining repeated long-run stall was
caused by rejecting a valid acknowledged peer key update while older
packet-protection material remained on a PTO-derived retention timer. The
authenticated replacement path now discards that obsolete retained generation
before installing the successor, and the final uninstrumented three-repetition
c1/s4 run passed 3/3 with zero failed or timed-out requests. Package-backed
rack-lab smoke proof validates the same stream-throughput scenario through
admitted implementation, test-executor, and scenario-pack packages, and repeated
package-backed proof validates 3/3 repetitions. Package-backed multiplex and
duplex repeats also validate and benchmark 3/3 with zero failed or timeout
requests. The package-backed repeats are still variance-blocked and lack runtime
counters, so they are regression evidence only. A c1/s4 diagnostic shape is
more stable for single-run throughput than c1/s1. Repeated local correctness is
now clean for the retained confidence sample, but latency/throughput variance
and readiness gates remain too weak for publishable claims.

Done when:

- `quic-dotnet-raw-dev` package/source mode can run raw stream throughput scenarios reliably. Source-reference local confidence proof and package-backed rack-lab confidence proof exist; publishable stability remains open because variance and isolation gates still block.
- Raw QUIC scenarios report throughput, allocation, GC, exception count, and validation. Closed locally for `RawQuicStreamThroughput` smoke runs when `-CaptureCounters` is used.
- At least one raw stream-throughput scenario is part of the smoke lane. Closed locally by `RawQuicStreamThroughput`.
- HTTP/3 regressions can be compared against raw QUIC results to locate whether the problem is transport or application framing.

## 8. Compare Against External Implementations Honestly

Performance only matters relative to known-good peers, but comparisons need matching scenarios and honest caveats.

Status: closed for the current local matched peer-comparison pass; hosted
publication remains open. Fresh package-backed local comparison cells now cover
`quic-dotnet-dev`, `quic-go-http3`, and the C-based `nginx-http3` implementation
for the official `http3.payload.bytes.1kb` scenario at matching c4/s4 controls
and three repetitions. All 9/9 cells passed validation and benchmarking, and the
retained QUIC-side report keeps the results local/non-publishable. ProtocolLab
classified the quic-go bundle as `confidence`; the combined Incursa/nginx bundle
remained `diagnostic` because nginx variance exceeded the publishable threshold.
ProtocolLab now emits `evidence-bundle.json`, native run comparisons, evidence
quality classifications, source/package parity verdicts, failure reason codes,
artifact manifests, and hotspot trend data. The QUIC-side retained baseline
report can still inventory older external-reference rows, but those older peer
rows predate the evidence-bundle comparison path and should not be upgraded into
publishable rankings. Treat local peer rows as diagnostic unless the run has
matching scenario, protocol, load profile, validation status, source/package
provenance, resource controls, repetition/variance proof, and readiness gates.

Remaining work is hosted isolation, readiness review, and intentional public
publication of only comparable cells. Do not compare Incursa HTTP/3 managed-load
results against raw QUIC load-tool results, and do not compare old aggregate-only
external rows against new evidence-bundle rows as if they had the same
provenance.

Done when:

- ProtocolLab runs comparable scenarios against at least quic-go and one C/Rust implementation where available.
- Comparison reports only include cells with matching protocol, workload, load tool, resource controls, and validation.
- Unsupported or non-comparable cells are explicitly labeled instead of hidden.
- Public reports show Incursa results beside comparable peers with warnings when evidence is local or non-isolated.

## 9. Build Regression Gates Without Premature Hard Thresholds

We need automated protection from obvious regressions, but local noise makes strict thresholds risky.

Status: partially closed for local lanes. `Invoke-QuicPerformanceLane.ps1` has
checked-in extreme-change rules for retained aggregate baselines, reports all
gate comparisons into `lane-summary.json`, and keeps confidence lanes
non-blocking by default. ProtocolLab now classifies repetition, variance,
validation, isolation, load controls, source mode, and readiness in each
evidence bundle. The remaining gap is enough isolated hosted evidence to set and
enforce reviewed publishable thresholds.

Done when:

- Smoke gates fail only on validation failure, infrastructure failure, or extreme metric changes.
- Confidence gates report performance movement but do not block without enough repetitions.
- Publishable gates can enforce thresholds once lab variance is understood.
- Threshold rules are checked into source control and reviewed like code.

## 10. Improve Counter And Trace Artifact Import

Status: closed for the current ProtocolLab evidence workflow. ProtocolLab now
emits `evidence-bundle.json` with validation status, benchmark metrics,
diagnostics, qlog/artifact links, source/package provenance, evidence quality,
and explicit non-publishability wording. The bundle also carries
`hotspotTrends`, allocation/exception attribution availability, and first-class
diagnostic/confidence/publishable classification. The public report path can
import and display these fields without inferring publishability from local or
diagnostic evidence.

Keep improving this item only when a new diagnostic artifact family needs to be
promoted into the standard evidence bundle, import queue, or public report
schema.

Done when:

- Counter summaries, trace summaries, qlog status, validation proof, and benchmark metrics are imported into a single evidence document. Done through `evidence-bundle.json`.
- Reports include links to raw artifacts. Done through run/cell artifact links and `artifact-manifest.json`.
- Exception type/count and allocation hot spots are first-class report fields. Done through attribution artifacts and `hotspotTrends`, with explicit unavailable reasons when traces are absent.
- The public site can show whether a run is diagnostic, confidence, or publishable. Done through evidence-quality classification; publishability remains gate-controlled.

## 11. Make Source-Backed And Package-Backed Runs Equivalent

Source-backed runs are good for development, but package-backed controller jobs are the long-term boundary.

Status: source/package identity aligned for new raw QUIC evidence. The controller can now
run the raw stream-throughput scenario from pinned package references without
rebuilding or re-uploading the implementation package. The proven package-backed
jobs use the `quic-dotnet-raw-dev` package implementation identity and record
readable package provenance. New source-backed raw runs now use the matching
`quic-dotnet-raw-dev` implementation identity through a ProtocolLab source-mode
manifest alias, so native comparison can match source/package cells for new
evidence.
The latest
package-backed repeats passed 3/3 validation and benchmark repetitions for
stream throughput, multiplex, and duplex, but are still blocked from publishable
use by variance, local shared-host execution, and missing runtime counters.
QUIC-owned package builders now record the exact source repository and full
commit in `protocol-lab.internal.json`; public package v2 remains limited to its
portable contract fields. Live controller admission and a pinned-reference
multiplex smoke prove the resulting archive is selectable and executable.
Remaining work is richer counter capture, documenting/automating the
binary-backed component package path beyond the local generated package flow,
running higher-repetition matched source/package comparisons, and moving the
same evidence onto isolated lab hardware.

Done when:

- The same scenario can run source-backed locally and package-backed on the controller with matching implementation identity. New source-backed raw performance lanes now use `quic-dotnet-raw-dev`; older retained source evidence under `incursa-raw-quic-adapter-v1` remains historical and will not match package-backed cells.
- Package manifests record the exact quic-dotnet commit, package version, build mode, and supported scenario list. The public manifest records portable package identity/capabilities, while `protocol-lab.internal.json` records the exact repository and commit used by the QUIC-owned builder.
- A package-backed run can reproduce the smoke lane on lab hardware.
- Differences between source-backed and package-backed results are understood and documented. Stream-throughput, multiplex, and duplex now have matched native smoke comparisons with source/package parity satisfied; higher-repetition and isolated-host comparisons remain open.

## 12. Add Public API Stream Transfer Benchmarks

Status: closed for the current public comparison surface.
`QuicPublicApiStreamTransferBenchmarks` and the
`QuicPublicApiSteadyStateStreamBenchmarks` suites now give the `PublicApiStream`
performance-lane surface bounded public-facade upload-only, download-only,
bidirectional request/response, sequential and concurrent many-stream
request/response, and established-connection stream comparisons between
Incursa.Quic and `System.Net.Quic`. Smoke proof
`codex-public-api-stream-smoke-20260709a` passed, expanded smoke proof
`codex-public-api-stream-expanded-smoke-20260709a` documents current Incursa
latency/allocation gaps, and focused BDN Short proof under
`.artifacts/bdn/public-concurrent-closeout-20260710` revalidated the concurrent
row against the current runtime. The current public stream profile has narrowed
the Incursa managed allocation gap from 17,135 B/op at initial diagnosis to
7,849 B/op in the latest 400-iteration Incursa-only local run.

Existing public comparison work is mostly connection establishment. We need public stream transfer workloads that compare real user-facing APIs.

Done when:

- BenchmarkDotNet includes public facade stream upload, download,
  bidirectional echo/request-response, and sequential and concurrent
  many-stream workloads.
- Incursa and `System.Net.Quic` are compared only where both can run the same public workload honestly.
- The benchmark does not use internal runtime helpers.
- Results are documented separately from HTTP/3 and raw internal transport benchmarks.

## 13. Profile Scheduler, Timers, And Send Queue Hot Paths

Status: closed for the current local trace-driven pass. 2026-07-09 added
stale-entry wait/dequeue coverage to `QuicDeadlineSchedulerBenchmarks` and
wired the deadline scheduler suite into the `RawQuicSendCore` lane beside
send-priority, queue-sorting, batch-payload, distinct-stream-id, and congestion
control. Smoke proof `codex-sendcore-deadline-scheduler-smoke-20260709a`
passed locally and produced the expected `QuicDeadlineSchedulerBenchmarks`
slice with re-arm, wait, and dequeue rows. Fresh raw multiplex and H3 c32 CPU
samples found no dominant project-owned scheduler, timer, or queue method; the
largest project execution surface was runtime-shard processing at less than 5
percent inclusive time. Reopen when an isolated or higher-concurrency trace
identifies a project-owned hot method rather than general wait/I/O pressure.

If throughput stalls under concurrency, likely culprits include send queue ordering, timer processing, ACK/loss effects, and packet assembly.

Done when:

- CPU traces identify top runtime hot paths under raw QUIC and HTTP/3 concurrency.
- Send queue and timer hot paths have BenchmarkDotNet microbenchmarks tied to real ProtocolLab scenarios. `RawQuicSendCore` now covers send queue and deadline scheduler companion suites, and can be paired with a caller-supplied raw QUIC ProtocolLab scenario.
- Changes show improvement in both microbenchmarks and at least one end-to-end scenario.
- No protocol scheduling semantics are weakened to gain speed.

## 14. Improve Buffer Pool Diagnostics And Tuning

Status: closed for the current local diagnostics and tuning pass. 2026-07-09 added
`System.Diagnostics.Metrics` instruments to the central `QuicBufferPool` wrapper
for rents, returns, rented/returned bytes, outstanding buffers/bytes, and
oversized rents using bounded `size_bucket` tags. This gives ProtocolLab counter
captures a no-code-change way to show pool pressure for any path that uses the
central wrapper. True pool misses and retained-memory accounting remain open
because `ArrayPool<byte>.Shared` does not expose those directly.
Smoke proof `codex-buffer-pool-metrics-smoke-20260709a` passed
`http3.payload.bytes.1kb` at c4-s4 with counter capture enabled; raw counter
output includes `incursa.quic.buffer_pool.rents`, `returns`, `bytes.rented`,
`bytes.returned`, `outstanding.buffers`, `outstanding.bytes`, and
`oversized_rents` rows. The current ProtocolLab `counters-summary.json` parser
does not yet roll those custom pool instruments into summary fields.
ProtocolLab commit `d1f7d57` now emits an additive
`quic-buffer-pool-summary.json` artifact, links it from `artifact-manifest.json`
and `evidence-bundle.json`, and projects top pool metrics into the evidence
bundle's `diagnostics.quicBufferPool` section without changing benchmark
semantics. `QuicMetrics` now reports outstanding buffer/byte pressure as
observable gauges instead of interval deltas, so the summary can report
non-negative current/peak pool pressure by `size_bucket`. Smoke proof
`codex-buffer-pool-gauge-summary-smoke-20260709a` passed
`http3.payload.bytes.1kb` at c4-s4 with counter capture enabled and produced a
populated pool summary with stable metric IDs, size-bucket rollups, and
non-negative outstanding gauge values.
Follow-up smoke `codex-buffer-pool-tuning-smoke-20260709a-h3-local-v1` found no
outstanding retained pool pressure in the sampled H3 1KB c4-s4 run; apparent
oversized rents were small-bucket ArrayPool rounding, so default pool-size
tuning remained unproven. A later dedicated-pool experiment retained 128
arrays per bucket through 64 KiB and was rejected: rent/return cost rose about
25 percent, median raw allocation rate regressed about 2 percent, and traced
pool-miss bytes per request rose about 11 percent. `ArrayPool<byte>.Shared`
therefore remains the evidence-backed local default. Reopen only when an
isolated workload shows a different miss/retention balance.

Buffer reuse is central to reducing allocations, but pool behavior needs better visibility.

Done when:

- Buffer pool diagnostics can be enabled per ProtocolLab run without code changes. Central-wrapper metrics are now emitted through `Incursa.Quic`.
- Reports show rent/return counts, misses, peak outstanding buffers, oversized rents, and retained memory. Rent/return counts, bytes, oversized rents, and non-negative outstanding gauge summaries are now available through the dedicated pool summary artifact and evidence-bundle diagnostics; true misses and retained memory remain open because `ArrayPool<byte>.Shared` does not expose them directly.
- The default pool choice is justified by scenario evidence: the bounded
  dedicated-pool candidate was slower and missed more per request than
  `ArrayPool<byte>.Shared`.
- Pool tuning improves allocation rate without increasing retained memory
  unreasonably. No tested tuning candidate met this condition; the rejected
  candidate and its reason are preserved rather than committed.

## 15. Keep Requirement Trace And Performance Evidence Connected

Performance changes can accidentally weaken protocol behavior. Every optimization should preserve traceability.

Status: closed for local performance-slice closeout. `New-QuicPerformanceCloseout.ps1` creates a reviewable JSON/Markdown ledger that records requirement/spec artifacts, correctness commands, requirement-home commands, SpecTrace validation/backlog notes, ProtocolLab artifacts, local performance artifacts, and git diff hygiene separately. Runtime changes still need human judgment to choose the nearest requirement artifacts.

Done when:

- Performance fixes that alter runtime behavior cite the nearest requirement/spec/verification artifact.
- Verification artifacts distinguish correctness evidence from performance evidence.
- Full test, focused requirement-home tests, ProtocolLab validation, and diff hygiene are recorded before commit.
- Known standing SpecTrace validation backlog is separated from new-change validation.

## 16. Build A Small “Performance Triage” Command

Status: closed for local retained-run closeout. `scripts/perf/Compare-QuicProtocolLabRuns.ps1`
accepts two retained ProtocolLab aggregate run roots or resolvable run IDs and emits concise
Markdown plus JSON under `.artifacts/perf-triage/{runId}`. Proof run
`codex-triage-command-proof-20260709a` compared the listener-endpoint-cache counters run with
the complete-response-frame-cache counters run, found 1 matching row with no missing or added
rows, flagged request-rate and p95 improvements, and called out allocation-rate noise as a
regressed signal. The command now also consumes adjacent `evidence-bundle.json` files when
present, surfacing evidence quality, publishability blockers, qlog status, buffer-pool
diagnostics, allocation/exception attribution availability, hotspot trend counts, and top
diagnostic groups while keeping aggregate-only retained runs compatible.

Keep improving this item only if future closeout needs cross-run trace-attribution deltas,
dashboard import, or hosted-lab integration.

Done when:

- A script accepts two ProtocolLab run IDs and compares validation, throughput, latency, allocation, GC, exceptions, CPU, and warnings.
- It emits a concise markdown report with improved/regressed/unchanged sections.
- It highlights evidence quality changes such as missing counters, missing qlogs, or lower repetition count.
- It is used in performance PR closeout.

## Suggested Order

### Accepted 2026-07-15: FIN-aware terminal receive capacity

`QuicConnectionStreamState` now rents exact capacity for newly buffered STREAM
data that reaches an already validated final size. This applies both to a
data-bearing FIN and to non-FIN data arriving after an out-of-order FIN-only
frame. Nonterminal data keeps the existing 4 KiB initial and 8 KiB continuation
coalescing capacity. The change does not compact an existing segment when a
later FIN establishes final size, because that would add a copy to reclaim an
already-rented buffer.

Deterministic proof:

- focused receive/read/ownership/metrics tests passed 51/51, including
  nonterminal coalescing, a 1 KiB terminal continuation tail, and FIN-first
  reordered data delivery, completion, and release;
- the complete Release inventory passed as a deterministic partition: the main
  partition passed 9,579 tests with five intentional skips, while the HTTP/3
  incomplete-content close and dropped-server-FIN recovery tests each passed
  5/5 independently after showing suite-order timing failures in all-in-one
  runs;
- independent review found the FIN-first and below-threshold proof gaps; both
  were fixed before closeout;
- permanent `QuicByteBufferAllocationBenchmarks` rows cover a terminal 1 KiB
  frame and a 1 KiB terminal tail after a full 4 KiB segment. Matched local
  ShortRun means were 433.3 ns versus 440.3 ns for the single terminal frame
  and 702.5 ns versus 790.5 ns for the terminal tail. Both three-iteration
  samples have very wide confidence intervals and unchanged rounded managed
  allocation, so they are retained as branch/shape guards rather than a speed
  claim.

End-to-end evidence:

- one matched c64/s100 counter pair was diagnostic and mixed: peak central-pool
  outstanding bytes fell 18 percent in the `<=16 KiB` bucket and 6 percent in
  the `<=4 KiB` bucket, while stream-write and buffered-byte tails varied in the
  opposite direction;
- five alternating exact-baseline/candidate source-backed c64/s100 runs of
  `quic.transport.multiplex.100x64kb` all passed validation and completed with
  zero failed or timed-out requests. Candidate throughput exceeded its paired
  baseline in all five accepted pairs; median throughput moved from 56.16 to
  63.63 MB/s, median p95 latency from 6,159.57 to 5,591.06 ms, and throughput
  relative range from 35.35 to 11.35 percent;
- one additional baseline attempt failed during warmup with `timeout: no recent
  network activity` and is retained as negative reliability evidence rather
  than replaced or counted as a successful repetition.

Artifacts are retained under
`protocol-lab-internal/.artifacts/runs/quic-terminal-receive-*-20260715a-*` and
the two reviewed BenchmarkDotNet roots under
`.artifacts/bdn/terminal-receive-*-reviewed-20260715a`. These are local
shared-host development results. They justify retaining the bounded runtime
change but are not publishable or peer-ranking evidence.

The next program priority is to audit the freshness and breadth of published
raw QUIC evidence before selecting another micro-optimization: map every public
row to its run date, QUIC.NET commit/package, scenario, load shape, load tool,
validation status, and matched peer evidence; then fill missing stream
throughput, multiplex, duplex, concurrency, payload-size, loss, and flow-control
workloads with current repeated baselines.

The audit is recorded in
[`raw-quic-performance-evidence-plan.md`](raw-quic-performance-evidence-plan.md).
It found that the latest public raw cohort is a non-publishable two-target,
one-repetition smoke comparison, the multiplex row does not retain the effective
100-stream shape, and the current three-target package-matrix dry-run omits
MsQuic and cannot run its duplex peer slice. Package identity, shape proof, and
three-target parity now precede further runtime micro-optimization.

### Accepted 2026-07-15: raw peer package identity and provenance

The local three-target package gap is closed without changing controller or
worker state. Incursa commit `c9cef4f1` adds cold-handshake and
connection-churn support beside throughput, multiplex, duplex, and peer matrix;
its package builder now rejects dirty package inputs by default, emits embedded
source/build provenance plus an external SHA-bound attestation, and creates
deterministic archives. ProtocolLab commit `e3165c6` provides the same evidence
contract for the distinct System.Net.Quic/MSQuic target.

Verification:

- the Incursa package/run-helper contract suite passed 20/20;
- repeated dirty-source Incursa package builds produced the same archive SHA;
- the Windows Incursa package started and its live adapter manifest reported all
  six scenarios;
- clean Incursa package `dev-c9cef4f1-clean` is parity-eligible at SHA-256
  `861326182b8b474c3ceaeed92752db10f764d36f51e4a8cfed997d7a112c4649`;
- ProtocolLab operator-script tests passed 47/47, and clean MsQuic package
  `0.1.1-dev-e3165c6` is parity-eligible at SHA-256
  `bc60e9208cc7726db680dc61e08bba79421ccff094c4fa3553fe86178a143a53`;
- both clean archives passed ProtocolLab controller package admission.

These are local package artifacts, not benchmark evidence. No upload,
deployment, campaign execution, or publication occurred. The next accepted
step requires explicit package registration followed by a fresh package-matrix
preview that resolves Incursa, quic-go, and MsQuic as three runnable targets.

### Accepted 2026-07-15: scenario-owned raw QUIC confidence matrix

ProtocolLab public-contract commit `69edaed` and internal runner commit
`ed7b177` replace the misleading single `local-comparison` QUIC shape with a
dimension-neutral `raw-quic-peer-confidence` profile. The profile fixes timing,
cooldown, five repetitions, and non-publishable evidence policy while each
scenario retains its valid stream count. Cold handshake, 1 MiB stream
throughput, 100x64 KiB multiplex, connection churn, and duplex coverage now
span c1/c4/c16/c32/c64/c128. The matched campaign includes all five workload
families and uses round-robin implementation ordering.

Verification:

- the exact public repository-health workflow passed;
- 102 load-profile, scenario, and operator-script tests passed;
- 84 raw adapter, execution, and package tests passed;
- the complete internal suite passed 1,203/1,209 tests, with the remaining six
  failures isolated to pre-existing cross-repository schema-registry and
  unrelated component-package compatibility checks;
- rerunning the failing contract class in isolation removed the registry-order
  failures and retained two unrelated `protocol-lab-components` mismatches;
- the raw scenario and quic-go executor component packages rebuilt
  successfully in a temporary output directory.

This is workload and campaign readiness, not throughput evidence. No package
upload, worker/controller deployment, lab execution, or publication occurred.
The next gate remains a three-target package-matrix preview after explicit
registration approval, followed by a fresh matched campaign.

### Accepted 2026-07-15: raw latency and stream-limit coverage

The raw peer contract now includes two additional matched workloads. The 1 KiB
bidirectional echo lane runs at c1/c4/c16/c32/c64/c128. The 100x64 KiB
stream-limit lane intentionally stays at one connection so it measures
advertised stream capacity rather than multiplying the scenario into 12,800
simultaneous streams. Incursa, MsQuic/System.Net.Quic, and quic-go advertise
both lanes, and the reusable quic-go executor validates their canonical
behavior names.

The quic-go target still does not advertise the bidirectional 1 MiB payload
lane: its package server intentionally suppresses echoes above 64 KiB. That is
retained as an explicit two-target coverage gap rather than a false parity
claim.

Verification:

- public ProtocolLab repository health passed at commit `ff870ee`;
- reusable Go executor and quic-go target tests passed at component commit
  `32507af`;
- all 84 public/internal component manifest pairs and the coverage baseline
  passed;
- 125 focused ProtocolLab parser, validator, package-script, and live adapter
  tests passed at internal commit `f23b47e`;
- 20 Incursa package-template tests passed at commit `bee9068a`;
- clean scenario, executor, quic-go, Incursa, and MsQuic packages were produced
  with parity-eligible provenance, yielding an exact eight-scenario target
  intersection;
- a bounded package-to-package Windows smoke completed 3,660 c4 latency streams
  and 200 c1/s100 stream-limit operations with zero failures/timeouts and exact
  sent/received byte symmetry.

Artifact hashes are recorded in
[`raw-quic-performance-evidence-plan.md`](raw-quic-performance-evidence-plan.md).
This accepts contract and local execution readiness only. Registration and a
matched three-target campaign remain the next gates. No package was uploaded
and no lab or publication state changed.

### Accepted 2026-07-16: raw workload-shape integrity and slow-reader coverage

The raw QUIC evidence surface now includes
`quic.transport.flow-control.slow-reader-16x64kb`, a 16-stream, 64 KiB exact
echo workload whose client delays response reads by 100 milliseconds. Incursa,
MsQuic/System.Net.Quic, and quic-go package templates advertise the scenario,
the reusable executor validates its canonical behavior and observed delay, and
clean local packages passed strict package-backed smoke for the supported host
targets. Public contract commit `950ec73`, component commits `5063930` and
`5083c00`, internal commits `5c5ec71` and `066838a`, and Incursa commit
`40774b16` retain that work.

Review of current controller previews also found that the generic `smoke`
profile could override a fixed raw scenario's stream count. Historical cells
labeled `quic.transport.multiplex.100x64kb` could therefore execute as `c1-s1`
and still validate against the overridden cell shape. Internal commit
`d35a727` closes that evidence-integrity hole: raw campaign defaults now use
the dimension-neutral `raw-quic-peer-confidence` profile, plan construction
rejects any stream count that differs from `quicTransport.streamCount`, and
the deterministic validator repeats the same gate. Throughput remains one
stream, multiplex remains 100, slow-reader remains 16, and handshake remains
zero. Explicit incompatible CLI overrides fail rather than silently relabeling
the workload.

Verification:

- 100 focused load-profile, planner, validator, execution, and operator-script
  tests passed;
- a live controller dry-run selected `raw-quic-peer-confidence`, Comparison,
  five repetitions, round-robin ordering, and all three throughput targets;
- the all-up internal suite passed 1,219/1,228 tests, with the nine failures
  isolated to existing cross-repository schema registration, package fixture,
  and environment-materialization interference outside this slice;
- no package was registered, no worker/controller was deployed or restarted,
  no benchmark job was submitted, and no result was published.

Older raw QUIC results whose retained cell shape does not match the named
scenario contract are not authoritative baselines. The next gate is explicit
approval to register the already-built current packages and deploy the current
runner, followed by a fresh matched c1/c4/c16/c32/c64/c128, five-repetition,
round-robin Incursa/quic-go/MsQuic campaign. Runtime changes should be selected
from those corrected traces rather than from the stale public numbers.

### Accepted 2026-07-16: stable-connection stream-churn parity

The ninth matched raw lane now distinguishes stream lifecycle cost from
connection lifecycle cost. `quic.transport.stream-churn` opens, exchanges 128
bytes in both directions, and closes 1,000 sequential bidirectional streams on
one stable connection. The contract's exact total is 256,000 bytes. Public
commit `cc149c7`, component commit `5be4862`, internal commit `0a51cfe`, and
Incursa commit `e5a5304d` align the contract, reusable executor, Incursa and
MsQuic adapters, campaign slices, and source-backed package template.

Raw validation now also rejects any executor output whose reported behavior
does not equal the selected scenario behavior. This prevents byte-compatible
but semantically different workloads from being accepted under the wrong raw
scenario identity.

Verification:

- Go executor tests passed and exercise live stream-churn dispatch;
- 143/143 focused runner, validator, campaign, and live adapter tests passed;
- 20/20 Incursa package-template tests passed;
- all 90 component manifest pairs passed;
- clean scenario, Linux/Windows executor, Incursa Linux, and MsQuic Linux
  packages were built with parity-eligible attestations whose hashes match;
- all five package manifests reference `quic.transport.stream-churn`.

Exact package versions and hashes are recorded in
[`raw-quic-performance-evidence-plan.md`](raw-quic-performance-evidence-plan.md).
No package was uploaded or registered, no service was deployed or restarted,
no lab benchmark ran, and no result was published. The public July 12 raw rows
remain stale diagnostic evidence; the next decision gate is the current matched
nine-lane package-backed campaign.

The post-build live dry-run proves package registration is the remaining
coverage blocker rather than another local scenario gap. Only throughput and
multiplex currently resolve three runnable targets. Four lanes resolve quic-go
alone, and stream churn, stream-limit pressure, and slow-reader do not resolve
from the registered inventory. The dry-run used Comparison, five repetitions,
and round-robin ordering and submitted no job.

### Accepted 2026-07-16: exact 1 MiB server-to-client download coverage

`quic.transport.stream-download.1mb` closes the largest directional gap in the
raw comparison surface. A client sends a fixed 16-byte request prelude and the
server sends exactly 1 MiB whose byte at zero-based offset N is `N % 251`.
The executor excludes the prelude from payload metrics, rejects a short, long,
or corrupt response, and reports zero payload bytes sent for this direction.
The server implementations share a deterministic response payload instead of
allocating one 1 MiB array per stream.

Public commit `63242f4`, component commit `0032d2a`, internal commit `42f937b`,
and Incursa commit `a450928a` retain the complete contract and implementation
slice. The immutable local package artifacts are:

- scenario package `0.1.12`, SHA-256
  `e434f72a3fd92afde2ec3dad0e17205d942ec4d8a6c8d08bb4e612529f705e0a`;
- Windows executor package `0.1.10`, SHA-256
  `f3f5af7320b51e4fc20e1fb27d1d2061ea29c5a7a4da355bedb0fed233cce96e`;
- quic-go raw target package `0.1.13`, SHA-256
  `0279f2590b58eb41f74ba2c81c6387a31795c0437b37373d90ef4d9e723f9c98`.

Focused validation passed 116/116 internal tests and 20/20 Incursa package
tests; all 92 component manifest pairs and the Go suites passed. Local c1
diagnostics retained under the following run roots completed exact validation
with no failures or timeouts:

- `raw-download-smoke-20260716-quic-transport-v1-comparison`: Incursa,
  38.21 MiB/s and 29.68 ms p95;
- `raw-download-msquic-smoke-20260716-quic-transport-v1-comparison`: MsQuic,
  181.44 MiB/s and 6.49 ms p95;
- `raw-download-quicgo-smoke-20260716-direct-package-cell`: quic-go,
  61.79 MiB/s and 17.59 ms p95.

The three cells are one short sequential shared-host pass, so they are
diagnostic only. A current matched c1/c4/c16/c32/c64/c128 campaign still
requires deterministic round-robin ordering, at least five repetitions,
target and generator telemetry, exact source/package provenance, and explicit
operator approval before any package registration or lab execution. Until
then, the justified local next step is trace attribution on Incursa's isolated
download send and completion path, not a public peer-ranking claim.

1. Finish terminal exception attribution and cleanup.
2. Add permanent exception/trace-site tooling.
3. Establish stable smoke and confidence ProtocolLab lanes.
4. Attack HTTP/3 allocation hot spots.
5. Add raw QUIC and public API stream-transfer baselines.
6. Move repeatable evidence onto package-backed lab/controller runs.

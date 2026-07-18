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

### Accepted 2026-07-16: current raw cross-section and honest coverage

The raw performance program now has a current source-backed c16 cross-section
instead of relying on the stale public magnitude. Five exact repetitions each
measured 259.49 MB/s for 16 MiB upload, 30.74 MB/s for 100x1 KiB multiplex, and
123.26 MB/s for 16x1 MiB duplex. Every one of the 15 cells passed with zero
failed or timed-out operations. Upload throughput range was 2.96 percent;
multiplex and duplex remain diagnostic because throughput or p95 range was
8.25-48.25 percent. Evidence is under
`C:\shared\temp\protocol-lab-current-raw-baseline-20260716\runs`.

ProtocolLab internal commits `d11f0dd`, `b394890`, and `acbb155` close the
source workload inventory and executable-dispatch gaps. Mixed-size c4/s16,
stream-churn c1/s1000, slow-reader c1/s16, and duplex-peer c1/s16 all passed
real source-backed validation and benchmark execution; the slow-reader median
was 112.36 ms. Component commit `d2edb1b` produces scenario package `0.1.18`
with the exact 16-stream duplex c1-c128 shape at SHA-256
`c65ac9f7186151e5c4fdbf56394f56de59333687589c2d4589a779822917e388`.

This accepts coverage truth and diagnostic baselines, not a runtime throughput
change or public ranking. No package was uploaded or registered and nothing was
deployed or published. The next engineering target is a fixed-total-byte raw
write-granularity lane (1 KiB versus 64 KiB chunks, upload and download) and a
matched package-backed peer campaign after operator approval.

1. Finish terminal exception attribution and cleanup.
2. Add permanent exception/trace-site tooling.
3. Establish stable smoke and confidence ProtocolLab lanes.
4. Attack HTTP/3 allocation hot spots.
5. Add raw QUIC and public API stream-transfer baselines.
6. Move repeatable evidence onto package-backed lab/controller runs.

### Accepted 2026-07-16: bounded ACK receipt-ledger work

Sustained raw receive traffic exposed two quadratic ACK-generation operations.
`RecordProcessedPacket` enumerated every retained receipt to find the largest
ack-eliciting packet and enumerated the same history again to count disjoint
ACK ranges. ACK scheduling then scanned acknowledged-but-not-yet-retired
receipts from index zero even when only one newer packet was pending.

The accepted runtime keeps the disjoint range count in
`QuicPacketReceiptStore`, caches the largest retained ack-eliciting packet with
explicit refresh after retirement and trimming, and binary-searches to the
first receipt newer than the last ACK trigger. Duplicate replacement,
out-of-order detection, delayed ACK thresholds, ECN state, ACK-range
retirement, and packet-number-space discard behavior remain unchanged.

Permanent BenchmarkDotNet coverage in
`QuicAckGenerationStateRecordingBenchmarks` measured contiguous receipt
recording as follows:

| Receipts | Baseline | Candidate | Delta |
| ---: | ---: | ---: | ---: |
| 128 | 22.32 us | 3.701 us | -83.4% |
| 1,024 | 1,082.76 us | 30.415 us | -97.2% |
| 2,400 | 5,881.90 us | 74.912 us | -98.7% |

The pending-ACK check after retained history fell from 310.5 ns to 18.76 ns at
128 receipts, from 2.125 us to 21.74 ns at 1,024, and from 4.935 us to 23.04 ns
at 2,400. Allocations stayed effectively flat; the optimized recording state
is 1.86 KiB per benchmark operation versus 1.84 KiB before the cached field.
Reports are under `C:\shared\temp\quic-ack-recording-*20260716` and
`C:\shared\temp\quic-ack-pending-*20260716`.

Matched local source-backed ProtocolLab runs used exact 16 MiB uploads, five
repetitions, current target builds, and zero failed or timed-out operations.
The c1 comparison produced the material end-to-end result:

| Scenario | Baseline | Candidate | Throughput delta | p95 delta |
| --- | ---: | ---: | ---: | ---: |
| 16,384 x 1 KiB | 27.43 MiB/s | 56.98 MiB/s | +107.7% | -48.1% |
| 256 x 64 KiB | 43.01 MiB/s | 74.23 MiB/s | +72.6% | -45.2% |

At c16 the same candidate was neutral within variance: +0.7% for 1 KiB and
-2.1% for 64 KiB, with 7-10% throughput ranges. This change removes a
single-connection retained-history bottleneck; it does not close Incursa's
absolute c16 peer gap. Evidence and machine-readable comparisons are under
`C:\shared\temp\protocol-lab-ack-ledger-*20260716`.

Focused tests passed 10/10. The full suite passed 9,602, skipped five, and hit
two broad-run timing failures: one existing HTTP/3 close timeout and one
dropped-FIN resilience assertion. Both passed on exact rerun, and the
dropped-FIN case then passed 10 consecutive runs. Two independent reviews
found no correctness defect and requested the now-present largest-cache
retirement regression. No package was registered, no controller or worker was
changed, and nothing was deployed or published.

The next raw runtime tranche should target the absolute c16-c128 gap in the
shared receive/send pipeline, especially datagram send cost, stream receive
locking, and packet scheduling, rather than retuning small-write heuristics.

### Rejected 2026-07-17: per-datagram ECN lookup and direct Windows send

The retained c64 CPU trace attributed 3.16% exclusive CPU to the listener
datagram-send method, with the native socket send accounting for only part of
that sampled stack. Two bounded candidates tested whether avoidable socket
bookkeeping or managed endpoint marshalling explained the gap.

The current runtime emits `NotEct` while the managed receive path cannot read
ECN metadata. Avoiding creation and lookup of fresh per-socket ECN state reduced
the isolated marking helper from 9.650 ns to 2.179 ns (-77.4%) with zero
allocation. The absolute saving is only 7.471 ns per datagram, too small to
explain the multiplex collapse or justify a full c1-c128 campaign. The helper
change was not retained; the permanent benchmark and raw reports remain under
`C:\shared\temp\quic-ecn-notect-*20260717`.

A Windows `sendto` P/Invoke candidate then reused the cached `SocketAddress`
buffer and `SafeSocketHandle` to bypass the managed overload. The matched
loopback benchmark measured 7.246 us for `Socket.SendTo` and 7.216 us for the
direct primitive, ratio 1.00 within noise, with zero allocation for both. The
candidate and benchmark were removed. Evidence remains under
`C:\shared\temp\quic-direct-sendto-20260717`.

Neither primitive passed the independent gate, so ProtocolLab cells were not
run and no end-to-end improvement is claimed. Do not repeat a direct Windows
send wrapper or minor ECN lookup variant without materially different evidence.
The next target is packet scheduling and queue service capacity; asynchronous
listener send decoupling remains rejected because socket emission must stay
coupled to congestion and recovery accounting.

### Rejected 2026-07-16: split stream-action lifecycle and processing gates

The 100x1 KiB multiplex ladder falls after c16: 7.28 MiB/s at c1, 17.65 at
c4, 24.44 at c16, 20.97 at c32, 13.61 at c64, and 8.47 at c128. Target CPU
also falls while memory and handle counts rise. The investigated lock protected
both cross-thread request lifecycle and the complete stream-write transport
mutation, so the candidate separated lifecycle, retry, and processing gates
while preserving serialized packet and send-state mutation.

The first design removed transport serialization and is rejected for
correctness: a c64 cell returned 221 of 1,024 expected response bytes. Its
evidence remains under `C:\shared\temp\pllockcandidate\c16` and `c64`.

The second design used an exact-value `ConcurrentDictionary`, per-request
completion ownership, a lifecycle gate, a retry-queue gate, and a distinct
processing gate. It passed 20 focused cancellation, completion-pool, and
structural requirement tests, including a 128-write transition/cancellation
race that also passed ten repetitions. A full run completed 9,605 passing tests
and five skips, with one DoQ excessive-load timing failure that passed ten
consecutive exact reruns. Candidate commit `30667255` and revert `57c47587`
retain the implementation and its removal.

Pre-commit shared-host evidence initially looked favorable. Five usable c64
matched pairs produced 14.14 versus 15.89 MiB/s (+12.4%), with p95 improving
26.5% and p99 improving 29.2%. c1 and c4 were +1.8% and +2.7%; c16 was -2.3%.
Stable controls stayed within 3.4% throughput, but the 16 MiB upload control
completed 10/10 baseline cells and only 8/10 candidate cells before five
candidate supplements passed. Evidence is under
`C:\shared\temp\pllockcandidate\v2-c1`, `v2-c4`, `v2-c16`, `v2-c64`, and
`v2-controls-corrected`.

Wake diagnostics explained only a bounded scheduling effect. Async wakeups
fell from 5,344 to 2,903 and mean work per wake rose from 2,048.6 to 2,401.6,
but average shard peak queue depth increased from 496.5 to 510.6, absolute peak
from 561 to 569, and outstanding pooled bytes remained approximately 7 MiB.
Request-registration slow-monitor attribution fell from 0.377% to 0.314%, while
total slow-monitor and thread-pool semaphore wait shares stayed flat near 4.2%
and 67.2%. ProtocolLab commit `68effd6` and evidence under
`C:\shared\temp\pllockcandidate\v2-diagnostics` retain that attribution.

The required clean committed rerun reversed the result. All ten c64 cells
passed exact validation with zero failures or timeouts, but variance was too
high and the candidate was slower:

| Variant | Median | Range | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| Baseline `ea4fb618` | 14.72 MiB/s | 73.4% | 287.02 ms | 351.15 ms |
| Candidate `30667255` | 13.19 MiB/s | 57.7% | 328.60 ms | 396.93 ms |

That is -10.4% throughput, +14.5% p95, and +13.0% p99. No cell had an
objective network/resource failure or load-generator saturation signal that
would justify excluding it, and the candidate lost four of five paired
repetitions. The clean evidence root is
`C:\shared\temp\pllockcandidate\committed-c64-30667255`.

The candidate is therefore rejected and must not be published as an
improvement. Do not repeat another minor lock split. The next diagnosis should
target the unchanged queue peaks, pooled-buffer retention, and the pre-existing
221-byte truncated-response and upload idle-timeout failures before another
runtime scheduling design is attempted.

### Rejected 2026-07-17: collapse STREAM receive delivery decisions

Sampled c64 CPU evidence from the retained multiplex campaign attributed 4.27%
exclusive CPU to `Monitor.Enter_Slowpath`. The largest project-attributed
groups were stream snapshots, pending stream-action ownership, stream priority,
peer stream-capacity release, application reads, and STREAM-frame receipt.
The 1-RTT and 0-RTT receive loops applied each accepted STREAM frame under the
connection-wide stream-state lock, then reacquired the same lock twice for
completion/readability snapshots and once more to mark first peer delivery.

Candidate commit `b982ed85` returned completion, readability, and first-accept
decisions from the original receive transaction while preserving the legacy
bookkeeping entry point. Revert `1fe495a2` removes it from the active runtime.
Receive-buffer tests passed 21/21. A broader runtime, stream-state, and RFC 9000
filter passed 4,476, skipped three intentional ProtocolLab-sized cases, and had
zero failures.

All 40 uninstrumented source-backed ProtocolLab cells used exact 100x1 KiB
multiplex validation, identical executor package 0.1.14, alternating AB/BA
ordering, five observations per variant and shape, and zero validation,
request, or timeout failures. The initial c16 gate favored the candidate, but
the required higher-concurrency gates did not:

| Shape | Baseline | Candidate | Throughput delta | Baseline p95 | Candidate p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| c16 | 17.51 MiB/s | 25.97 MiB/s | +48.3% | 63.94 ms | 58.01 ms |
| c64, immediate alternation | 14.54 MiB/s | 12.90 MiB/s | -11.3% | 298.22 ms | 282.87 ms |
| c64, 30-second cooldown | 18.80 MiB/s | 17.17 MiB/s | -8.7% | 266.06 ms | 281.04 ms |
| c128, 30-second cooldown | 9.28 MiB/s | 8.86 MiB/s | -4.5% | 723.98 ms | 784.18 ms |

The shared host remained highly variable at c64-c128. The cooled candidate
range was 31.4% at c64 and 106.7% at c128; its c128 p99 was 953.27 ms versus
833.80 ms baseline. The c64 generator CPU also tracked achieved throughput,
confirming that slow cells left the generator waiting rather than proving a
generator saturation ceiling. Cooldown removed the strongest immediate-order
bias but did not produce a repeated high-concurrency win.

Evidence is retained under:

- `C:\shared\temp\pl-receive-result-candidate-20260717`;
- `C:\shared\temp\pl-receive-result-candidate-c64-cooldown-20260717`;
- `C:\shared\temp\pl-receive-result-candidate-c128-cooldown-20260717`.

This candidate is rejected because it improves c16 without improving the actual
c64-c128 collapse and worsens high-concurrency tail latency. Do not repeat
another variation that only folds receive-state snapshots into the existing
connection-wide stream lock. The next evidence-supported target is the
independent datagram send cost, followed by packet scheduling and receive-state
ownership changes that shorten or remove the connection-wide critical section
rather than doing more work inside it.

### Rejected 2026-07-17: payload-sized ProtocolLab echo receive buffers

The raw Incursa ProtocolLab server rented a 64 KiB echo buffer for every active
stream, including the 100x1 KiB multiplex lane. A bounded harness candidate
instead sized non-download receive buffers from the declared payload length,
which would reduce the nominal active-stream rental from 64 KiB to 1 KiB in
that lane without changing runtime flow control, packet scheduling, write
ordering, or FIN behavior.

The first matched source-backed c16 gate completed five exact repetitions per
variant with zero validation failures, request failures, or timeouts. The
baseline median was 28,884.40 requests/s (28.21 MiB/s), 53.60 ms p95, and
76.24 ms p99. The candidate median was 27,418.40 requests/s (26.78 MiB/s),
56.24 ms p95, and 104.69 ms p99: -5.1 percent throughput and +37.3 percent
p99. One candidate repetition also fell to 12,146.40 requests/s, confirming
that the shared-host batch was not stable enough to support a memory claim.

The run's adapter working-set metric was captured before load, and both
variants reported unavailable QUIC buffer-pool counters because the counter
stream was empty. The experiment therefore neither passed the performance gate
nor produced proof of lower peak working set or pooled-buffer retention. The
candidate was reverted without spending the c1-c128 matrix. Evidence remains
under `C:\shared\temp\pl-receive-buffer-size-20260717`. Do not repeat
payload-sized harness rentals without load-window process-memory or pool-counter
instrumentation and a materially different explanation for the tail-latency
regression.

### Accepted 2026-07-17: coalesce bounded small echo data and FIN

The raw Incursa ProtocolLab server previously issued `WriteAsync` followed by
`CompleteWritesAsync` for every bidirectional echo. The runtime already exposes
an internal `WriteFinalAsync` operation that preserves the write gate,
cancellation, delayed `ValueTask` consumption, exception propagation, and FIN
ordering while representing data plus FIN as one stream action. The accepted
harness change uses that operation only when the peer contract declares a
positive payload no larger than the existing 1 KiB small-application-write
policy. Duplex behavior and payloads above 1 KiB retain the incremental read,
write, and completion path. The bounded path requires peer EOF before writing
the response and rejects requests with bytes beyond the declared payload, so
truncated and oversized requests do not become successful benchmark samples.

The matched 100x1 KiB source-backed campaign used the same executor package,
exact payload validation, five repetitions per shape, and zero failures or
timeouts in all 60 baseline/candidate cells:

| Shape | Baseline | Candidate | Throughput delta | Baseline p95 | Candidate p95 | p95 delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| c1 | 9.17 MiB/s | 10.65 MiB/s | +16.2% | 11.19 ms | 9.47 ms | -15.4% |
| c4 | 20.05 MiB/s | 26.38 MiB/s | +31.6% | 20.71 ms | 16.77 ms | -19.0% |
| c16 | 26.77 MiB/s | 32.29 MiB/s | +20.6% | 59.29 ms | 52.22 ms | -11.9% |
| c32 | 21.86 MiB/s | 30.02 MiB/s | +37.4% | 129.15 ms | 94.83 ms | -26.6% |
| c64 | 17.32 MiB/s | 20.54 MiB/s | +18.6% | 285.73 ms | 220.89 ms | -22.7% |
| c128 | 10.54 MiB/s | 13.84 MiB/s | +31.3% | 695.23 ms | 465.83 ms | -33.0% |

The candidate materially reduces scheduling pressure at every measured shape
but does not close Incursa's absolute c128 peer gap. Candidate p99 improved at
c4, c32, c64, and c128; it regressed 12.9% at c1 and 15.2% at c16 on the
shared host, while p95 and throughput improved at both shapes.
Matched unaffected controls remained within the throughput guardrail: 64 KiB
single-stream upload -0.4%, fixed-total 256x64 KiB upload -3.3%, 16-stream
duplex -1.3%, and 16x1 MiB multiplex -0.8%. Each control had five exact
baseline and candidate repetitions with no request failures or timeouts.

One diagnostic-only c16 counter pair supports the mechanism rather than being
used as a throughput claim. At higher achieved throughput, the final EOF-first
candidate reduced the observed runtime queue peak from 209 to 94, stream-write
queue peak from 124 to 41, packet-receive queue peak from 99 to 67,
delayed-send peak from 103 to 90, receive-retained-buffer peak from 129 to 123,
and sampled pool-rent volume from 4.37 million to 3.44 million. Peak
outstanding pooled buffers fell from 1,259 to 496. The counter
aggregation is sampling-based, so these values are attribution signals, not
exact per-request accounting.

An initial 64 KiB fast-path bound is explicitly rejected. At c16 it regressed
median 100x64 KiB throughput from 72.12 to 66.29 MiB/s (-8.1%) and raised p99
10.7%, showing that incremental read/write overlap matters for larger payloads.
After narrowing the bound to the existing 1 KiB policy, a five-repetition c16
rerun produced 74.16 MiB/s (+2.8%) and 11.9% lower p99 versus the same baseline.
The c1 narrowed rerun was -5.0% with a 7.6% candidate range on the shared host;
because the large-payload path is unchanged and c16 recovered, it is retained
as a variance caveat rather than evidence for the candidate.

An earlier small-payload variant wrote the response before checking peer EOF.
It produced larger headline gains but could respond before rejecting an
oversized request, so it is rejected as a semantic shortcut. Its artifacts are
retained alongside the accepted EOF-first matrix and are not used for the
accepted throughput claim.

Evidence is retained under `C:\shared\temp\pl-final-write-20260717`, including
the full c1-c128 matrix, control runs, counter captures, the rejected broad
64 KiB bound, and the narrowed 64 KiB reruns. A fixed-total 16,384x1 KiB upload
attempt did not exercise the candidate and is not an idle-timeout result: the
0.1.14 raw load executor rejected `sustained-stream-16384x1kb` as unsupported.
That artifact is retained as an executor-coverage gap and no performance claim
is made from it.

Focused final-write, cancellation, concurrency, FIN-scheduling, and harness
tests passed 42/42. The full solution run passed 9,603, skipped five, and
reproduced two previously documented broad-run timing failures: the HTTP/3
incomplete-content close timeout and the dropped-server-FIN resilience
assertion. Both passed together on exact rerun; the dropped-FIN case then
passed 10/10 consecutive isolated reruns. After the EOF-order correction, the
full suite produced the same 9,603 passes, five skips, and same two broad-run
failures; both exact tests then passed together in 10/10 consecutive reruns.
`git diff --check` passed. No package was registered and nothing was deployed
or published.

The accepted clean source at `90e1416e` was subsequently packaged locally as
`quic-dotnet-raw-dev@0.0.0-final-write-90e1416e` for both `linux-x64` and
`win-x64`. Its immutable SHA-256 is
`70149e61f22e9553e0fadde923e7e97c5a4d22897093b2a68de2b61cadb1d372`.
The external attestation and embedded provenance both identify full commit
`90e1416e84d0af898a8760e81af86a15e098c944`, a clean package-input scope, and
source/package parity eligibility. Recomputed archive hashing matched the
attestation, all four platform adapter/server payloads were present, and the
extracted Windows package entrypoint reported adapter status `ready` before its
validation process tree was stopped. Retain the package, attestation, extracted
validation payload, and health logs under
`C:\shared\temp\pl-final-write-20260717\packages`. The package was not uploaded
or registered, and nothing was deployed or published.

### Rejected 2026-07-17: direct due-timer processing during bounded shard drains

The c64 queue diagnostics suggested that the shard's complete inbox drain can
postpone ACK, recovery, idle, and application-send deadline checks while the
channel remains continuously nonempty. A bounded-drain candidate alternated 64
inbox work items with already-due timer events and passed a focused test that
preloaded 256 local work items before an idle deadline.

The design was rejected before ProtocolLab measurement because it processed
timer events directly instead of re-entering them through the same serialized
inbox. That violates `REQ-QUIC-CRT-0054` and the deadline-scheduler architecture
even though runtime mutation remained single-threaded. The code and candidate
test were reverted. A future deadline-fairness design must retain one queued
ordering surface for network, local API, and timer events; do not repeat direct
timer dispatch or treat queue serialization alone as equivalent to the required
same-queue contract.

### Rejected 2026-07-17: bounded Linux listener `sendmmsg` batches

The published Linux raw QUIC peer report and the current 64 KiB echo trace
justified testing the dormant `QuicSocketSendBatch` primitive at the listener
boundary. The candidate accumulated at most 32 already-protected datagrams per
runtime shard, preserved routed-handle and datagram order, retained detached
packet owners until the synchronous batch callback completed, and kept packet
information, custom sender, Windows, and unsupported native paths on the
existing single-send implementation. Focused ownership, observer-failure,
runtime-shard, listener-host, and socket-batch tests passed 47/47. A second
variant used single sends below four datagrams to avoid native setup cost for
small batches.

Same-host Debian 12 source builds used the current accepted `90e1416e` source,
the same freshly built `quic-go-raw-load` executable, 64 KiB bidirectional echo,
one stream per connection, two seconds of warmup, 15 seconds of measurement,
and five repetitions. The accepted baseline measured 27.910 MiB/s at c16 and
34.997 MiB/s at c64. Unconditionally batching two or more datagrams measured
27.210 MiB/s at c16 (-2.5%) and 37.976 MiB/s at c64 (+8.5%). Requiring at least
four datagrams measured 26.882 MiB/s at c16 (-3.7%) and 37.224 MiB/s at c64
(+6.4%). Every cell completed with zero failed or timed-out requests, but both
variants regressed the documented c16 gap and remained below the normal 10%
throughput bar at c64. No c1-c128 or control campaign was justified.

The runtime and test changes were reverted. Retain local evidence under
`C:\shared\temp\pl-linux-sendmmsg-20260717` and the copied SUT evidence under
`/home/samuel/quic-perf/evidence/{baseline-90e1416e-c16-c64-20260717,candidate-sendmmsg-batch-c16-c64-20260717,candidate-sendmmsg-min4-c16-c64-20260717}`.
Do not retry listener-level `sendmmsg` batching without a materially cheaper
native buffer-lifetime design or evidence that the deployment path produces
larger batches without c16 loss.

### Rejected 2026-07-17: queue-preserving bounded shard drains

The prior direct timer-dispatch experiment was replaced with a contract-safe
design that processed at most 64 inbox items before re-entering the shard loop.
Newly due ACK, recovery, idle, and application-send timers were still appended
to the same serialized inbox required by `REQ-QUIC-CRT-0054`; no timer bypassed
the channel and existing work retained its order. A requirement-home test
proved that a deadline becoming due under a continuously nonempty inbox was
discovered between drain windows. Focused timer, deadline, idle, application
send, and runtime-shard tests passed 80/80.

The current accepted `90e1416e` Linux source baseline completed the 64 KiB
bidirectional echo lane at c1, c4, c16, c32, c64, and c128 with five
repetitions and zero failed or timed-out requests. Its c16 and c64 medians were
28.406 MiB/s and 36.382 MiB/s. The bounded-drain candidate measured 28.463
MiB/s at c16 (+0.2%) and 33.373 MiB/s at c64 (-8.3%); median p95 latency was
essentially unchanged at c16 and worsened from 88.43 ms to 91.19 ms at c64.
The c64 candidate range also widened to 27.624-35.541 MiB/s. These direct
same-host source runs were sequential diagnostic gates, not matched
publishable evidence, but the clear c64 regression made a full campaign
unnecessary.

The runtime and test changes were reverted. Retain the accepted-source ladder
under `C:\shared\temp\pl-current-raw-baseline-20260717`, the candidate gate
under `C:\shared\temp\pl-bounded-drain-20260717`, and the copied SUT evidence
under `/home/samuel/quic-perf/evidence/{baseline-90e1416e-c1-c128-20260717,candidate-bounded-drain-c16-c64-20260717}`.
Do not retry bounded inbox drains without evidence for a different fairness
mechanism that avoids the c64 throughput and variance penalty.

### Rejected 2026-07-17: direct Linux `sendto` wrapper

A fresh current-source Linux c16 trace for the 64 KiB bidirectional echo lane
attributed 5.15 percent inclusive sampled time to listener datagram send. The
managed `SocketPal.TryCompleteSendTo` portion was 3.0 percent and native
`sendmsg` was 2.14 percent, so a Linux-specific direct syscall was tested before
changing production code. The isolated gate reused one UDP socket, the same
cached native socket address, a 1,200-byte payload, pinned payload/address
memory, seven alternating 100,000-datagram rounds, and a dedicated loopback
receiver.

Managed `Socket.SendTo` measured a stable 11.300 microseconds per datagram;
direct libc `sendto` measured 10.276 microseconds, a 9.1 percent primitive
reduction. Applied to the traced 5.15 percent send share, the upper-bound
whole-process benefit is approximately 0.5 percent before accounting for
SafeHandle, platform, error-mapping, and maintenance costs. That does not meet
the end-to-end gate and does not justify replacing the framework socket path.
No production or test files changed and no ProtocolLab matrix was spent.

Retain the diagnostic trace under
`C:\shared\temp\pl-current-linux-trace-20260717`, the isolated benchmark source
under `C:\shared\temp\linux-sendto-gate-20260717`, and the SUT copies under
`/home/samuel/quic-perf/evidence/baseline-90e1416e-c16-linux-trace-20260717`
and `/home/samuel/quic-perf/linux-sendto-gate-20260717`. Do not retry a direct
single-datagram syscall wrapper without a materially larger measured managed
overhead or a safe zero-copy batch design that also clears the c16 guardrail.

### Rejected 2026-07-17: derive packet-number length after one header mask

The current short-header packet-open path tries packet-number lengths one
through four. Because the QUIC header-protection sample begins four bytes after
the packet-number offset regardless of the encoded packet-number length, a
candidate generated one header-protection mask per connection-ID candidate,
derived the encoded length from the unmasked first byte, and retained the same
fixed-bit, reserved-bit, AEAD, key-phase, packet-number expansion, and payload
validation. Both allocating and pooled-lease paths were changed. The Release
solution build passed with zero warnings, and focused RFC 9001, short-header,
captured-interoperability, and grease-bit tests passed 436/436.

The accepted `90e1416e` Linux source baseline measured 28.406 MiB/s at c16 and
36.382 MiB/s at c64 in the 64 KiB bidirectional echo lane. Five candidate
repetitions measured 28.538 MiB/s at c16 (+0.46%) and 35.509 MiB/s at c64
(-2.40%). Median p95 latency moved from 38.36 to 37.88 ms at c16 and from 88.43
to 86.64 ms at c64. Candidate throughput ranged from 27.118 to 29.748 MiB/s at
c16 and from 30.668 to 38.747 MiB/s at c64. All ten cells completed with zero
failed or timed-out requests, but the throughput movement was immaterial and
did not justify a full c1-c128 campaign. A repository BenchmarkDotNet row was
also non-decisive because its iteration setup forces one invocation and
produces iterations far below the recommended measurement duration.

The runtime change was reverted. Retain local candidate evidence under
`C:\shared\temp\pl-header-pn-20260717` and the SUT evidence under
`/home/samuel/quic-perf/evidence/candidate-header-pn-c16-c64-20260717`.
Do not retry this packet-number derivation unless a materially different packet
open design has direct attribution and can clear the end-to-end c16 guardrail.

### Rejected 2026-07-17: raise raw-server ThreadPool minimum to 64

The retained c16 traces combine deep shard queues, low target CPU, and an empty
ThreadPool queue. A diagnostic-only raw-server candidate raised both worker and
completion-port minimums to 64 on the 16-core Linux target to test whether slow
worker injection or continuation scheduling explained the queue service gap.
It did not change the QUIC runtime, protocol behavior, or load shape.

Against the accepted `90e1416e` 64 KiB bidirectional echo baseline, five
candidate repetitions measured 27.642 MiB/s at c16 versus 28.406 MiB/s
(-2.69%) and 34.977 MiB/s at c64 versus 36.382 MiB/s (-3.86%). Median p95 moved
from 38.36 to 38.58 ms at c16 and from 88.43 to 86.95 ms at c64. Candidate
throughput ranged from 26.375 to 28.889 MiB/s at c16 and 34.754 to 36.571 MiB/s
at c64. All ten cells completed with zero failed or timed-out requests.

The temporary server setting was removed. Retain local evidence under
`C:\shared\temp\pl-minthreads64-20260717` and the SUT evidence under
`/home/samuel/quic-perf/evidence/diagnostic-minthreads64-c16-c64-20260717`.
Do not use global ThreadPool minimum tuning as the next queue-service candidate;
investigate queue ownership, service ordering, and the reproducible truncated
response or upload idle-timeout paths instead.

### Rejected 2026-07-17: one-millisecond deadline wake floor

Fresh accepted-source counter captures localized the apparent empty-wakeup
pressure to the shard deadline timer rather than the channel itself. At c64,
one shard peaked at 30,520 `deadline_wake` enqueues and 29,814 empty async wake
cycles per second while the inbox peaked at 84 work items. A bounded candidate
rounded only future sub-millisecond waits up to one millisecond before arming
the operating-system timer. It preserved absolute due ticks, same-inbox timer
serialization, cancellation, timer ordering, and generation checks. Focused
deadline, shard-serialization, and metrics tests passed 35/35.

The counter gate proved the mechanism but also exposed its tradeoff. At c64,
the maximum sampled deadline-wake rate fell from 30,520 to 247 per second and
the inbox peak fell from 84 to 56. However, the counter-attached throughput
dropped from 28.71 to 16.08 MiB/s, retained pooled memory rose from 1.10 to
1.49 MiB, and the oldest retained sent-packet age rose from 2.61 to 4.12
seconds. Counter-attached throughput is not an acceptance metric, but the
retention movement made a complete uninstrumented gate necessary.

The uninstrumented 64 KiB bidirectional echo gate used the same Linux SUT,
load executable, source-backed server, two-second warmup, 15-second duration,
exact payload validation, and five repetitions per c1/c4/c16/c32/c64/c128
point. Candidate median throughput versus accepted `90e1416e` was +2.27%,
+2.33%, -2.59%, +2.56%, +1.48%, and +21.49% respectively. The c128 comparison
was not stable evidence: baseline CV was 48.33%, candidate CV was 65.36%, and
the candidate had two severely disturbed cells at 2.32 and 6.42 MiB/s. Stable
c1-c64 points remained below the normal 10% acceptance bar, while c16 regressed
and c128 stability worsened. All 30 candidate cells completed with zero failed
or timed-out requests.

The full solution run passed 9,605 tests, skipped five, and reproduced the
previously documented HTTP/3 incomplete-content close timeout. The exact test
then passed 5/5 consecutive reruns. The runtime and focused-test changes were
reverted. Retain local evidence under
`C:\shared\temp\pl-deadline-wake-20260717` and SUT evidence under
`/home/samuel/quic-perf/evidence/{candidate-deadline-wake-c16-c64-counters-20260717,candidate-deadline-wake-c16-c64-20260717,candidate-deadline-wake-c1-c128-20260717}`.
Do not retry a coarse timer floor without a deadline mechanism that avoids both
early-wake churn and millisecond-scale ACK, recovery, and application-send
deferral.

### Rejected 2026-07-17: cumulative `MAX_STREAMS` release batching

The 100x1 KiB multiplex trace showed repeated peer-stream capacity releases and
provided a plausible general packet-scheduling candidate: replace one protected
`MAX_STREAMS` packet per closed peer stream with one cumulative update per
direction. The implementation prepared and committed each group atomically,
preserved congestion/protection failure retry, and retained the existing
per-stream path for invalid or small groups. Focused stream-capacity,
concurrency, retry, and RFC tests passed 29/29, and the raw server Release build
completed with zero warnings.

The first matched source-backed c1-c128 campaign batched every eligible group.
It completed all 60 cells with five repetitions per baseline/candidate shape,
exact payload validation, and zero failures or timeouts. The candidate was
+2.8%, +4.8%, -7.4%, +0.2%, +17.5%, and +1.7% at c1, c4, c16, c32, c64, and
c128. Despite the c64 gain and lower c64 p95/p99, the 7.4% c16 regression
rejected that design. A diagnostic batch-size histogram then showed median
groups of five at c16 and six at c64, while c64 p95/p99 groups reached 23/37.

A second design retained the original individual path below 16 releasable
streams per direction. Its matched c16/c64 gate also used five interleaved
baseline and candidate repetitions, the same source-backed runner and load
tool, exact payload validation, and zero failures, timeouts, validation errors,
or detected generator saturation. At c16, median throughput improved from
30.14 to 31.69 MiB/s (+5.1%), p95 improved 1.6%, and p99 improved 2.8%. At c64,
median throughput fell from 19.77 to 16.97 MiB/s (-14.2%), while p95 improved
4.3% and p99 improved 35.5%. The repeated c64 throughput regression rejects
the thresholded design and shows that the first campaign's c64 gain was not a
stable basis for retaining the added state and packet-building complexity.

The runtime, metrics, helper, and tests were reverted. Retain the unthresholded
campaign, counter capture, and thresholded gate under
`C:\shared\temp\pl-maxstreams-batch-20260717`. These are shared-host diagnostic
results, not publishable isolated-hardware proof. Do not retry cumulative
`MAX_STREAMS` release batching without new attribution that separates control
packet cost from the dominant stream/data scheduling path and explains the
opposite c64 outcomes.

### Accepted 2026-07-17: keep HTTP/3 response payload writes in one state machine

A source-backed `gc-verbose` ProtocolLab trace of the 1 MiB fixed response at
c16 attributed 6.91 MiB of sampled allocation to
`Http3Server.WritePayloadBytesSlowAsync`. The 1.6 MiB streaming response was
more pronounced: its per-chunk `WriteResponseDataFramesAsync` state machines
accounted for 178.79 MiB in one 15-second diagnostic cell. Both helpers were
entered once per HTTP/3 DATA-frame payload even though the surrounding fixed or
streaming response method already owned an asynchronous state machine.

The accepted change keeps the existing 16 KiB DATA-frame boundaries, 4 KiB
QUIC write size, final-write behavior, cancellation, flow control, and frame
diagnostics. It only moves the bounded payload sub-write loops into the existing
per-response state machines. The removed allocation groups no longer appeared
in candidate traces. The candidate streaming response state machine itself was
1.83 MiB, versus 178.79 MiB for the removed per-chunk state machines. Trace
cells are attribution evidence only and are not used as throughput claims.

Five clean baseline and candidate repetitions were run for each lane on the
same shared host. All 40 cells passed exact protocol and payload validation with
zero request failures:

| Lane | Baseline median | Candidate median | Throughput delta | p95 delta | Baseline range | Candidate range |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 MiB fixed response, c16 | 43.18 MiB/s | 48.33 MiB/s | +11.9% | -20.4% | 36.3% | 8.7% |
| 1.6 MiB streaming response, c16 | 43.57 MiB/s | 46.51 MiB/s | +6.7% | -9.8% | 28.1% | 8.5% |
| 100x1 KiB multiplex control | 0.18 MiB/s | 0.19 MiB/s | +7.2% | -11.5% | 45.5% | 2.7% |
| 1 MiB simultaneous duplex control | 3.19 MiB/s | 3.07 MiB/s | -3.9% | +4.1% | 17.7% | 41.2% |

The shared-host campaign remains diagnostic, and the wide baseline ranges make
small throughput deltas non-authoritative. The allocation mechanism is direct,
the two affected workload medians improved, and the duplex control stayed
inside the 5% guardrail. Focused large-response, streaming-response, frame
boundary, and simultaneous duplex tests passed 6/6. The full solution passed
9,605 tests, skipped five, and failed zero.

Evidence is retained under
`C:\shared\temp\pl-h3-crosslayer-20260717`, including clean repeated runs
prefixed `baseline-h3-` and `candidate-h3-`, plus the fixed and streaming
trace runs. The same streaming trace still attributed about 701 MiB to
`System.Byte[]` from the ProtocolLab deterministic streaming-body generator.
That adapter-owned payload churn is the next separate cross-layer/API-usage
candidate; it is not credited to this library change. Nothing was deployed or
published.

### Accepted 2026-07-17: reuse fragmented HTTP/3 frame pending storage

The sustained simultaneous request/response trace identified a second general
HTTP/3 allocation mechanism after the response-write state-machine change. A
16 KiB server read commonly ended after the 16 KiB DATA payload but before the
frame header and payload were both complete. `Http3FrameReader` appended the
next read to a newly allocated array and then allocated again to retain the
unconsumed suffix. The accepted change retains one bounded per-reader pending
buffer, compacts unconsumed bytes in place, and releases capacities above 64
KiB once the buffered frame has been consumed. Frame payloads remain owned by
their returned frame objects; parsing, truncation errors, and frame validation
semantics are unchanged.

The permanent 64-frame fragmentation benchmark measured 3.01 MiB allocated per
operation on `12e05b5c` and 1.05 MiB with the candidate, a 65.1% reduction.
Median time moved from 322.3 to 163.0 microseconds, but benchmark timing was
noisy and is supporting evidence rather than the primary acceptance claim. In
the sustained duplex trace, normalized `System.Byte[]` attribution fell from
4.331 MiB per exact 1 MiB bidirectional transfer to 1.259 MiB, a 70.9%
reduction. Trace-instrumented throughput is not used as a performance claim.

Five clean sustained-duplex repetitions improved median throughput from 22.70
to 23.93 MiB/s (+5.4%) and median p95 from 37.4 to 36.5 ms (-2.4%), with 614
candidate transfers and no failures. The first c16 control campaign was visibly
disturbed, so the complete baseline/candidate sequence was repeated. In the
final matched baseline/candidate pair, the 1 MiB fixed response was flat at
42.95 versus 42.92 requests/s, the 1.6 MiB streaming response was flat at 27.48
versus 27.65 requests/s, and the 64 KiB upload echo was flat at 403.10 versus
400.47 requests/s with improved p95. The 1 MiB upload sink improved from 53.59
to 81.30 requests/s (+51.7%) while p95 fell from 532.2 to 318.6 ms. All 40
cells in the final baseline/candidate pair passed exact protocol and payload
validation with zero failures or timeouts.

Focused frame-layer tests passed 38/38. The full solution passed 9,605 tests,
skipped five, and failed zero. Evidence is retained under
`C:\shared\temp\pl-h3-crosslayer-20260717`, including the A/B/A/B control
campaigns, sustained-duplex repetitions, traces, and benchmark output. These
shared-host results remain diagnostic. Nothing was deployed or published.

### Rejected 2026-07-17: borrowed HTTP/3 DATA-frame payload views

The post-`7ff46d04` buffered-upload trace attributed about 8.02 GiB of sampled
`System.Byte[]` allocation while validating 1.07 GiB of request payload. A
candidate added internal borrowed frame-payload views for buffered server and
client consumers while preserving the public owning parser API, diagnostics,
frame validation, payload ordering, and streaming-body ownership. The direct
64-frame fragmentation benchmark fell from 1,077.55 KiB to 48.2 KiB allocated
per operation, a 95.5% reduction.

The first integration intentionally retained the owning path whenever frame
diagnostics were enabled and therefore did not affect the ProtocolLab target.
The second emitted the same frame type, raw type, stream ID, and payload length
directly from borrowed views, but initially traded the owned payload copy for a
partial-frame suffix copy. A third design retained an unread offset and delayed
compaction until the next read. The trace then exposed the actual adapter path:
handlers that support any streaming route first create a streaming body reader,
and non-streaming `/echo`, `/hash`, `/sink`, and `/upload` requests buffer
through that reader. The final candidate covered that fallback as well.

Even after all real paths were covered, sampled byte-array allocation changed
only from 7.301 to 7.155 MiB per completed 1 MiB upload, about 2%. The clean c16
upload-sink gate completed five valid candidate cells with zero failures or
timeouts, but median throughput regressed from the accepted `7ff46d04` result
of 81.30 to 75.79 requests/s (-6.8%). Median p95 moved from 318.6 to 324.2 ms,
and relative throughput range worsened from 4.0% to 12.1%. The source and test
changes were reverted.

Retain the baseline, intermediate traces, clean candidate run, and machine-
readable negative result under `C:\shared\temp\pl-h3-crosslayer-20260717`.
Do not retry borrowed parser views without call-stack attribution showing that
owned HTTP/3 frame payloads are a material fraction of an end-to-end workload,
or a design that removes a broader copy boundary than frame parsing alone.

### Accepted 2026-07-17: retain server-owned buffered HTTP/3 request bodies

Call-stack analysis of the post-`7ff46d04` 1 MiB upload trace explained why
borrowed parser views had little end-to-end effect. In addition to fragmented
frame storage and the owned DATA payload, the non-streaming adapter fallback
copied that payload into an `ArrayBufferWriter<byte>` and then copied the
completed body again into `Http3Request`. The accepted change keeps public
request constructors defensively copying caller memory, but lets the server
retain memory it exclusively owns. A single non-empty DATA frame is transferred
directly into the request; multiple frames are concatenated only after the
second segment arrives, and the resulting owned writer memory is retained
without a final copy. Empty frames, frame ordering, content-length validation,
diagnostics, streaming handlers, cancellation, and transport behavior are
unchanged.

The matched c16 `gc-verbose` upload trace completed exact payload validation
with zero failures. Sampled `System.Byte[]` attribution fell from 8.406 to
5.435 billion bytes while completed requests rose from 1,098 to 1,245.
Normalized attribution therefore fell from 7.301 to 4.164 MiB per 1 MiB
request, a 43.0% reduction. The removed top stacks were request-body aggregation
and the final `Http3Request` copy. Trace throughput is attribution evidence only.

The first clean five-repetition candidate run was +10.6% versus the prior
accepted upload baseline but had 12.9% range, so a fresh parent-commit baseline
at `dcfaa8de` and second candidate run were executed back-to-back. Median upload
throughput improved from 89.30 to 92.21 requests/s (+3.3%), p95 improved from
277.1 to 272.5 ms (-1.7%), and candidate range was 5.4%. All ten cells passed
exact validation with zero failures or timeouts. The substantial allocation
reduction, rather than the modest shared-host throughput movement, is the
primary acceptance evidence.

Fresh five-repetition controls remained inside the normal guardrail:

| Lane | Baseline median | Candidate median | Throughput delta | p95 delta |
| --- | ---: | ---: | ---: | ---: |
| 1 MiB fixed response, c16 | 46.68 requests/s | 45.21 requests/s | -3.2% | -3.2% |
| 1.6 MiB streaming response, c16 | 28.22 requests/s | 28.05 requests/s | -0.6% | +1.6% |
| 64 KiB upload echo, c16, isolated rerun | 387.70 requests/s | 421.98 requests/s | +8.8% | -1.3% |
| 1 MiB simultaneous duplex, c1 | 23.43 requests/s | 25.63 requests/s | +9.4% | -1.9% |
| 100-stream multiplex, c1/s100 | 192.78 requests/s | 195.75 requests/s | +1.5% | +0.4% |

The initial mixed control command incorrectly forced the sustained duplex lane
to c16 even though that load tool is defined for one persistent connection; its
nonzero exits are preserved in `baseline2-h3-owned-controls-r5-h3-local-v1` and
are not treated as runtime evidence. Correct c1 duplex baseline/candidate runs
then passed all ten cells. Focused request ownership, empty-body, multi-frame,
and coalesced-body tests passed 6/6. The full Release solution passed 9,606
tests and skipped five, with one unrelated server-FIN recovery assertion failing
once before passing 5/5 exact reruns.

Evidence is retained under
`C:\shared\temp\pl-h3-crosslayer-20260717`, including the trace, two upload
candidate campaigns, fresh parent/candidate controls, corrected duplex runs,
multiplex runs, and the malformed-shape evidence. These are local shared-host
diagnostics, not isolated publishable claims. Nothing was deployed or
published.

### Accepted 2026-07-17: stream bounded HTTP/3 request DATA segments

ProtocolLab call-stack attribution on the accepted `9d9f86aa` source showed
that large request bodies were still assembled as complete `Http3DataFrame`
payloads before either a streaming handler or the buffered fallback could
consume them. At c16, the one-MiB upload trace attributed the dominant sampled
allocation to repeated `Http3FrameReader.Read` growth and final payload copies.
The sustained duplex trace showed the same whole-frame boundary in the direct
request-to-response streaming path.

The accepted reader parses frame headers incrementally, retains non-DATA frame
behavior, and emits DATA as owned segments bounded to 64 KiB. Buffered handlers
retain those owned segments and perform one exact final concatenation only when
more than one segment exists. Streaming handlers can consume segments before
the complete DATA frame arrives. Frame ordering, trailing headers, declared
frame diagnostics, content-length validation, truncation errors, cancellation,
single-enumeration behavior, and owned-memory lifetime remain intact.

The first implementation exposed two correctness and performance issues that
are retained as negative evidence. Its buffered fallback accidentally reused
an empty first-segment sentinel after aggregation began and omitted one 16 KiB
segment; ProtocolLab rejected the request with exact expected/received lengths.
After that fix, 16 KiB parser segments moved buffered cost into repeated
`ArrayBufferWriter` growth and increased duplex iterator pressure. The final
design retains segments and groups parser output at 64 KiB instead of trusting
remote Content-Length for eager allocation.

Final matched local diagnostics on the same shared host produced:

| Lane | Baseline median | Candidate median | Throughput delta | Baseline p95 | Candidate p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 MiB upload sink, c16 | 89.30 requests/s | 97.73 requests/s | +9.4% | 277.1 ms | 234.6 ms |
| 1 MiB simultaneous duplex, c1 | 23.43 MiB/s | 27.89 MiB/s | +19.0% | 35.0 ms | 33.6 ms |
| 1 MiB fixed response, c16 | 46.68 requests/s | 47.58 requests/s | +1.9% | 421.2 ms | 356.6 ms |
| 100x16 KiB streaming response, c16 | 28.22 requests/s | 30.50 requests/s | +8.1% | 698.5 ms | 548.0 ms |
| 64 KiB upload echo, c16 | 438.22 requests/s | 492.20 requests/s | +12.3% | 69.4 ms | 41.8 ms |
| 100-stream multiplex, c1/s100 | 192.78 requests/s | 198.25 requests/s | +2.8% | 101.3 ms | 100.0 ms |

Every valid candidate cell passed exact HTTP/3 and payload validation with zero
failed or timed-out requests. The c16 duplex load tool failed in all five
baseline and all five candidate cells, so that invalid shape is preserved but
excluded from comparison. An initial multiplex campaign was visibly disturbed
at 138.6-197.9 requests/s; the immediate repeat tightened to 192.0-202.4 and is
the reported diagnostic. A fresh detached baseline attempt failed before
readiness because ProtocolLab's source-root adapter `.deps.json` omitted the
source-backed QUIC assemblies; it is infrastructure evidence, not benchmark
evidence.

Final trace attribution is not used as a throughput claim. It reduced sampled
`System.Byte[]` allocation from 4.23 to 2.27 MiB per completed upload and from
1.26 to 1.07 MiB per duplex transfer. Exception event counts were unchanged.
Focused parser, large-body fallback, streaming, and System.Net HTTP/3 tests
passed 9/9 before the full regression gate.

Evidence is retained under
`C:\shared\temp\pl-h3-crosslayer-20260717`, including every failed validation,
intermediate 16 KiB trace and campaign, final repeated campaign, final trace,
disturbed multiplex run, and failed source-root baseline attempt. These are
shared-host diagnostics, not publishable isolated-hardware claims. Nothing was
deployed or published.

### Accepted 2026-07-17: lazily grow HTTP/3 request read buffers

The current 100-stream HTTP/3 multiplex call-stack trace showed that every
`Http3StreamingRequestBodyReader` eagerly rented its configured 16 KiB buffer,
including bodyless requests handled by the buffered fallback. The accepted
change starts each reader with at most 4 KiB and promotes it to the configured
size only after the first DATA segment is observed. Large uploads and duplex
requests therefore retain the sustained-body buffer size after their first
segment, while 100 simultaneously active bodyless readers request about
1.17 MiB less pooled capacity in aggregate.

The trace also preserved important non-candidates. Its runtime counter
collector allocated about 38 MiB of `Int32[][]`, and the forced counter stop
left a truncated output file, so trace allocation samples and trace throughput
are not used as an acceptance claim. The exception stream contained nine
HTTP/3 shutdown/control-path exceptions plus one channel-close and one
object-disposed event; that volume and attribution did not justify exception
path tuning. No raw QUIC transport change was attempted.

Fresh five-repetition shared-host diagnostics produced:

| Lane | Baseline median | Candidate median | Throughput delta | Baseline p95 | Candidate p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 100-stream multiplex, c1/s100 | 188.16 requests/s | 192.78 requests/s | +2.5% | 107.01 ms | 100.14 ms |
| 1 MiB fixed response, c16 | 32.01 requests/s | 32.58 requests/s | +1.8% | 532.89 ms | 494.85 ms |
| 100x16 KiB streaming response, c16 | 19.56 requests/s | 20.67 requests/s | +5.7% | 846.23 ms | 772.38 ms |
| 1 MiB upload sink, c16 | 64.30 requests/s | 65.12 requests/s | +1.3% | 384.23 ms | 367.48 ms |
| 1 MiB simultaneous duplex, baseline first | 18.42 requests/s | 17.50 requests/s | -5.0% | 51.22 ms | 50.31 ms |
| 1 MiB simultaneous duplex, candidate first | 16.51 requests/s | 17.84 requests/s | +8.1% | 53.03 ms | 51.50 ms |

All 40 baseline and 40 candidate cells passed exact protocol and payload
validation with zero failures or timeouts. The duplex throughput result changed
sign with execution order, while p95 improved in both orders; it is retained as
order-sensitive neutral evidence rather than an improvement claim. Multiplex
range narrowed from 11.6% to 5.8%. Other candidate ranges remained above the
publishable threshold, including 14.9% for upload and 12.8% for the reversed
duplex run.

A new 32-stream bodyless-request concurrency test passed. The first selected
HTTP/3 invocation passed 80 tests, skipped one, and retained one control-stream
close-observation timeout. The repeat passed 79, skipped one, and retained that
timeout plus an incomplete-content-length close timeout. Each exact close test
then passed 5/5 in isolation. The full Release solution passed 9,614 tests and
skipped five, with the incomplete-content-length close test timing out once;
its immediate post-suite rerun passed 5/5. These timing failures remain
explicit rather than being reported as a completely green invocation.

Evidence is retained under
`C:\shared\temp\pl-h3-crosslayer-20260717` in the
`baseline-h3-lazy-body-buffer-*`, `candidate-h3-lazy-body-buffer-*`,
`baseline2-h3-lazy-body-buffer-*`, and
`candidate2-h3-lazy-body-buffer-*` runs, plus the baseline and candidate
multiplex call-stack traces. These are shared-host diagnostics, not publishable
isolated-hardware claims. Nothing was deployed or published.

### Evidence correction 2026-07-17: HTTP/3 16 KiB response-write boundary remains unassessed

The current c16 fixed-response and streaming-response traces showed that the
HTTP/3 adapter creates 16 KiB DATA frames but submits each payload to QUIC as
four 4 KiB writes. A bounded experiment aligned the adapter write boundary to
the existing 16 KiB DATA-frame boundary. Focused source tests passed exact
delivery for 128 concurrent one-MiB HTTP/3 responses and for queued final writes
across 16 transport streams.

The associated ProtocolLab campaign cannot assess the candidate. Its target
adapter loaded package-backed QUIC and HTTP/3 assemblies dated 2026-05-31, not
the requested source tree containing the candidate. The recorded 7,303 truncated
responses remain useful evidence about that stale package build, but they do not
prove a candidate regression or a transport completion defect. The candidate is
reverted pending a correctly provenance-verified Release campaign.

Do not accept, reject, or tune adjacent write boundaries from this invalid
campaign. Any future source-backed run must verify that the source-built QPACK,
QUIC, and HTTP/3 assembly hashes exactly match the assemblies copied beside the
ProtocolLab adapter before load begins.

The failed campaign and machine-readable negative result are retained under
`C:\shared\temp\pl-h3-crosslayer-20260717\candidate-h3-16kb-write-boundary-r5-h3-local-v1`
and `C:\shared\temp\pl-h3-crosslayer-20260717\negative-results`. A correction
addendum is retained beside the original negative record. These are shared-host
diagnostic artifacts. Nothing was deployed or published.

### Accepted 2026-07-17: align HTTP/3 response writes to 16 KiB DATA payloads

A corrected Release campaign verified the source-built QPACK, QUIC, and HTTP/3
assembly hashes against the binaries copied beside the ProtocolLab adapter
before load. Five-repetition baseline/candidate runs then exercised fixed 1 KiB,
64 KiB, and one-MiB responses, 1.6 MiB streaming responses, one-MiB uploads, and
simultaneous one-MiB request/response streaming.

At c1, the 16 KiB boundary improved median throughput or request rate by 16.6%
for 1 KiB, 20.4% for 64 KiB, 16.9% for one-MiB, 29.0% for streaming, and 10.5%
for duplex. Upload request rate declined 2.5%. At c16, 1 KiB was neutral at
-0.2%, while 64 KiB improved 17.2%, one-MiB 6.0%, streaming 3.7%, and upload
2.9%. Every valid candidate cell had zero failed or timed-out requests. The c1
shared-host runs had material variance, so these are diagnostic medians rather
than isolated-hardware claims; the lower-variance c16 runs confirm no broad
regression and a substantial 64 KiB gain.

The requested c16 duplex shape was excluded because the load tool correctly
requires one connection and one stream for exact simultaneous-duplex proof; all
five valid c1 duplex repetitions passed. The focused source suite passed exact
queued final-write delivery and 128 concurrent one-MiB HTTP/3 responses. A broad
HTTP/3 run passed 1,115 tests with one skip and one known close-observation
timeout; that timing-sensitive test then passed 5/5 in isolation.
The final Release solution run passed 9,618 tests with five skips and no
failures.

Evidence is retained under
`C:\shared\temp\pl-h3-crosslayer-verified-20260717`, including per-run source
verification JSON. Nothing was deployed or published.

### Rejected 2026-07-17: bypass wildcard packet-information receive for HTTP/3

The accepted `f31b5979` response-write change was followed by a source-verified,
instrumented c16 one-MiB HTTP/3 run. It completed 489 exact responses with zero
failures or timeouts. Metrics instrumentation dominated sampled allocation, so
the instrumented throughput is attribution-only evidence. The first substantial
non-instrumentation allocation group was the wildcard UDP packet-information
path under `Socket.ReceiveMessageFromAsync`, principally `UInt16[]` and
`IPAddress` instances.

A reversible ProtocolLab adapter experiment bound the Incursa endpoint to the
concrete IPv6 loopback address, bypassing wildcard packet-information receipt
without changing the QUIC runtime. Five exact c16 repetitions regressed median
throughput from 38.04 to 37.21 MiB/s (-2.2%) and p95 latency from 439.91 to
450.27 ms. Both campaigns had zero failures and timeouts. The temporary adapter
change was reverted; the packet-information allocations are real but do not
justify a native receive rewrite from this evidence.

The same trace gives a stronger cross-layer direction: one active runtime shard
reached queue depth 69, 70 delayed application sends, about 558 KiB of retained
application-send payload, and mean STREAM-write completion around 5.5 ms.
Investigate application-send queue ownership, service ordering, wakeup
coalescing, and bounded batching next. Return to socket receive only if another
broad workload attributes a material end-to-end cost and supplies a plausible
mechanism.

Trace and negative evidence are retained under
`C:\shared\temp\pl-h3-crosslayer-verified-20260717` in the
`post-f31b-h3-1mb-c16-trace-direct-package-cell`,
`diagnostic-h3-ipv6loopback-c16-r5-direct-package-cell`, and
`negative-results` directories. These are shared-host diagnostics. Nothing was
deployed or published.

### Accepted 2026-07-17: cache bounded immutable HTTP/3 response frame sequences

The c16 one-MiB HTTP/3 trace showed paired small header writes and 16 KiB DATA
payload writes contributing separate stream actions, queue entries, and retained
buffers for every response frame. Immutable fixed responses already cached their
encoded headers and, for tiny bodies, one complete HEADERS-plus-DATA sequence.
The accepted change extends that existing ownership contract to cache the full
serialized HEADERS and DATA frame sequence for immutable fixed responses up to
2 MiB. Later requests submit bounded 16 KiB slices from that reusable sequence
without rebuilding every DATA header or copying the immutable body into fresh
frame arrays. Dynamic and streaming responses retain their existing behavior.

The cache has an explicit 2 MiB cap and a per-response construction gate.
Responses above the cap remain uncached, and immutable-body ownership is still
required. HTTP/3 frame boundaries, diagnostics, cancellation, final-write
semantics, content length, payload bytes, and FIN behavior are unchanged.

The development loop was moved to a new repo-local exact HTTP/3 harness rather
than continuing speculative ProtocolLab runs. It keeps certificate generation,
server startup, and warmup outside measured samples; validates exact HTTP/3,
content length, and every response byte; and reports five repeated samples for
64 KiB and one-MiB payloads at c1, c4, and c16. Separate baseline and candidate
binaries were run in A/B/B/A order. Combining ten samples per variant produced:

| Payload / concurrency | Baseline MiB/s | Candidate MiB/s | Throughput delta | Baseline/Candidate CV | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB / c1 | 41.18 | 47.58 | +15.5% | 20.0% / 18.9% | -11.4% | -14.1% |
| 64 KiB / c4 | 49.17 | 51.52 | +4.8% | 1.9% / 1.9% | -5.5% | -13.7% |
| 64 KiB / c16 | 46.30 | 47.09 | +1.7% | 2.8% / 5.1% | +4.2% | -13.4% |
| 1 MiB / c1 | 50.96 | 54.82 | +7.6% | 6.9% / 2.2% | -8.8% | -13.8% |
| 1 MiB / c4 | 53.30 | 53.15 | -0.3% | 1.3% / 5.8% | +1.6% | -21.0% |
| 1 MiB / c16 | 47.27 | 50.53 | +6.9% | 3.7% / 2.7% | -9.1% | -16.9% |

All 120 measured samples completed with zero failures. The noisy 64 KiB c1 row
is retained but not used alone as an acceptance claim. The stable rows show no
control regression beyond 5%, while the candidate reduces allocation in every
shape and meets the 20% allocation gate at one-MiB c4 without a timing
regression. The duplicate candidate passes differed by only 0.6-3.5% at c4/c16.

Earlier source-verified focused ProtocolLab candidate runs under
`C:\shared\temp\pl-h3-peer-current-20260717` also passed exact validation with
zero failures or timeouts and were directionally positive, but their detached
baseline changed from roughly 48 to 34 MiB/s during one campaign. Those lab
numbers are retained as shared-host confirmation and variance evidence, not as
the primary effect-size claim. A final c1 baseline that was already running when
the workflow changed completed cleanly; its candidate counterpart was
intentionally not launched.

The new cache concurrency, upper-bound, repeated large-response, and native
System.Net HTTP/3 concurrency tests passed 5/5. The full Release solution
completed with 9,623 passing tests, five skips, and one previously documented
incomplete-content close-observation timeout; that exact test then passed 5/5. Local
A/B artifacts are retained under
`C:\shared\temp\quic-http3-local-cache-20260717`. The local harness is a
same-process development surface, not isolated peer evidence. Nothing was
deployed or published.

### Local-first workflow 2026-07-17: cover broad HTTP/3 workload shapes

The repo-local exact loopback harness now covers fixed downloads, streaming
downloads, buffered uploads, and simultaneous streaming request/response echo.
It supports 1 KiB, 64 KiB, and one-MiB payloads plus c1/c4/c16 development
shapes without ProtocolLab orchestration. Upload handlers validate every request
byte, all clients validate exact HTTP/3, content length, and response bytes, and
duplex throughput accounts for both directions.

A 64 KiB c1 smoke completed every workload with zero failures. The single
diagnostic sample reported about 16-22 KiB allocated per request for fixed,
streaming, and duplex, but about 390 KiB per buffered upload plus 22 gen2
collections in one second. That one-second sample is not a performance claim;
it selects buffered upload for the next local allocation/exception trace before
any runtime candidate is proposed. ProtocolLab remains reserved for confirming
candidates that first pass the local gate.

### Accepted 2026-07-17: reuse the streaming frame parser for buffered request bodies

A five-second local 64 KiB buffered-upload trace at baseline `246fe779`
attributed nearly all managed allocation to three server-side byte-array paths:
761.55 MB copying complete HTTP/3 frame payloads, 481.66 MB repeatedly growing
the buffered request body, and 207.44 MB growing the frame reader's pending
buffer. The exact workload completed 3,144 requests at 39.04 MiB/s, allocated
about 390.3 KiB per request, and incurred 179 gen0, 89 gen1, and 89 gen2
collections. The trace and stack attribution are retained under
`C:\shared\temp\quic-http3-local-upload-trace-20260717`; the trace SHA-256 is
`9a006ba696b4234192b33538dd8ef5d4fbe7bf568f8e2bc76e1c998eadb99feb`.

The accepted change routes ordinary buffered request bodies through the existing
pooled streaming frame parser, then makes the one exact owned body copy required
by the buffered `Http3Request.Body` lifetime. It preserves the existing
headers-only fast path, streaming-handler selection and retention contract,
frame diagnostics, content-length validation, cancellation, and connection
error behavior. A first version that routed bodyless requests through the
streaming reader was immediately rejected after a quick local control showed a
roughly 24% fixed-download regression; it was refined rather than retained.

Separate baseline and candidate assemblies ran in A/B/B/A order. Each pass used
five exact one-second samples after warmup for 1 KiB, 64 KiB, and one-MiB
uploads at c1/c4/c16, plus 64 KiB fixed-download controls. Across 240 measured
samples there were no payload, content-length, protocol, or request failures.
Combined ten-sample medians were:

| Workload | Baseline MiB/s | Candidate MiB/s | Throughput delta | Baseline/Candidate CV | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 KiB upload / c1 | 2.24 | 2.08 | -7.0% | 27.1% / 26.2% | +3.5% | -14.8% |
| 1 KiB upload / c4 | 9.70 | 9.72 | +0.2% | 3.6% / 2.6% | -4.5% | -14.1% |
| 1 KiB upload / c16 | 13.36 | 13.02 | -2.5% | 3.1% / 7.5% | -5.1% | -15.0% |
| 64 KiB upload / c1 | 51.67 | 54.44 | +5.3% | 3.1% / 4.2% | -23.0% | -80.3% |
| 64 KiB upload / c4 | 85.48 | 90.11 | +5.4% | 6.8% / 2.0% | -10.5% | -80.3% |
| 64 KiB upload / c16 | 85.02 | 88.10 | +3.6% | 2.1% / 2.1% | -1.0% | -80.3% |
| 1 MiB upload / c1 | 80.69 | 86.72 | +7.5% | 11.3% / 2.8% | -5.0% | -82.2% |
| 1 MiB upload / c4 | 90.08 | 100.15 | +11.2% | 3.9% / 4.1% | -23.7% | -82.3% |
| 1 MiB upload / c16 | 89.91 | 90.95 | +1.2% | 3.2% / 11.1% | -18.6% | -81.8% |
| 64 KiB fixed / c1 | 37.19 | 36.82 | -1.0% | 33.7% / 32.1% | -2.4% | -1.3% |
| 64 KiB fixed / c4 | 51.24 | 49.31 | -3.8% | 3.0% / 4.6% | +8.2% | -0.3% |
| 64 KiB fixed / c16 | 47.17 | 46.54 | -1.3% | 2.5% / 3.6% | +1.1% | -0.3% |

The noisy c1 1 KiB and fixed rows are retained but are not used alone as effect
claims. Stable controls remain within the approximately 5% throughput guardrail.
The candidate passes the local gate through its repeated 80-82% large-upload
allocation reduction, removal of hundreds of gen2 collections, stable timing,
and the c4 one-MiB throughput and tail-latency gains.

A matching candidate trace reported about 76.8 KiB allocated per 64 KiB
request with no gen2 collections. The three baseline copy/growth stacks were
absent; the dominant remaining allocation was the single exact owned request
body array. Its trace SHA-256 is
`82d8ad285c03776ee2c41f3839eccfa67dfde233c039a27a3d602955c063b484`.
Baseline and candidate exception traces were identical: 19 shutdown-time
abort/cancellation exceptions each and no new steady-state exception pressure.
Candidate A/B, trace, allocation, and exception artifacts are retained under
`C:\shared\temp\quic-http3-buffered-reader-20260717`.

The existing ProtocolLab Incursa upload adapter intentionally selects
`IHttp3StreamingRequestHandler` for hash, sink, echo, upload, and duplex paths,
so those scenarios bypass this buffered API and cannot confirm its effect.
No ProtocolLab run was launched and no benchmark-only adapter switch was added.
The normal one-MiB exact-body test is now active rather than opt-in. The focused
HTTP/3 server and streaming-reader suite passed 83/83; the broader HTTP/3 run
passed 1,119 tests before two close-observation timeouts, both of which then
passed 5/5 in isolation. The final Release solution run passed 9,625 tests with
four intentional skips and no failures. Nothing was deployed or published.

### Local-first attribution 2026-07-17: correct the HTTP/3 allocation boundary

The broad local HTTP/3 harness completed fixed, streaming, upload, and duplex
workloads for 1 KiB, 64 KiB, and one-MiB payloads at c1, c4, and c16 with zero
validation failures. The one-MiB streaming and duplex rows plateaued at c16,
with medians of 46.90 and 68.36 MiB/s and p95 latencies of 351.56 and 527.93 ms.
The complete 18-shape result is retained at
`C:\shared\temp\quic-http3-broad-local-20260717\current-c73c88c9.json`.

Review found that each measured sample created its per-worker client receive
buffers after the allocation counter started. That setup is not request-path
work and distorted large-payload allocation most severely at high concurrency.
The corrected harness creates those buffers before starting allocation and
timing measurement. A five-sample one-MiB c16 check retained exact HTTP/3,
content-length, and payload validation with zero failures. Streaming allocation
fell from about 532.7 KiB to 178.4 KiB per request, confirming that most of the
previous growth was harness setup. Duplex remained about 1.12 MiB per request,
so its allocation pressure is not explained by that artifact. Corrected evidence
is retained under
`C:\shared\temp\quic-http3-broad-local-20260717\harness-boundary-corrected`.

A five-second verbose allocation trace of exact one-MiB c16 duplex traffic then
completed 144 requests with zero failures. Trace-instrumented throughput is
attribution-only. The largest stack was 89.36 MB of ACK-only protected-datagram
copies in `TryProtectAndAccountApplicationPayload`, followed by 33.65 MB of the
now-excluded harness receive-buffer setup, 18.18 MB of pooled stream receive
buffers, 11.25 MB of receive-ring buffers, and 5.41 MB of buffered-segment list
growth. The ACK-only copy alone was about 46% of the 195.75 MB sampled total and
is large enough to justify a bounded hosted-send ownership experiment. The trace
is retained under
`C:\shared\temp\quic-http3-broad-local-20260717\duplex-1mb-c16-attribution`;
its SHA-256 is
`8da796fe6211936fb7ac20cc4b83f11702cd3239393325f5aab989c9215777ff`.

### Rejected 2026-07-17: transfer ACK-only protected buffers through hosted sends

A hosted-runtime-only experiment transferred the existing pooled protected ACK
datagram through `QuicConnectionSendDatagramUpdate` and returned it after the
synchronous socket send. Public transition results retained their existing exact
owned arrays, and focused ACK timer ownership/return tests passed. The mechanism
removed the dominant ACK-only `ReadOnlyMemory.ToArray()` stack from the exact
one-MiB c16 duplex allocation trace.

The focused A/B/B/A lane used ten exact one-second samples per variant after
warmup. Median duplex throughput moved from 60.53 to 62.24 MiB/s (+2.8%), p95
improved 6.4%, and measured allocation fell 24.7%. Both variants were noisy,
with throughput CVs of 17.7% and 20.7%, so this was only an allocation gate and
not a throughput claim.

The required broader A/B/B/A controls rejected the candidate. Each row combined
ten samples per variant with exact protocol, content-length, and payload
validation and zero failures:

| Workload | c | Baseline MiB/s | Candidate MiB/s | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| fixed 64 KiB | 1 | 38.92 | 37.62 | -3.4% | -10.2% | -0.1% |
| fixed 64 KiB | 4 | 49.41 | 49.68 | +0.5% | +0.6% | -4.0% |
| fixed 64 KiB | 16 | 45.02 | 44.83 | -0.4% | +4.1% | -2.8% |
| streaming 1 MiB | 1 | 37.81 | 39.26 | +3.8% | -21.2% | -4.2% |
| streaming 1 MiB | 4 | 49.70 | 49.57 | -0.3% | +4.5% | -2.7% |
| streaming 1 MiB | 16 | 47.77 | 47.30 | -1.0% | -2.9% | -4.3% |
| upload 1 MiB | 1 | 86.85 | 77.84 | -10.4% | +11.6% | -2.4% |
| upload 1 MiB | 4 | 98.42 | 98.80 | +0.4% | +8.0% | -2.0% |
| upload 1 MiB | 16 | 100.15 | 90.70 | -9.4% | +19.3% | +1.5% |
| duplex 1 MiB | 1 | 45.74 | 49.46 | +8.1% | +1.7% | -13.4% |
| duplex 1 MiB | 4 | 69.19 | 67.57 | -2.4% | +2.4% | -14.3% |
| duplex 1 MiB | 16 | 65.46 | 65.71 | +0.4% | -0.8% | -5.1% |

The stable c16 upload regression exceeded the control guardrail. Candidate
attribution also showed the removed 89.36 MB exact-copy group replaced by about
106.10 MB of sampled `QuicBufferPool.RentBytes` allocation, versus 18.18 MB in
the baseline trace. Holding the protected ACK pool owner until hosted send
completion increased pool misses and moved allocation pressure rather than
removing it. The runtime and test changes were reverted. ProtocolLab was not
run because the candidate failed local controls.

Matched results are retained under
`C:\shared\temp\quic-http3-hosted-ack-owner-20260717`. The candidate trace SHA-256
is `8fb1ea2eb735e00e0a3fdde3f96565d9b1774fcc56a981256fbaa668c98de3ee`.

### Rejected 2026-07-17: lazily create public-stream completion delegates

The established public-stream allocation profile attributed about 23% more
managed allocation to Incursa than to System.Net.Quic. Sampled stacks included
three bound completion delegates created eagerly by every `QuicStream`, even
though a stream normally uses only one public write API family. A bounded
candidate created each delegate on first use after acquiring the existing write
gate. It preserved callback identity, delayed completion, cancellation,
disposal, exception propagation, and write serialization; the focused stream
and write suite passed 93/93.

Separate baseline `b38937bf` and candidate assemblies ran in A/B/B/A/A/B order
through the established one-KiB request/response profile. Each variant produced
six measured samples with one or two thousand operations per sample:

| Variant | Median ms/op | Range ms/op | CV | Median managed B/op | Allocation range |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 0.5545 | 0.528-0.601 | 4.36% | 4,051 | 4,024-4,082 |
| Candidate | 0.6015 | 0.570-0.650 | 5.03% | 3,794 | 3,765-3,817 |

The candidate reduced managed allocation by only 6.3% and regressed median
time by 8.5%. The harness reports aggregate operation time rather than a tail
latency distribution, so no tail claim is made. The candidate missed both the
allocation and end-to-end local gates and was reverted. Broader HTTP/3 controls
and ProtocolLab were intentionally not run.

Evidence is retained under
`C:\shared\temp\quic-stream-lazy-delegates-20260717`. The next investigation
must target a mechanism large enough to explain a substantial cross-layer gap,
not another per-stream micro-allocation.

### Local-first coverage 2026-07-17: matched established transport workloads

The permanent benchmark executable now exposes `--transport-loopback` for
matched Incursa.Quic and System.Net.Quic transfers on established connections.
It covers exact download, upload, and simultaneous duplex bodies at configurable
payload sizes and c1/c4/c16 concurrency. Certificate generation, listener and
connection setup, deterministic payload creation, and per-worker receive
buffers remain outside measurement. Every operation validates exact bytes,
length through EOF, and all public stream closure signals. Each cell receives a
fresh connection, and peer implementations run adjacent for the same shape.

Harness validation found two important API-ordering constraints. System.Net.Quic
does not surface a locally opened stream to the peer until its first write, so
the client write must start before awaiting server acceptance. Large bodies must
also be written and read concurrently to avoid normal QUIC flow-control
deadlock. The final one-KiB all-scenario peer smoke and one-MiB c1/c4/c16 smokes
completed with zero payload, EOF, stream-lifecycle, or benchmark failures.

The fresh-connection one-MiB c16 diagnostic sample was:

| Workload | Incursa MiB/s | System.Net MiB/s | Incursa B/op | System.Net B/op | Incursa/System.Net allocation |
| --- | ---: | ---: | ---: | ---: | ---: |
| download | 25.86 | 224.29 | 393,824 | 22,132 | 17.8x |
| upload | 33.42 | 205.93 | 412,360 | 21,167 | 19.5x |
| duplex | 36.64 | 263.34 | 886,147 | 37,892 | 23.4x |

These are single-sample diagnostics, not stable effect-size claims. They select
one-MiB c16 allocation and execution traces plus a five-repetition peer baseline
as the next work. The magnitude is sufficient to stop per-stream
micro-optimization: Incursa is competitive in the one-MiB c1 smoke but loses
throughput as concurrency exposes roughly 0.4-0.9 MiB of allocation per
operation. Evidence is retained under
`C:\shared\temp\quic-transport-local-peer-20260717`. ProtocolLab was not used.

### Rejected 2026-07-18: reuse terminal completion source for ordinary reads

The five-repetition one-MiB peer baseline confirmed that Incursa remains close
to System.Net.Quic at c1 but loses both throughput and allocation efficiency as
concurrency rises. At c16, Incursa produced 32.64 MiB/s download, 23.84 MiB/s
upload, and 33.50 MiB/s duplex while allocating about 404, 530, and 873 KiB per
operation. System.Net.Quic produced 251, 257, and 273 MiB/s while allocating
about 22, 22, and 37 KiB per operation. The full matched result is
`C:\shared\temp\quic-transport-local-peer-20260717\1mb-peer-r5.json`.

An allocation trace of exact one-MiB c16 duplex traffic attributed about
22.60 MB to the `QuicStream.ReadCoreAsync` state machine, 22.48 MB to
`SemaphoreSlim.WaitUntilCountOrTimeoutAsync`, 13.20 MB to cancellation promises,
and 8.75 MB to semaphore task nodes. This was sufficient attribution for a
bounded candidate that reused the stream's existing `IValueTaskSource<int>` for
the common single pending ordinary read while preserving the semaphore path for
concurrent readers. Focused tests covered sequential reuse, delayed ValueTask
consumption, concurrent-reader fallback, cancellation, abort, FIN, disposal,
and notification races; all 32 read-lifecycle tests passed.

The isolated pending-read BDN Short row reduced managed allocation from 321 to
144 B/read (-55.1%). Its three timing iterations were too short and variable for
an authoritative timing claim, although the candidate median was lower. Exact
c16 duplex A/B/B/A-style runs then produced five successful samples per clean
campaign:

| Variant | Median MiB/s | Throughput range | CV | Median p95 ms | Median B/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| Candidate A | 34.67 | 27.39-38.46 | 11.4% | 958.8 | 109,525 |
| Baseline B | 39.69 | 29.01-42.32 | 12.7% | 896.7 | 849,914 |
| Candidate C | 33.89 | 26.50-35.48 | 10.7% | 1,035.2 | 125,688 |
| Baseline D | 41.78 | 37.56-42.89 | 5.4% | 844.5 | 828,807 |

The candidate removed roughly 85% of measured allocation but regressed adjacent
median throughput by 12.6% and 18.9%, with worse p95 latency. It therefore
failed the no-timing-regression condition of the allocation gate and was
reverted. The first broader baseline attempt also retained an existing c16
failure, `The requested path cannot send an ordinary packet`, rather than being
silently discarded. A custom inline continuation was not pursued because it
would run arbitrary application continuation work on the runtime notification
path and weaken scheduling isolation and fairness. ProtocolLab was not run.

Candidate, baseline, BDN, failure, and trace artifacts are retained under
`C:\shared\temp\quic-read-completion-20260718` and
`C:\shared\temp\quic-transport-local-peer-20260717\incursa-duplex-1mb-c16-trace`.
The trace SHA-256 is
`b9c68ff6930b2b3fab80069de2e6cd1dc6c19a532bbeb8780edc73a15ba72772`.

### Local-first coverage 2026-07-18: bounded HTTP/3 runtime diagnostics

The exact HTTP/3 loopback harness now has an opt-in `--diagnostics true` mode
that records bounded per-series summaries from the existing `Incursa.Quic`
runtime and buffer-pool metrics. The normal path remains uninstrumented. The
diagnostic path polls observable gauges every 100 ms and reports queue and
service delay, work-item depth and rates, wakeups, work per wake, stream-write
completion, delayed sends by cause, receive/send/retransmission retention,
buffer-pool pressure by owner and size bucket, and byte/datagram totals.
Counter output distinguishes event sums from cumulative observable-counter
deltas. Instrumented samples are explicitly marked diagnostic-only because the
listener affects timing and allocation.

An uninstrumented one-KiB fixed-response smoke and an instrumented 64-KiB c4
duplex smoke both passed exact HTTP/3, content-length, payload, and EOF
validation. The exact one-MiB c16 duplex attribution run then completed 112
requests with zero failures. Its 42.73 MiB/s timing is not a performance claim.
All 16 streams shared one connection and one runtime shard. During the
five-second measured interval that shard processed 119,284 packet-receive work
items, spending 4,255.76 ms in their measured service intervals, plus 650.14 ms
on 14,560 stream-write items. Packet-receive queue delay averaged 18.20 ms and
reached 51.09 ms at p95 in this instrumented run; stream-write completion
averaged 5.00 ms and reached 12.47 ms at p95. The actor is therefore saturated
by aggregate per-packet work rather than by wakeup frequency or one isolated
CPU method.

The server received 122,474,009 bytes in 119,284 datagrams, about 1,027 bytes
per datagram, and sent 123,225,147 bytes in 164,867 datagrams, about 747 bytes
per datagram. Buffer-owner counters recorded 49,649 acknowledgment rents,
119,284 inbound packet-protection rents, and 329,734 outbound packet-protection
rents. These counts justify investigating general packet count, packetization,
and ACK/data coalescing mechanisms from broader HTTP/3 evidence. They do not by
themselves justify weakening ACK behavior or assuming a larger path MTU.

The CPU trace and metrics evidence are retained under
`C:\shared\temp\quic-http3-local-first-20260718`. The earlier intermittent c16
ordinary-packet failure did not reproduce in 60 additional exact duplex
samples, so no speculative PMTU fix was made. No ProtocolLab run was launched.

### Accepted diagnosis 2026-07-18: validate a larger path datagram ceiling

The cross-scenario one-MiB c16 diagnostic run showed that Incursa's HTTP/3
upload path received 478,006,135 bytes in 324,745 datagrams, or 1,471.94 bytes
per datagram, while download and duplex responses remained constrained by the
runtime's permanent 1,200-byte path ceiling. This broad workload attribution
was sufficient to test the packet-count mechanism without changing any QUIC
recovery, scheduling, or stream behavior.

A reversible candidate changed only the initial path ceiling from 1,200 to
1,472 bytes. Committed baseline and candidate assemblies ran in A/B/B/A order,
with five exact one-MiB c16 samples per variant and shape. All 40 samples passed
payload, content-length, EOF, and protocol validation:

| Workload | Baseline median | Candidate median | Throughput delta | Baseline p95 | Candidate p95 | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| fixed response | 47.03 MiB/s | 60.46 MiB/s | +28.6% | 423.68 ms | 295.50 ms | -17.4% |
| duplex | 64.77 MiB/s | 74.05 MiB/s | +14.3% | 549.95 ms | 491.79 ms | -3.4% |

Fixed-response coefficient of variation was 9.33% baseline and 8.19%
candidate; duplex was 2.21% and 2.17%. The mechanism passes the local timing
gate, but an unconditional 1,472-byte default would assume an unvalidated path
MTU and was reverted. The accepted product direction is a bounded DPLPMTUD
probe: ordinary traffic must remain at 1,200 bytes until an exact padded probe
is acknowledged, and loss must leave the ceiling unchanged. No ProtocolLab run
was launched for the unsafe default candidate.

Evidence, assembly hashes, commands, per-sample results, and the combined
summary are retained under
`C:\shared\temp\quic-http3-local-first-20260718\pmtu-1472-experiment`.

### Accepted 2026-07-18: timer-gated validated path datagram ceiling

The runtime now keeps ordinary packets at the safe 1,200-byte QUIC minimum and
uses one bounded DPLPMTUD discovery attempt per validated path record. After
application stream data is acknowledged, a dedicated one-millisecond timer is
armed. The timer sends an exact PING-plus-PADDING probe only when the same path
is still active, no application write or retransmission is queued, and no
ack-eliciting packet remains in flight. The target is 1,472 bytes for IPv4 and
1,452 bytes for IPv6 or an unresolved address, capped by the peer's advertised
`max_udp_payload_size`. Only a matching acknowledgment raises the path's
ordinary datagram ceiling; loss removes outstanding tracking and leaves the
ceiling unchanged.

Three trigger placements were rejected before the timer design was accepted.
Immediate post-handshake probing failed 14 full-suite tests. Inline probing
from ACK processing failed 9 tests by consuming recovery/application-send
budget. Posting a follow-on actor event still allowed synchronous dispatcher
reentrancy, and an idle ACK send still violated ACK transitions that must emit
no datagram. The timer design passed the focused PMTU/recovery set (44/44) and
the broader timer/recovery/metrics set (104/104) without weakening those tests.

Committed baseline and final timer-candidate assemblies ran in adjacent
A/B/B/A order for fixed and duplex one-MiB c16 workloads. Ten exact samples per
variant and shape produced zero failures:

| Workload | Baseline MiB/s | Candidate MiB/s | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| fixed 1 MiB c16 | 46.44 | 58.01 | +24.9% | -18.8% | -16.8% |
| duplex 1 MiB c16 | 65.48 | 73.35 | +12.0% | -10.1% | -2.4% |

The broader baseline/candidate/baseline control campaign covered fixed,
streaming, upload, and duplex workloads at 1 KiB, 64 KiB, and 1 MiB and c1, c4,
and c16. All 36 cells and 540 measured samples passed exact protocol, content
length, payload, and EOF validation. Two short one-second cells crossed the
approximately five-percent guardrail and were repeated with adjacent
three-second, seven-sample A/B/A runs. The repeat cleared both concerns: fixed
1 KiB c1 was +3.3% throughput with p95 +3.9%, and upload 1 MiB c16 was +4.6%
throughput with p95 +1.3%. No stable control regression remained.

Evidence is retained under
`C:\shared\temp\quic-http3-local-first-20260718\pmtu-dplpmtud-candidate`,
including `timer-summary.json`, `timer-control-summary.json`,
`timer-suspect-summary.json`, hosted smoke/diagnostic results, binaries, logs,
and focused TRX files. The final Release build completed with zero warnings and
errors. The full Release test-project rerun passed 9,631 tests with four
explicit skips and zero failures. Two integration tests that failed once under
the first full-suite load each passed five immediate isolated reruns before the
clean full-suite rerun.

The smallest matching ProtocolLab confirmation then ran the one-MiB c16 HTTP/3
scenario in adjacent baseline/candidate/baseline order with five repetitions
per pass. Source assembly verification proved clean `9eeaecd2` baseline and
`f6acad6b` candidate inputs. Across the ten baseline and five candidate cells,
median throughput increased from 52.36 to 61.79 requests/s (+18.0%) and median
p95 latency fell from 315.77 to 267.80 ms (-15.2%). Throughput CV was 2.14%
baseline and 1.64% candidate. All 15 cells passed exact HTTP/3 validation with
zero failed or timed-out requests. The confirmation summary and normal evidence
bundles are retained under
`C:\shared\temp\pl-h3-pmtu-confirmation-20260718`.

This confirmation is shared-host local-lab evidence, not isolated-hardware or
peer-comparison proof, and no public claim is made. Repeated PMTU search with
bounded retry/backoff remains future work; do not replace the safe initial
ceiling or repeat the rejected trigger placements.

### Local-first diagnosis 2026-07-18: c16 upload congestion-window growth stalls without loss

The transport loopback harness now has an opt-in `--diagnostics true` mode for
Incursa samples. It captures bounded summaries from the existing runtime,
buffer-pool, byte, and datagram meters and marks every instrumented sample as
diagnostic-only. The normal benchmark path remains uninstrumented. A new
bounded runtime counter records detected packet losses by endpoint role and
packet-number space so congestion-window attribution no longer has to infer
loss from retained packet state.

A fresh uninstrumented five-repetition one-MiB c1/c4/c16 peer campaign retained
Incursa's competitive c1 result but reproduced the c16 collapse. At c16,
Incursa produced 24.81 MiB/s download, 21.99 MiB/s upload, and 31.67 MiB/s
duplex while System.Net.Quic produced 185.98, 190.30, and 212.71 MiB/s. Incursa
allocated 17.74x, 18.30x, and 20.24x as many managed bytes per operation in
those three lanes. All payload and protocol validation passed. The evidence is
`C:\shared\temp\quic-transport-local-first-20260718\post-pmtu-peer\1mb-c1-c4-c16-r5.json`.

The c16 upload CPU trace did not expose a single hot method large enough to
explain the gap. The process spent most of the interval waiting; runtime inbox
consumption accounted for about 5.96% inclusive CPU, packet receive for about
2.29%, endpoint send for about 1.73%, listener send for about 1.21%, and socket
send for about 0.3%. This points to queueing or send-credit progression rather
than a CPU-bound send primitive. Trace artifacts are under
`C:\shared\temp\quic-transport-local-first-20260718\post-pmtu-cpu`.

Instrumented c1 and c16 one-MiB upload samples then isolated the mechanism. The
c16 sample spent the measured interval with a weighted congestion-window mean
of about 338 KiB and a maximum of about 460 KiB, while bytes in flight averaged
about 337 KiB and available send budget averaged only 738 bytes. It recorded
32,808 congestion-limited flushes, an application-send queue mean of 20.4
writes and maximum of 27, about 660 KiB average retained application data, and
about 298 average retained sent packets. Stream-write completion averaged
34.2 ms and reached about 42.8 ms at p95; sender queue delay averaged about
22 ms and reached about 33 ms at p95. The comparable c1 sample grew its window
from about 6.8 MiB to 50.5 MiB and had roughly 1 ms write completion and queue
delay.

The loss-instrumented repeat recorded zero detected packet losses at both c1
and c16. Therefore the small c16 window was not a loss response: it remained
full but failed to grow. The current congestion helper subtracts acknowledged
bytes before deciding whether `bytes_in_flight < congestion_window`, which
makes a previously full sender appear underutilized after every ACK unless a
separate pacing-limited signal happens to be present. The next bounded
candidate is to evaluate congestion-window utilization from the pre-ACK state,
while preserving explicit application-limited and flow-control-limited
suppression. This is a standards/correctness hypothesis that requires focused
RFC 9002 tests and adjacent local A/B evidence before acceptance. No
ProtocolLab run has been launched.

Instrumented evidence is retained under
`C:\shared\temp\quic-transport-local-first-20260718\runtime-diagnostics` and
`C:\shared\temp\quic-transport-local-first-20260718\runtime-loss-diagnostics`.

### Rejected 2026-07-18: pre-ACK congestion-window utilization classification

A reversible candidate captured whether the congestion window was fully used
at ACK-frame entry and applied that classification to every packet acknowledged
by the frame. It preserved application-limited, flow-control-limited, recovery,
and pacing suppression, and its focused RFC 9002 and runtime ownership set
passed 24/24 tests. Baseline and candidate assemblies were frozen with SHA-256
`4446ab41938ddbcea959a3b4cced805b6dc67ca8de9ec106bdff3cab0b24d5e0`
and `a9413e45c363b1cbd3c614a43350f62deae0abd445bd3d93f343d895685420e7`.

Adjacent A/B/B/A one-MiB upload and duplex runs covered c1, c4, and c16 with
ten exact samples per variant and cell. All 120 measured samples passed:

| Lane | Baseline median | Candidate median | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| upload c1 | 35.84 MiB/s | 36.31 MiB/s | +1.3% | -3.8% | +1.5% |
| upload c4 | 27.74 MiB/s | 27.83 MiB/s | +0.3% | -4.4% | +2.4% |
| upload c16 | 22.32 MiB/s | 22.44 MiB/s | +0.5% | -1.3% | +0.4% |
| duplex c1 | 42.21 MiB/s | 39.74 MiB/s | -5.9% | +3.2% | +6.7% |
| duplex c4 | 40.44 MiB/s | 39.85 MiB/s | -1.5% | +3.2% | +0.7% |
| duplex c16 | 28.19 MiB/s | 30.91 MiB/s | +9.6% | -10.3% | -5.4% |

The candidate failed the local acceptance gate because upload remained flat
and the c1 duplex control crossed the approximate five-percent guardrail. More
importantly, an instrumented candidate c16 upload sample proved that the window
did grow: its observed client window ranged from about 6.1 MiB to 39.9 MiB,
with tens of MiB of available send credit. Throughput still remained only
18.82 MiB/s in that diagnostic sample, while 21,602 recovery flushes stopped at
`burst_limit_reached` and stream-write completion averaged 25.5 ms. The small
baseline congestion window was therefore real but not the dominant throughput
limit. The candidate was reverted and ProtocolLab was not run.

Evidence, binaries, hashes, per-pass logs, combined statistics, focused TRX,
and the candidate diagnostic run are retained under
`C:\shared\temp\quic-cwnd-preack-20260718`. Do not repeat congestion-growth
variants without new evidence. The next highest-confidence mechanism is the
runtime's bounded flush progression and whether it schedules enough follow-up
work after reaching the four-datagram burst cap.

### Rejected 2026-07-18: timer-driven bounded application-send continuation

A reversible candidate replaced the application-send timer's single-datagram
continuation with the existing bounded four-datagram recovery flush policy. It
kept the established per-transition cap and 1 ms follow-up timer, so it did not
repeat the rejected larger fixed burst or ACK-byte-credit designs. A focused
requirement-home test proved that one timer expiration emitted exactly one
additional bounded tranche. The stream API, standalone FIN scheduling, and
send-policy set passed 32/32 tests after congestion-blocked timer re-arming was
preserved.

Frozen baseline and candidate assemblies had SHA-256
`4446ab41938ddbcea959a3b4cced805b6dc67ca8de9ec106bdff3cab0b24d5e0`
and `574918ecdcc34a8798caeffd69305083bd7693ac96383c6c231e7dca26f26c2d`.
Two successful passes per variant covered exact one-MiB upload and duplex at
c1, c4, and c16, producing ten successful samples per variant and cell:

| Lane | Baseline median | Candidate median | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| upload c1 | 36.87 MiB/s | 35.40 MiB/s | -4.0% | +2.4% | -2.5% |
| upload c4 | 28.59 MiB/s | 27.68 MiB/s | -3.2% | +3.7% | -1.6% |
| upload c16 | 21.12 MiB/s | 22.10 MiB/s | +4.6% | -6.4% | -7.7% |
| duplex c1 | 39.67 MiB/s | 44.21 MiB/s | +11.4% | -7.2% | -11.1% |
| duplex c4 | 39.24 MiB/s | 39.81 MiB/s | +1.5% | -2.9% | -1.6% |
| duplex c16 | 32.62 MiB/s | 29.55 MiB/s | -9.4% | +18.2% | -5.1% |

The candidate failed the local gate because c16 duplex throughput regressed
9.4% and p95 latency regressed 18.2%. Low-concurrency upload also regressed.
The runtime and test changes were reverted and ProtocolLab was not run. The
campaign additionally retained one baseline attempt that aborted at the first
c16 duplex sample with `The requested path cannot send an ordinary packet`;
two subsequent baseline passes completed, so this is intermittent baseline
fragility rather than a candidate-only failure.

Evidence, frozen binaries, hashes, candidate diff, exact commands, successful
per-pass JSON, aggregate statistics, and the failed-baseline record are under
`C:\shared\temp\quic-timer-burst-20260718`. Do not retry a timer-driven
multi-datagram continuation or another minor burst variant without materially
new attribution. Two distinct bounded flush-progression designs have now
failed the local gate. Reassess the broader end-to-end HTTP/3 traces for a
cross-layer queue, copy, write-completion, or API-usage mechanism before
changing raw send progression again.

### Diagnosed 2026-07-18: current HTTP/3 upload and duplex allocation paths

Fresh post-PMTU EventPipe traces used the current accepted runtime rather than
the superseded response-cache and buffered-request candidates. Exact one-MiB
c16 upload completed 276 requests with zero failures. Its dominant sampled
allocation was the one exact owned request-body array created by
`ReadBufferedRequestAsync`; that copy is required by the durable
`Http3Request.Body` lifetime, while the high-throughput streaming handler used
by ProtocolLab bypasses it. Pooling or removing that copy without changing the
public ownership contract is not a valid candidate. Evidence is under
`C:\shared\temp\quic-http3-current-upload-20260718`; the nettrace SHA-256 is
`63887582b83d9abb23ed17b760b7ae922955b1d23206754286bebab23ac3f21d`.

Exact one-MiB c16 duplex completed 128 requests with zero failures. Its largest
sampled runtime stack was 84.54 MB of frequent small ACK-only ownership copies
in `TryProtectAndAccountApplicationPayload`, reached from
`TrySendPendingApplicationAck`. This confirms the broader-workload mechanism
after the PMTU change without repeating the rejected hosted ACK-owner design.
Evidence is under `C:\shared\temp\quic-http3-current-duplex-20260718`; the
nettrace SHA-256 is
`d3ae513d075572428998d8dc182c9788eff8897168cf7e70da0af2e9dda9ea8e`.

Diagnostic-only runtime metrics now classify application ACK sends as
standalone or piggybacked and record queued application-write depth at emission.
The instruments exit before tag construction when disabled. A five-second c16
duplex sample recorded 39,288 standalone ACKs, including 12,127 emitted while
application data was already queued (median queue depth 2, p95 9), and 12,153
piggybacked ACKs. The baseline diagnostics are retained under
`C:\shared\temp\quic-http3-ack-policy-20260718`.

### Rejected 2026-07-18: prefer one queued DATA packet when an ACK is due

A reversible policy candidate used one existing queued application send to
carry a due ACK before falling back to a standalone ACK-only packet. It kept the
ACK deadline, congestion and amplification checks, retransmission priority, and
the one-datagram local bound. It did not transfer ACK buffer ownership or change
the rejected timer continuation. Focused ACK, RFC 9000 piggyback, send-delay,
and metrics tests passed 35/35.

The focused A/B/B/A c16 one-MiB duplex campaign used separate baseline and
candidate assemblies and ten exact samples per variant. All samples passed:

| Variant | Median MiB/s | Range MiB/s | CV | Median p95 ms | Median allocated B/request |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 52.11 | 37.45-54.46 | 12.54% | 709.87 | 956,052 |
| candidate | 53.38 | 38.73-54.58 | 11.50% | 692.61 | 953,642 |

The candidate improved median throughput 2.4%, p95 2.4%, and allocation 0.25%,
which is below the local promotion gate. A diagnostic candidate run confirmed
the mechanism: standalone ACKs emitted with queued data fell from 12,127 to
zero, while piggybacked ACKs with queued data rose from 11,989 to 15,659. The
policy change and its test were reverted. ProtocolLab was not run.

Evidence, frozen assemblies, hashes, candidate diff, diagnostics, transcripts,
per-pass JSON, and aggregate statistics are retained under
`C:\shared\temp\quic-http3-ack-policy-20260718`. Do not repeat minor standalone
ACK scheduling variants without a mechanism likely to exceed the local gate.

### Rejected 2026-07-18: dedicated bounded ACK datagram pool

A materially different follow-up to the rejected hosted ACK-owner transfer
copied protected ACK-only datagrams into a dedicated bounded `ArrayPool<byte>`
and returned the general protected-packet buffer immediately. Hosted sends
carried explicit pool ownership through the existing synchronous send observer;
direct transition results retained exact owned arrays. A focused hosted ACK
deadline test verified packet protection, owner classification, and release.

The local A/B/B/A c16 one-MiB simultaneous duplex campaign used frozen baseline
and candidate assemblies, five exact samples per pass, and ten samples per
variant. All samples completed with zero payload-validation failures:

| Variant | Median MiB/s | Range MiB/s | CV | Median p95 ms | Median allocated B/request |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 51.58 | 30.86-54.89 | 13.77% | 729.35 | 807,278 |
| candidate | 50.11 | 32.92-54.03 | 13.23% | 731.20 | 912,893 |

The candidate regressed median throughput 2.9%, did not improve latency, and
increased median process allocation 13.1%. It therefore failed both the timing
and allocation gates. The runtime and focused-test changes were reverted, and
ProtocolLab was not run. Frozen candidate binaries and all four per-pass JSON
reports are retained under
`C:\shared\temp\quic-http3-ack-dedicated-pool-20260718`. Do not repeat ACK
storage-pool or hosted ACK-owner variants without new attribution that explains
why they would improve the saturated single-shard actor rather than only move
buffer ownership.

### Rejected 2026-07-18: align HTTP/3 response writes to 32 KiB

The c16 HTTP/3 diagnostics recorded 11,050 stream-write work items and about
650 ms of stream-write service in a five-second one-MiB duplex interval. A
bounded candidate doubled the default HTTP/3 DATA-frame and response-write
boundary from 16 KiB to the transport's existing 32 KiB maximum. It did not
change QUIC packetization, transport write limits, flow control, congestion
control, recovery, or final-write behavior. Eight focused large-response,
one-MiB, concurrent, streaming, and System.Net HTTP/3 interoperability tests
passed.

Frozen A/B/B/A assemblies then ran exact one-MiB fixed, streaming, and
simultaneous duplex workloads at c16, with five samples per pass and ten samples
per variant and lane. All 60 samples passed payload, content-length, EOF, and
protocol validation:

| Lane | Baseline MiB/s | Candidate MiB/s | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| fixed | 41.48 | 38.74 | -6.6% | +5.2% | +0.9% |
| streaming | 39.29 | 39.72 | +1.1% | -1.6% | -0.1% |
| duplex | 50.20 | 50.16 | -0.1% | -0.3% | -8.7% |

The fixed-response regression crossed the normal control guardrail, while the
affected streaming and duplex lanes did not provide a timing gain or the 20%
allocation reduction needed for promotion. The one-line runtime candidate was
reverted and ProtocolLab was not run. Frozen binaries and all four JSON reports
are retained under `C:\shared\temp\quic-http3-write32k-20260718`. Do not retry
larger HTTP/3 response write or DATA-frame boundaries without new attribution
that explains the fixed-response regression and predicts a broader gain.

### Rejected 2026-07-18: Windows UDP segmentation for listener send batches

The saturated c16 one-MiB duplex CPU trace attributed about 4.87 seconds to
`QuicListenerHost.SendDatagram`, including about 2.46 seconds in native socket
send and 1.96 seconds in GC polling. A standalone exact Windows loopback probe
combined four 1472-byte payloads with `UDP_SEND_MSG_SIZE` and reduced median
sender time from 180.35 ms to 105.58 ms (-41.5%) across seven interleaved
repetitions. All 140,000 measured datagrams preserved exact length and order.
This was materially different from the rejected Linux `sendmmsg` path because
it used one buffer and one socket call without native per-datagram allocation.

A bounded QUIC candidate added a synchronous contiguous send-batch observer
that retained detached packet owners until callback completion. The Windows
IPv4 listener combined only consecutive same-path, same-ECN, exact-1472-byte
datagrams, up to the UDP payload limit. Custom senders, Linux packet-info,
IPv6-sized packets, mixed runs, and singleton sends retained the existing path.
The build had zero warnings; ten focused socket and pooled-owner tests and ten
large, concurrent, upload, and System.Net.Quic HTTP/3 tests passed.

Frozen A/B/B/A executables then ran exact one-MiB fixed, streaming, and duplex
workloads at c1, c4, and c16. Five samples per pass produced ten samples per
variant and lane. All 180 samples passed payload, content-length, EOF, and
protocol validation:

| Lane | Baseline MiB/s | Candidate MiB/s | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| fixed c1 | 47.41 | 46.73 | -1.4% | +2.6% | -3.9% |
| fixed c4 | 46.55 | 47.07 | +1.1% | -1.9% | +0.1% |
| fixed c16 | 42.91 | 42.54 | -0.9% | +0.7% | +1.8% |
| streaming c1 | 43.46 | 43.01 | -1.0% | +1.2% | +2.5% |
| streaming c4 | 43.78 | 42.99 | -1.8% | -1.7% | +5.7% |
| streaming c16 | 40.44 | 40.68 | +0.6% | -0.9% | +2.5% |
| duplex c1 | 54.74 | 54.97 | +0.4% | +0.8% | +0.3% |
| duplex c4 | 55.23 | 55.31 | +0.1% | +1.5% | +7.0% |
| duplex c16 | 52.31 | 51.65 | -1.3% | +4.0% | +19.0% |

The socket-only gain did not translate to HTTP/3, and duplex c16 allocation
rose materially. Real transitions likely expose too few compatible consecutive
datagrams to offset the pooled concatenation buffer and full payload copy. The
candidate was reverted and ProtocolLab was not run. Frozen executables, all
four JSON reports, logs, hashes, and the design record are retained under
`C:\shared\temp\quic-http3-windows-udp-segmentation-20260718`; the standalone
probe is under `C:\shared\temp\udp-segmentation-probe-20260718`. Do not repeat
listener-level datagram aggregation without evidence of materially larger
compatible runs and a zero-copy lifetime design. Reassess above the socket-send
layer for a broader HTTP/3 mechanism.

### Rejected 2026-07-18: immediate asynchronous Windows UDP submission

The c16 one-MiB HTTP/3 duplex CPU trace showed one connection actor saturated,
with listener datagram submission occupying the largest inclusive runtime
stack. This materially different follow-up to the rejected sender queue tested
whether submitting each datagram to Windows immediately with
`Socket.SendToAsync` could remove synchronous actor cost while keeping recovery
accounting adjacent to OS submission. It did not add an intermediate queue.

An out-of-repo exact loopback probe compared cached-address synchronous sends
against 64 bounded outstanding asynchronous sends in sync/async/async/sync
order. Eight measured samples per mode each sent 10,000 exact 1,200-byte
datagrams. All 160,000 measured datagrams arrived with exact length and payload:

| Mode | Sender median | Range | CV | End-to-end median | Process CPU median | Allocation median |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| synchronous | 88.11 ms | 81.61-115.30 ms | 11.87% | 88.13 ms | 226.56 ms | 1,440,576 B |
| asynchronous | 90.83 ms | 86.76-110.14 ms | 8.48% | 90.85 ms | 234.38 ms | 1,442,320 B |

Immediate asynchronous submission was 3.1% slower at the median and did not
reduce CPU or allocation. No runtime code was changed and ProtocolLab was not
run. The probe source and JSON are retained under
`C:\shared\temp\udp-sync-async-send-probe-20260718`. Do not replace the
synchronous listener send with `SendToAsync` without a materially different OS
mechanism and new end-to-end attribution. Continue above the socket layer with
packet-count and per-packet actor-service work.

### Diagnosed 2026-07-18: same-connection receive packet runs

The exact one-MiB c16 simultaneous HTTP/3 duplex workload confirmed that the
single connection actor usually has several receive packets ready together. A
disabled-by-default histogram now records consecutive same-runtime packet runs
and their bounded termination reason. In a five-second diagnostic sample,
98,025 packet-receive work items formed 9,133 runs terminated by another work
item: mean 10.73 packets, median 4, p95 55, p99 135, and maximum 732. The same
sample completed 95 exact requests with no failures and recorded 23,097
application-send recovery flushes. The diagnostic evidence is retained under
`C:\shared\temp\quic-http3-packet-runs-20260718`; do not infer a batching gain
from this trace because metric collection materially perturbs the actor.

The disabled instrumentation path was also checked separately against the
clean `b17880ff` baseline. Frozen `Incursa.Quic.dll` SHA-256 values were
`BCEB0730FBD7F34FE9E16415CF890C98D4B88894D9B5410A76AB36A7FBC5DD7E`
and `E70CF48060C5B3C53FB9294B83F69C81839E5E6E258FFC2677A532EEAE408AA7`.
An A/B/B/A campaign produced ten exact c16 duplex samples per variant: baseline
50.36 MiB/s median, 26.63-52.49 range, 17.67% CV, and 736.14 ms p95 versus
instrumentation 50.65 MiB/s median, 40.54-52.26 range, 7.96% CV, and 720.13 ms
p95. The disabled path therefore showed no timing or allocation regression.
Raw evidence is under
`C:\shared\temp\quic-packet-run-instrumentation-20260718`.

### Rejected 2026-07-18: defer application-send recovery flushes across packet runs

A bounded candidate used channel lookahead to defer only application-send
recovery flushing across at most eight consecutive packets for the same
connection. Packet decryption, frame handling, stream delivery, ACK generation,
ACK deadlines, retransmission processing, flow-control updates, timer handling,
and effect publication remained per packet. Twelve focused ACK, recovery-flush,
and metrics tests passed.

The frozen baseline and candidate `Incursa.Quic.dll` SHA-256 values were
`BCEB0730FBD7F34FE9E16415CF890C98D4B88894D9B5410A76AB36A7FBC5DD7E`
and `96B4B3E0080D0F0C4F868DCE9E3C762145B435D1274338A5B65FD95CADA16972`.
An A/B/B/A campaign ran five exact three-second one-MiB c16 duplex samples per
pass, for ten samples per variant and no payload or protocol failures:

| Variant | Median MiB/s | Range MiB/s | CV | Median p95 ms | Median allocated B/request |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 50.16 | 38.92-54.39 | 10.38% | 705.24 | 924,343 |
| candidate | 52.34 | 32.33-53.81 | 16.10% | 875.47 | 660,794 |

Although median throughput improved 4.3% and allocation fell 28.5%, p95 latency
regressed 24.1% and throughput variance increased materially. The candidate
therefore failed the local timing and stability gates and was reverted.
ProtocolLab was not run. Frozen binaries, raw A/B/B/A JSON, logs, and diagnostic
results are retained under
`C:\shared\temp\quic-packet-flush-batch-20260718` and
`C:\shared\temp\quic-http3-packet-runs-20260718`. Do not defer send-queue
progress across receive packets again without a design that preserves prompt
application-data scheduling; the run-length metric remains as attribution for
materially different packet-processing designs.

### Rejected 2026-07-18: in-place 1-RTT packet protection

The c16 one-MiB duplex diagnostics attributed 243,716 rents and about 304 MB of
pooled traffic to outbound packet protection in roughly five seconds. The
application packet path formatted plaintext into one pooled lease and then
rented a second lease for ciphertext. A bounded candidate reserved tag capacity
in the first lease and encrypted the payload in place. It preserved packet
numbers, header protection, AEAD usage accounting, congestion and amplification
checks, recovery ownership, and send completion. A focused bit-for-bit test
covered AES-128-GCM, AES-256-GCM, AES-128-CCM, and ChaCha20-Poly1305.

Diagnostics confirmed the mechanism: outbound packet-protection rents per
completed request fell about 49.6%, and rented bytes per request fell about
49.8%. Those instrumented runs were used only for attribution. The exact c16
duplex A/B/B/A campaign produced ten samples per variant and zero failures:

| Variant | Median MiB/s | Range MiB/s | CV | Median p95 ms | Median allocated B/request |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 52.527 | 45.842-53.695 | 5.39% | 685.85 | 876,854 |
| candidate | 52.400 | 42.110-54.400 | 7.56% | 695.91 | 916,169 |

Large fixed, upload, and duplex controls at c1, c4, and c16 were otherwise
mostly neutral, but upload required a focused repeat. Across ten A/B/B/A samples
per variant, upload throughput was 62.18 versus 59.78 MiB/s at c1 (-3.9%) and
70.19 versus 66.80 MiB/s at c16 (-4.8%). The c1 median p95 regressed from 18.00
to 19.15 ms (+6.4%), while managed allocation was unchanged. The candidate
therefore failed the local timing gate despite materially reducing pooled rent
traffic. Runtime and focused-test changes were reverted, and ProtocolLab was not
run. Evidence, frozen source and binaries, hashes, raw JSON, logs, BDN smoke
reports, and the candidate diff are under
`C:\shared\temp\quic-inplace-protection-20260718`. Do not retry exact in-place
packet protection without new evidence that explains the upload tradeoff and
predicts an end-to-end timing gain.

### Accepted 2026-07-18: split queued and formatted stream-payload attribution

The existing `outbound_stream_payload` pool owner combined two materially
different lifetimes: the stable copy retained while an oversized public write
is queued, and each datagram-sized STREAM frame retained by sent-packet state
for loss recovery. Separate `queued_raw_stream_data` and
`formatted_stream_payload` owner labels now distinguish those mechanisms
without changing allocation or send behavior.

One diagnostic-only five-second c16 one-MiB duplex run completed 84 requests
with exact payload validation and zero failures. It attributed 88,080,384
requested and rented bytes across 5,376 queued raw buffers, versus 88,774,308
requested bytes and 132,306,048 rented bytes across 70,056 formatted frame
buffers. Flow-control retry ownership was only 344,064 bytes across 21 rents.
The dominant duplication is therefore the raw-write-to-retransmittable-frame
transition, not retry transfer. The formatted buffers remain live in
sent-packet state and cannot be removed without preserving loss-recovery
payload lifetime. The instrumented timing is not performance evidence.
Artifacts are under
`C:\shared\temp\quic-stream-owner-attribution-20260718`.

### Rejected 2026-07-18: reusable signal-only public read waiter

A fresh exact one-MiB c16 public QUIC duplex allocation trace reproduced the
large public read-wait allocation path: excluding harness setup, about 84 MiB
of sampled allocation came from `ReadCoreAsync`, `SemaphoreSlim.WaitAsync`,
cancellation promises, task nodes, and continuation invokers. The trace had
zero lost events. This justified one materially different follow-up to the
previously rejected direct-read completion source.

The candidate reserved one reusable signal-only `IValueTaskSource` for the
common single pending read and retained the existing semaphore path for
overlapping readers. Runtime notification only completed the asynchronous
signal; stream-state reads, payload copies, flow-control credit, and application
continuations stayed off the connection actor. Focused cancellation, abort,
FIN, disposal, notification-race, concurrent-reader, and reuse tests passed
31/31. BDN Dry moved first-use pending-read allocation from 320 to 280 B/read.

A focused c16 one-MiB duplex A/B/B/A campaign ran ten exact samples per variant
with zero failures. Median allocation fell from 728,486 to 296,611 B/op
(-59.3%), throughput moved from 30.42 to 33.22 MiB/s (+9.2%), and p95 moved
from 1,108.07 to 1,005.03 ms (-9.3%), but throughput CV remained high at 16.7%
and 17.9%. The required broader A/B/B/A control screen then ran six exact
samples per variant and cell. Allocation fell 52-60% in every lane, but stable
c1 duplex throughput regressed 13.3% and p95 regressed 17.8% (baseline CV 4.5%,
candidate CV 1.8%). Download also regressed 11.8%, 5.6%, and 8.8% at c1, c4,
and c16, while c16 duplex reversed to -7.7% throughput and +8.1% p95.

The candidate therefore failed the timing and control gates and was reverted.
ProtocolLab was not run. Frozen binaries, SHA-256 hashes, BDN output, raw
loopback JSON/logs, the candidate diff, and the full decision record are under
`C:\shared\temp\quic-read-signal-20260718`. Do not retry another public
read-wait source variant without a materially different scheduling mechanism
that explains why both the direct-read and signal-only designs reduce
allocation but regress stable timing controls.

### Accepted 2026-07-18: adaptive shared-listener UDP receive capacity

New local multi-connection coverage separated one connection with many streams,
many independent listener sockets, and many connections behind one shared
listener. Sixteen independent listeners completed exact one-MiB duplex traffic
without detected loss, while a shared listener repeatedly stranded a moving
connection pair for 3-14 seconds. Instrumented shared-listener samples recorded
561-829 client-side loss detections and 31-39 aggregate PTOs, with zero explicit
UDP send errors or library packet drops. A single connection at c16 recorded no
loss, proving that shared socket ingress rather than generic recovery caused
this failure mode.

Two causal alternatives were rejected. Increasing QUIC connection and stream
receive windows to 128 MiB did not remove the stalls, so flow-control credit was
not the primary cause. Fixed 256 KiB and 4 MiB listener buffers stabilized raw
traffic, but unconditional buffering crossed the HTTP/3 control guardrail: the
256 KiB c16 upload repeat regressed 22%, and the 4 MiB repeat was borderline at
-6.4% with higher process-wide allocation per completed request. Those values
must not be applied unconditionally.

The accepted design preserves the platform socket buffer for one connection
and best-effort raises the shared listener receive queue to 4 MiB when a second
connection is registered. The bound is per listener, not per connection, and
an OS cap or rejected socket option falls back to the functional platform
default. It does not alter authentication, congestion control, flow control,
loss recovery, packet scheduling, stream semantics, or application buffers.

The final exact one-MiB, 16-connection, c1-per-connection A/B/B/A campaign used
five samples per pass and ten per variant:

| Variant | Actual receive buffer | Median MiB/s | Range MiB/s | CV | Median p99 | Worst worker | Median B/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| explicit baseline | 64 KiB | 103.51 | 22.15-118.13 | 29.34% | 358.88 ms | 4,623.39 ms | 919,533 |
| adaptive candidate | 4 MiB | 106.34 | 82.71-111.44 | 9.70% | 311.77 ms | 381.79 ms | 930,264 |

Median throughput improved 2.7%, but the material result is bounded progress:
throughput variance fell 67%, median p99 fell 13%, and the worst worker tail
fell 91.7%. A separate adaptive diagnostic sample reported the actual 4 MiB
buffer and zero client/server loss detections, PTOs, packet drops, and UDP
errors. One-connection c1/c4 controls retained the platform 64 KiB buffer and
showed no regression beyond 5%; exact fixed, streaming, upload, and duplex
HTTP/3 controls had zero failures. Evidence and commands are retained under
`C:\shared\temp\quic-connection-topology-20260718`.

The candidate then passed the smallest matching source-backed ProtocolLab
confirmation. An A/B/B/A campaign compared parent `9f67fcfd` with accepted
commit `0650d1b7` using
`quic.transport.duplex-streams.16x1mb`, 16 connections, 16 concurrent streams
per connection, five repetitions per arm, and exact bidirectional byte
validation. Across ten samples per variant, baseline throughput was 120.23
MiB/s median (112.10-126.40, 4.04% CV) versus 139.68 MiB/s for the candidate
(127.53-141.44, 2.87% CV), a 16.2% gain. Median p95 fell from 2,428.89 to
1,954.32 ms (-19.5%), and median p99 fell from 2,454.64 to 1,991.48 ms
(-18.9%). All 20 cells passed validation with 2 GiB sent and received per
cell, zero failed requests, and zero timeouts. ProtocolLab classifies the
single-host process-backed evidence as diagnostic and comparable with
warnings; it is confirmation of the local signal, not isolated-hardware or
publishable peer proof. Artifacts are retained under
`C:\shared\temp\pl-adaptive-ingress-20260718`.

### Accepted 2026-07-18: coalesced HTTP/3 streaming frame writes

Fresh exact one-MiB HTTP/3 diagnostics showed that streaming and simultaneous
duplex responses submitted about 129 serialized stream writes per completed
request. Each DATA frame header and its first 16 KiB payload chunk used
separate QUIC writes even though they belonged to one HTTP/3 frame. The
candidate adds an internal two-segment stream write that carries the header
and first payload chunk through the existing runtime work item and formats
both directly into one retransmittable STREAM payload. It does not allocate an
intermediate combined application buffer. Flow-control retries copy both
segments into the existing owned retry buffer, and the write retains one
completion source, cancellation registration, and write-gate acquisition.

Instrumented c16 one-MiB runs confirmed the mechanism without being used as
timing evidence. Streaming response writes fell from 22,704 across 176
requests to 11,440 across 176 requests, and duplex response writes fell from
15,609 across 121 requests to 8,320 across 128 requests. Both are approximately
129 to 65 writes per request. Per-action queue and completion latency rose
because each action now carries more bytes; the gain comes from halving the
number of serialized actions, not from making each action cheaper.

Frozen baseline `0beb7582` and candidate executables then ran in A/B/B/A order
across exact one-MiB fixed, streaming, upload, and simultaneous duplex lanes at
c1, c4, and c16. Five samples per pass produced ten samples per variant and
cell, 240 measured samples total, with zero payload, content-length, EOF, or
protocol failures. The targeted streaming lane improved from 43.32 to 47.73
MiB/s at c1 (+10.2%), 42.63 to 46.56 MiB/s at c4 (+9.2%), and 40.38 to 42.73
MiB/s at c16 (+5.8%). Streaming p95 improved 9.7%, 6.5%, and 4.5%
respectively. Duplex throughput improved 6.6%, 3.6%, and 1.9%, while duplex
p95 improved 7.2%, 6.0%, and 7.7%. Fixed-response throughput stayed within
1.9% of baseline. Upload, which does not use the new path, stayed within 4.6%;
its noisier p99 and duplex c4 allocation were not correlated with an added
per-request allocation in the candidate. Local evidence, diagnostics, logs,
and aggregate comparisons are retained under
`C:\shared\temp\pl-h3-segmented-write-20260718`.

The candidate passed the smallest matching source-backed ProtocolLab
confirmation on `http3.payload.stream.100x16kb` at c16. A/B/B/A order with
five repetitions per arm produced ten samples per variant. Baseline throughput
was 40.22 MiB/s median (37.76-43.07, 3.65% CV) versus 42.36 MiB/s for the
candidate (39.70-44.31, 4.13% CV), a 5.3% gain. Median p50, p95, and p99 fell
4.5%, 4.7%, and 5.0%. All 20 cells passed exact HTTP/3, status, content type,
and 1,638,400-byte body validation with zero failed requests or timeouts.
Source-hash verification bound every arm to its requested QUIC worktree.
ProtocolLab classifies this localhost process-backed evidence as diagnostic
and comparable with warnings because target and generator share the host and
the generator may be saturated. It is confirmation of the local result, not
publishable peer proof. Artifacts are under
`C:\shared\temp\pl-h3-segmented-write-20260718\protocol-lab`.

Focused framing, work-item layout, delayed `ValueTask` consumption,
cancellation, write-gate serialization, pooled retry ownership, final-write,
and HTTP/3 streaming tests passed 50/50. The full Release suite passed 9,643
tests with four intentional skips. No ProtocolLab repo files, packages,
deployments, registrations, or published results changed.

### Accepted 2026-07-18: explicit local HTTP/3 connection topology

The local HTTP/3 loopback harness previously labeled one connection with N
concurrent streams only as `concurrency=N`. That shape is useful for
single-connection actor pressure, but it does not reproduce a ProtocolLab
`connections=N, streamsPerConnection=1` peer cell. The harness now accepts
explicit `--connections` and `--streams-per-connection` lists, forms their
Cartesian product, creates one independent `SocketsHttpHandler` per connection,
warms every connection before measurement, and records both dimensions plus
total concurrency in schema version 2 output. The original `--concurrency`
option remains compatible and means one connection with N streams. Mixed legacy
and explicit topology options fail rather than silently relabeling a run.

A current-source exact one-MiB connection-fanout baseline ran fixed and
streaming responses at c1, c4, and c16 with one stream per connection, five
three-second samples per cell, and zero failures across all 30 samples:

| Lane | c1 MiB/s | c4 MiB/s | c16 MiB/s | c4 CV | c16 CV |
| --- | ---: | ---: | ---: | ---: | ---: |
| fixed | 46.35 | 134.11 | 234.33 | 0.50% | 3.24% |
| streaming | 46.74 | 133.07 | 218.15 | 0.84% | 1.29% |

The c1 fixed cell had one cold sample and 10.87% CV; c4/c16 were stable. A
separate diagnostic c4 sample proved that four independent server connections
were active on four shards, with 12,134-12,456 packet-receive work items per
shard. Certificate generation, listener startup, client construction, and
connection warmup remained outside measured samples, and every response passed
exact HTTP/3, content-length, EOF, and payload validation.

This local result is materially above the retained source-backed ProtocolLab
c16 result of roughly 35-38 MiB/s for the same broad response family. It rejects
an intrinsic c16 Incursa HTTP/3 transport ceiling as the immediate diagnosis.
The next local-first step is an out-of-process target/generator reproduction
that separates adapter/API usage and load generation from the library before
another runtime optimization. ProtocolLab was not run. Build and compatibility,
explicit-topology, invalid-option, and balanced-shard smokes passed. Evidence is
under `C:\shared\temp\quic-h3-local-first-next-20260718`.

### Accepted 2026-07-18: local external-target HTTP/3 comparison

The HTTP/3 loopback harness now has a client-only `--target-base-url` mode for
fixed deterministic byte responses. It preserves explicit connection and
stream topology while moving the target into a separate process, so target
startup and target allocation do not contaminate the client measurement.
External responses must pass exact HTTP/3, status, content-length, EOF, and
`index % 251` payload validation. The harness rejects target-side diagnostics
and listener socket options in this mode instead of mislabeling client data.

Five three-second exact samples compared current-source Incursa and
Kestrel/System.Net.Quic targets over one established connection with 1, 4, or
16 concurrent request streams:

| Target | c1 MiB/s | c4 MiB/s | c16 MiB/s | c16 CV | c16 p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Incursa | 41.11 | 40.30 | 36.05 | 1.31% | 465.50 ms |
| Kestrel/System.Net.Quic | 66.36 | 133.16 | 168.16 | 1.51% | 103.70 ms |

All 30 samples per target passed with zero failures. The Incursa gap widens
from 1.61x at c1 to 4.66x at c16 and reproduces the retained ProtocolLab result
without ProtocolLab orchestration. The retained lab generator allocated 7.93
GB while reading 399 MB and flagged possible saturation, but this separate
client path allocates about 133 KB per successful Incursa c16 request and still
reproduces the target-side ceiling.

A target-only sampled-thread trace and existing runtime metrics attribute the
fixed-response shape to one connection actor. A five-second c16 sample created
12,288 stream-write actions for 192 one-MiB responses, exactly 64 actions per
response. Packet and write work waited about 6.9 and 6.7 ms on the shard, and
write completion averaged 6.75 ms. Congestion window averaged about 66 MiB
while bytes in flight averaged only about 275 KiB, ruling out congestion credit
as the dominant limit. The next bounded candidate should reduce HTTP/3 API
write serialization for already-cached immutable fixed responses without
repeating the rejected 32 KiB boundary or raw burst experiments. Evidence is
under `C:\shared\temp\quic-h3-local-first-next-20260718\external-trace` and the
two `external-*-fixed-1mb.json` files in its parent. ProtocolLab was not run.

### Rejected 2026-07-18: one-call cached fixed-response final write

A bounded cross-layer candidate submitted an already-cached immutable HTTP/3
HEADERS+DATA response sequence through one final stream API write instead of
re-entering the public stream write path at each 16 KiB boundary. It retained
the existing frame bytes, 16 KiB DATA framing, flow control, congestion control,
and transport-owned 32 KiB chunking. This was materially different from the
rejected 32 KiB HTTP/3 frame/write boundary: it reduced API and write-gate entry
while leaving the serialized transport work-item size unchanged.

Frozen source-backed target binaries ran A/B/B/A over exact one-MiB fixed
responses at c1, c4, and c16. Three samples per pass produced six samples per
variant and cell, all with exact HTTP/3, content-length, EOF, and payload proof:

| Shape | Baseline MiB/s | Candidate MiB/s | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| c1 | 44.13 | 46.35 | +5.0% | -4.5% | -3.7% |
| c4 | 43.68 | 44.32 | +1.5% | +0.4% | -2.2% |
| c16 | 39.48 | 37.63 | -4.7% | +4.7% | -0.1% |

The candidate did not reach the local timing or allocation gate and moved the
important c16 shape in the wrong direction. The runtime change was reverted and
ProtocolLab was not run. Frozen assemblies, hashes, target logs, and all four
JSON reports are under
`C:\shared\temp\quic-h3-fixed-finalwrite-20260718`. Do not repeat a large
single-call fixed-response write or another response-write-size variant without
new attribution. Reducing HTTP/3 API entries alone does not raise the actor's
packet service capacity.

### Rejected 2026-07-18: clamp ACK walks to tracked packet bounds

The external one-MiB fixed-response trace showed ACK packet handling competing
with stream writes on the single connection actor. A bounded candidate scanned
the authoritative sent-packet and retransmission ledgers once per ACK and
clamped each encoded ACK range to the smallest and largest packet numbers still
tracked. This preserved range order, congestion and recovery accounting,
retransmission cancellation, packet-owner release, and spurious-loss handling,
while avoiding dictionary misses below or above the live ledger. Focused
sent-packet ownership and ledger tests passed 11/11.

Frozen source-backed target binaries had SHA-256 values
`A8C654B3B05BE14ABEF38BED5DCBFE72E0901D7BDA34A47FC524F54932DFCBAC`
for baseline and
`9021DC8777FC1111C6F7C9619C091EDCCEFCAC8A02E426D6301F47F3F28D38D9`
for candidate. An A/B/B/A campaign ran six exact three-second samples per
variant at c1, c4, and c16, with zero HTTP/3, content-length, EOF, payload, or
request failures:

| Shape | Baseline MiB/s | Candidate MiB/s | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| c1 | 45.33 | 45.35 | +0.0% | -2.2% | +5.6% |
| c4 | 43.60 | 43.30 | -0.7% | -0.1% | +0.2% |
| c16 | 39.22 | 40.42 | +3.1% | -4.2% | -0.9% |

The c16 direction was favorable and stable, but the gain was below the normal
5-10% end-to-end gate and no material allocation reduction appeared. The
runtime and candidate-only test changes were reverted, and ProtocolLab was not
run. The launcher, frozen assemblies, hashes, four raw JSON reports, target
logs, and aggregate statistics are retained under
`C:\shared\temp\quic-h3-ack-bounds-20260718`. Do not repeat packet-bound
clamping alone without evidence that historical ACK-range misses have become a
larger fraction of actor service time. The remaining gap still requires a
mechanism that reduces packet count, synchronous datagram submission cost, or
the serial actor work required per ACK by substantially more than this ledger
optimization.

### Rejected 2026-07-18: active-transfer PMTU discovery variants

The fixed one-MiB c16 diagnostic run sent 206,917,272 server bytes in 169,834
datagrams, only about 1,218 bytes per datagram, while recovery emitted exactly
four datagrams per application-send flush. Two bounded DPLPMTUD variants tested
whether raising the active path from QUIC's 1,200-byte floor during sustained
traffic could reduce packet count and synchronous socket submissions.

The first variant allowed the existing path-MTU timer to send while ordinary
application data was queued or ACK-eliciting data remained in flight, while
still deferring behind pending retransmissions. Its focused requirement-home
coverage passed 9/9. Frozen source-backed targets used baseline SHA-256
A8C654B3B05BE14ABEF38BED5DCBFE72E0901D7BDA34A47FC524F54932DFCBAC
and candidate SHA-256
84155414F03E280E3351E3B34BE3FE7959B911B93C2EA8A6C3C3CE7A59D095D7.
Six exact A/B/B/A samples per variant and cell produced:

| Shape | Baseline MiB/s | Candidate MiB/s | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| c1 | 44.08 | 43.60 | -1.1% | +1.9% | -4.2% |
| c4 | 42.35 | 43.05 | +1.7% | +0.5% | -1.0% |
| c16 | 38.71 | 38.47 | -0.6% | +1.3% | +1.3% |

An attribution-only instrumented candidate run averaged about 1,226 bytes per
server datagram. The timer still entered the deeply backlogged actor queue and
raised the packet size too late to affect most of the transfer. Evidence is
retained under
C:\shared\temp\quic-h3-active-pmtu-20260718.

The second, materially different variant emitted the single non-retransmittable
discovery probe directly in the transition that first acknowledged application
STREAM data, retaining the timer only as a fallback when immediate prerequisites
were unavailable. Focused requirement-home coverage passed 10/10. Frozen
source-backed targets used the same baseline and candidate SHA-256
666EAF33C17310D3A5BB5442EE65F7B483330DE589C7AFE93862F3C6B976D2DD.
Six exact A/B/B/A samples per variant and cell produced:

| Shape | Baseline MiB/s | Candidate MiB/s | Throughput delta | p95 delta | Allocation delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| c1 | 44.43 | 44.73 | +0.7% | +2.8% | -0.9% |
| c4 | 43.98 | 42.97 | -2.3% | +2.0% | +3.6% |
| c16 | 39.24 | 38.73 | -1.3% | +0.9% | -1.4% |

All 36 measured samples in each campaign passed exact HTTP/3, content-length,
EOF, payload, and request validation with zero failures. The direct variant's
instrumented run averaged about 1,228 bytes per server datagram, so earlier
discovery still did not materially change the packet shape or performance.
Both runtime and candidate-only test changes were reverted, and ProtocolLab was
not run. The second campaign is retained under
C:\shared\temp\quic-h3-immediate-pmtu-20260718. Do not repeat PMTU timing
or immediate-probe variants without new evidence that ordinary packets actually
remain materially larger for most of the measured transfer and that the reduced
packet count can exceed the cost of the existing actor and socket-send path.

### Rejected 2026-07-18: lock-free endpoint receive socket lookup

A sampled-thread trace of the local one-MiB transport download at c16 attributed
76 samples to `QuicConnectionEndpointHost.GetSocketBinding` entering
`socketGate` once per received datagram. A bounded candidate replaced that
receive-side monitor with a volatile socket-reference read and published a
port-rebinding replacement with a volatile write before disposing the old
socket. Socket replacement, sends, shutdown wakeup, and disposal remained under
the existing gate, preserving rebinding and receive-loop wakeup behavior.

Frozen pre-change and candidate benchmark outputs ran contemporaneously in
A/B/B/A followed by A/B/A/B order. The longer five-second campaign used five
exact one-MiB download samples per arm at c16 with zero failures:

| Variant | Campaign medians | Median p95 | Median allocation |
| --- | ---: | ---: | ---: |
| baseline | 24.98, 25.27 MiB/s | 699.15 ms | 428,239 B/op |
| candidate | 24.32, 24.61 MiB/s | 684.67 ms | 414,392 B/op |

The candidate regressed median throughput by about 2.6%, while p95 and
allocation improved only about 2-3%. Lower candidate variance did not satisfy a
timing, allocation, or tail-latency acceptance gate. The runtime change was
reverted and ProtocolLab was not run. Frozen assemblies, SHA-256 hashes, and all
eight raw JSON reports are retained under
`C:\shared\temp\quic-local-first-20260718`. Do not repeat endpoint socket
lookup lock removal without new evidence that it consumes a materially larger
share of end-to-end service time.

### Rejected 2026-07-18: direct STREAM frame dispatch

The c16 one-MiB download diagnostic attributed about 4.5 seconds of a
five-second saturated shard to packet-received work. The application packet
parser reaches the common STREAM frame after probing the earlier control-frame
codecs, so a bounded candidate recognized the one-byte STREAM frame-type range
and skipped those failed probes without changing any parser or error path.

A dedicated allocation-free ShortRun benchmark measured the previous probe
chain at 163.09 ns and direct STREAM dispatch at 34.44 ns, a 78.9% mechanism
improvement. The absolute saving was only 128.65 ns per STREAM frame, however.
Even incorrectly charging that saving to all 127,355 packet-received work items
in the diagnostic sample explains about 16.4 ms, less than 0.4% of the measured
run and less in reality because many packets carried ACK or control frames.

The candidate therefore lacked enough attributed cost to justify an
end-to-end campaign while a multi-fold transport gap remains. The runtime and
benchmark-only changes were reverted, and ProtocolLab was not run. BDN Dry and
Short artifacts are retained under
`C:\shared\temp\quic-local-first-20260718\bdn-frame-dispatch-*`. Do not repeat
frame-dispatch ordering variants unless a future workload materially changes
the frame mix or measured absolute parser cost.

### Accepted 2026-07-18: opt-in receive-phase attribution

The local transport diagnostics now expose disabled-by-default shard transition
and effect timing plus bounded application-packet phases by endpoint role. The
application path partitions packet opening, preparation, ACK and STREAM frame
handling, post-frame path work, queued-write retry, application-send recovery
flushes, received-packet accounting, ACK emission, ACK timer maintenance, and
connection-ID work. The local diagnostics collector records the packet-phase
histogram only when `--diagnostics true` is active. No packet scheduling,
recovery, flow-control, congestion-control, or stream behavior changed.

A diagnostic-only five-second one-MiB transport download at c16 attributed the
successful 1-RTT transition path to roughly 47% frame processing, 37%
post-frame work, 13% packet opening, and 2% preparation. On the sending server,
61,824 ACK frames spent 712.59 ms walking acknowledged packet ranges and
169.14 ms in recovery accounting; 69,597 post-ACK recovery calls spent
681.16 ms flushing queued application sends. On the receiving client, ACK
generation spent 373.23 ms. STREAM bookkeeping was materially smaller at
278.76 ms across 107,632 client STREAM frames. This makes ACK ledger work and
bounded recovery flushing the next evidence-supported mechanisms, while ruling
out another parser-dispatch micro-optimization.

The instrumented sample is attribution evidence only because per-event metric
collection perturbs the single-connection actor. Focused bounded-tag metrics
coverage passed, the benchmark project built with zero warnings, and the raw
diagnostic JSON is retained under
`C:\shared\temp\quic-local-first-20260718\transport-download-c16-packet-phase-attribution-v4.json`.

### Rejected 2026-07-18: reuse parsed acknowledged STREAM IDs

Receive-phase attribution showed that ACK-range processing was a substantial
part of sender actor time. Each acknowledged sent STREAM packet reparsed its
retained plaintext once to remove the packet from the outstanding-stream index
and again to suppress obsolete RESET_STREAM retransmission. A bounded candidate
made the index removal return the exact distinct non-empty STREAM IDs it had
already parsed and reused those IDs for RESET_STREAM suppression. It preserved
zero-length FIN handling, packet ownership, recovery and congestion accounting,
and retransmission behavior. Focused ownership and index tests passed 14/14.

An allocation-free BenchmarkDotNet ShortRun showed that the mechanism itself
was real: at 64, 256, and 1,024 packets, parsing once and reusing IDs took
1.993, 7.857, and 31.267 microseconds versus 3.925, 15.378, and 61.320
microseconds for two parses, a consistent 49% reduction with zero managed
allocation. Frozen source-backed local benchmark assemblies had SHA-256 values
`5782C2A457DB403CCF11C424F30331E0712CD163BEA853162323CB683D3C1F80`
for baseline and
`177E8EFF1E90A64AA0F7A95A2321773DDED239775EC931EEF2E7584830E5253C`
for candidate.

The broad A/B/B/A one-MiB download campaign experienced monotonic shared-host
drift and was retained only as disturbed diagnostic evidence. A tighter
A/B/A/B/A/B c16 campaign then ran five exact samples per arm, with zero payload,
length, EOF, request, or process failures. Across fifteen samples per variant:

| Variant | Median MiB/s | Range MiB/s | CV | Median p95 | Median allocation |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 22.83 | 17.24-26.01 | 12.45% | 873.88 ms | 467,003 B/op |
| candidate | 17.93 | 15.16-26.30 | 19.10% | 988.91 ms | 485,631 B/op |

The candidate was 21.5% slower by aggregate median, 13.2% worse at p95, and
4.0% higher in allocation. Same-neighborhood A/B throughput deltas were
-15.6%, -2.1%, and -10.0%, so host drift does not rescue the candidate. The
runtime, benchmark, and candidate-only test changes were reverted, and
ProtocolLab was not run. BDN, frozen assemblies, hashes, target logs, raw
reports, and aggregate evidence are retained under
`C:\shared\temp\quic-ack-stream-id-reuse-20260718`. Together with the earlier
tracked-bound ACK-range candidate, this rejects minor ACK-ledger parsing
variants as the next route to closing the multi-fold gap. Reassess the broader
serial actor and recovery-flush mechanism before attempting more ACK ledger
micro-optimizations.

### Rejected 2026-07-18: admit a complete public write in one actor action

The permanent local peer harness reproduced the single-connection scaling gap
with exact one-MiB downloads and five uninstrumented samples per cell. Incursa
measured 45.43, 30.51, and 25.84 MiB/s at c1, c4, and c16, while
`System.Net.Quic` measured 24.66, 202.42, and 197.34 MiB/s. Incursa p95 was
8.23x and 6.77x higher at c4 and c16, and allocation per operation was 19.05x
and 17.97x higher. The source-backed result is retained at
`C:\shared\temp\quic-local-first-20260718\current-peer-1mb-download-c1-c4-c16-r5.json`.

The current Incursa path turns one one-MiB public write into thirty-two
separately posted and awaited 32 KiB actor requests. A materially different
candidate removed that API-side chunk continuation and admitted the complete
buffer as one actor request, relying on the accepted semantic raw-send queue to
fragment the payload when packets were scheduled. This did not repeat the
rejected 64 KiB work-item boundary or the prior one-request design that reposted
each 32 KiB continuation. Focused flow-control, cancellation, stream-write, and
queued-final-write tests passed 167/167, and the candidate built with zero
warnings.

The candidate nevertheless failed the first end-to-end correctness gate. The
clean baseline completed its A1 c1/c4/c16 arm in about 36 seconds. The candidate
made no bounded progress and produced no result artifact after approximately
120 seconds, so only the owned local benchmark process was stopped. Reserving
the complete public buffer before sending any bytes can wait indefinitely when
the write exceeds currently available stream or connection flow-control credit;
the existing chunk path is what permits credit to advance incrementally. The
candidate was reverted before any ProtocolLab run.

Frozen assemblies, hashes, the completed baseline arm, launcher, logs, and a
machine-readable negative result are retained under
`C:\shared\temp\quic-full-write-admission-20260718`. Do not retry whole-buffer
admission without an incremental reservation and atomic cancellation/terminal
handoff design. That broader continuation design must also avoid the queue-depth
and retained-buffer regressions already measured by the rejected reposting
candidate; simply changing the admission size cannot safely close this gap.

### Local-first diagnosis 2026-07-18: single-connection packet actor service ceiling

A fresh uninstrumented loopback campaign compared Incursa with
`System.Net.Quic` in the same process and campaign. It used one established
connection, exact one-MiB payload validation, five samples per cell, and upload,
download, and simultaneous duplex shapes at c1, c4, and c16. Every operation
completed without a payload or protocol failure. Incursa remained competitive
at c1, then stopped scaling on the single connection while `System.Net.Quic`
continued to use the available host capacity:

| Shape | Incursa c1/c4/c16 MiB/s | System.Net.Quic c1/c4/c16 MiB/s | Incursa/System.Net at c16 | Incursa/System.Net allocation at c16 |
| --- | ---: | ---: | ---: | ---: |
| upload | 37.16 / 28.21 / 22.87 | 30.86 / 210.98 / 139.22 | 0.16x | 25.18x |
| download | 45.43 / 30.51 / 25.84 | 24.66 / 202.42 / 197.34 | 0.13x | 17.97x |
| duplex | 43.24 / 40.29 / 29.53 | 44.53 / 237.67 / 230.97 | 0.13x | 22.09x |

Incursa c16 p95 latency was 5.46x, 6.77x, and 7.45x the corresponding
`System.Net.Quic` upload, download, and duplex result. The exact uninstrumented
reports are
`C:\shared\temp\quic-local-first-20260718\current-peer-1mb-upload-duplex-c1-c4-c16-r5.json`
and
`C:\shared\temp\quic-local-first-20260718\current-peer-1mb-download-c1-c4-c16-r5.json`.
The existing multi-connection HTTP/3 control reached 218-234 MiB/s at 16
connections, so this is not a process-wide thread-pool, socket-host, or machine
ceiling. It is specific to many active streams sharing one connection actor.

A diagnostic-only three-shape c16 repeat quantified the queue mechanism. On the
active sender shard, packet-receive depth reached 649 for upload, 614 for
download, and 636 for duplex. Packet p95 queue delay reached 32.78, 41.89, and
36.26 ms, while individual packet service p95 was only 0.15, 0.09, and 0.14 ms.
Stream-write p95 queue delay reached 29.88, 41.81, and 35.99 ms. The active
shard processed 45,600-69,483 packet work items in a representative sample;
thousands of individually cheap serialized transitions consume the actor and
strand writes behind packet runs. Outstanding pooled storage simultaneously
peaked at roughly 1,442-1,492 buffers in the 4 KiB-or-smaller bucket and up to
45 buffers in the 64 KiB-or-smaller bucket. These instrumented timings are
attribution only, not performance evidence. The report is
`C:\shared\temp\quic-local-first-20260718\current-incursa-1mb-c16-attribution-r3.json`.

A ten-second sampled-thread upload trace reproduced 22.43 MiB/s with exact
validation. Runtime inbox consumption was the main active Incursa stack;
application packet processing and synchronous datagram submission were the
largest bounded components, but no single managed method was large enough to
explain the 6-8x c16 peer gap. The trace and Speedscope conversion are under
`C:\shared\temp\quic-local-first-20260718\cpu-upload-c16`.

No runtime candidate was introduced and ProtocolLab was not run. The local
inner loop now reproduces the decisive gap in minutes and supplies exact peer,
queue, buffer, write-completion, and CPU evidence. Do not resume socket-wrapper,
minor ACK-ledger, PMTU-timing, fixed burst, write-size, channel-publication, or
send-flush variants already rejected above. The next runtime candidate must be
a materially different design that can reduce the amount of serial actor work
per received packet or the number of packet transitions by enough to explain a
substantial fraction of the peer gap, while preserving prompt application-send
progress, packet ordering, ACK deadlines, recovery, flow control, cancellation,
and bounded memory.

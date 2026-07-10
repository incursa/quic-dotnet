# QUIC Performance Improvement Wishlist

This is a pragmatic backlog for improving Incursa.Quic performance evidence, runtime efficiency, and benchmark trustworthiness. Each item includes the finish line so we can tell when it is actually done.

## Progress Notes

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
  `.artifacts/runs/quic-raw-stream-acked-retention-final-20260710a-*`, and
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

1. Finish terminal exception attribution and cleanup.
2. Add permanent exception/trace-site tooling.
3. Establish stable smoke and confidence ProtocolLab lanes.
4. Attack HTTP/3 allocation hot spots.
5. Add raw QUIC and public API stream-transfer baselines.
6. Move repeatable evidence onto package-backed lab/controller runs.

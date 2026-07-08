# QUIC Performance Improvement Wishlist

This is a pragmatic backlog for improving Incursa.Quic performance evidence, runtime efficiency, and benchmark trustworthiness. Each item includes the finish line so we can tell when it is actually done.

## Progress Notes

- 2026-07-08: `152fda3c` removed disabled application-send diagnostic string allocations on the stream write hot path. Source-backed ProtocolLab profile pack `codex-h3-1kb-post-log-handler-20260708a` showed `http3.payload.bytes.1kb` request rate +2.24%, p95 -0.92%, allocation rate -29.97%, and bytes/request -31.51% versus `codex-h3-1kb-post-data-frame-20260708a`.
- 2026-07-08: `7c083271` added a queued inbound stream accept fast path. Source-backed ProtocolLab profile pack `codex-h3-1kb-post-accept-fastpath-20260708a` showed request rate +11.28%, p95 -18.03%, and bytes/request -1.17% versus `codex-h3-1kb-post-log-handler-20260708a`; allocation rate rose +9.98% while total throughput increased.
- 2026-07-08: exception attribution run `codex-exception-attribution-post-accept-fastpath-20260708a` for `http3.payload.bytes.64kb` passed ProtocolLab validation and benchmark with 22,992 EventPipe events, zero lost events, and zero first-chance exceptions.

## 1. Finish Expected Terminal Exception Cleanup

The HTTP/3 terminal-flow cleanup reduced local exception pressure materially, but traces still show terminal `Incursa.Quic.QuicException: The connection terminated` as the dominant remaining first-chance exception source.

Done when:

- A source-backed ProtocolLab `http3.payload.bytes.64kb` trace identifies the remaining throw sites by method.
- Expected connection shutdown no longer uses exceptions for normal HTTP/3 request, stream, accept, write, read, and cleanup paths.
- Public API terminal behavior still throws where the public contract requires it.
- Focused public-vs-internal terminal-flow tests prove both contracts.
- Local ProtocolLab exception counters are consistently near zero for successful short HTTP/3 h2load runs, excluding genuine cancellation/tool shutdown noise.

## 2. Build Permanent Trace-Site Attribution

Current exception attribution relied on temporary trace parsing and prior diagnostic instrumentation. We need a repeatable tool that tells us where exception pressure comes from without patching production code.

Done when:

- A repo script can run a ProtocolLab scenario with EventPipe exception capture.
- The script emits a markdown and JSON summary grouped by exception type, message, and managed stack top frame.
- It works for HTTP/3 and raw QUIC scenarios.
- The output is stored under `.artifacts/perf/` with run ID, git commit, scenario, load shape, and source-root/package mode.
- The script is documented in `scripts/perf/README.md`.

## 3. Add Stable ProtocolLab Performance Lanes

Single local runs are useful diagnostics but not stable enough for real performance claims. We need a repeatable lane that separates smoke, confidence, and publishable evidence.

Done when:

- Smoke lane runs one short local source-backed HTTP/3 and raw QUIC scenario.
- Confidence lane runs at least three repetitions and reports variance.
- Publishable lane runs on isolated lab hardware with explicit CPU, memory, network, and load-generator controls.
- Reports clearly label each result as diagnostic, confidence, or publishable.
- A failing lane distinguishes validation failure, benchmark failure, infrastructure failure, and performance regression.

## 4. Establish Baseline Dashboards For Key Scenarios

We need a small set of benchmark scenarios that represent the real performance story instead of chasing one-off runs.

Done when:

- ProtocolLab tracks current baselines for:
  - `http3.payload.bytes.1kb`
  - `http3.payload.bytes.64kb`
  - `quic.transport.stream-throughput.1mb`
  - high-concurrency HTTP/3 small payload
  - raw QUIC stream fanout
- Each baseline includes requests/sec or throughput, latency percentiles, allocation rate, GC counts, exception rate, and validation status.
- Baselines are compared against the previous accepted run and the best known run.
- Regressions are visible in the public report site or an internal generated report.

## 5. Reduce HTTP/3 Allocation Pressure

The next likely gains are in request/response frame handling, buffer ownership, QPACK field materialization, and per-request object churn.

Done when:

- Allocation traces identify the top HTTP/3 allocation sites for 1KB and 64KB payload scenarios.
- At least the top three avoidable allocation sources have targeted fixes or are explicitly accepted with rationale.
- Benchmarks show lower allocation rate without throughput or correctness regressions.
- Full HTTP/3 tests pass after each allocation-focused change.

## 6. Tighten Stream Lifecycle Cleanup

Stream disposal, final-write completion, read-side completion, and observer notification are still complicated. They are likely hiding both exception pressure and extra work.

Done when:

- Stream disposal has non-throwing internal cleanup paths for expected terminal states.
- Stream observer unregister, capacity release, and read/write completion are idempotent and covered by focused tests.
- ProtocolLab shutdown traces do not show repeated terminal cleanup exceptions.
- Stream lifecycle tests cover normal EOF, reset, connection close, disposal, and cancellation separately.

## 7. Add Raw QUIC Performance Proof

HTTP/3 tells us end-to-end behavior, but raw QUIC scenarios are needed to isolate transport performance from QPACK and HTTP/3 framing.

Done when:

- `quic-dotnet-raw-dev` package/source mode can run raw stream throughput scenarios reliably.
- Raw QUIC scenarios report throughput, allocation, GC, exception count, and validation.
- At least one raw stream-throughput scenario is part of the smoke lane.
- HTTP/3 regressions can be compared against raw QUIC results to locate whether the problem is transport or application framing.

## 8. Compare Against External Implementations Honestly

Performance only matters relative to known-good peers, but comparisons need matching scenarios and honest caveats.

Done when:

- ProtocolLab runs comparable scenarios against at least quic-go and one C/Rust implementation where available.
- Comparison reports only include cells with matching protocol, workload, load tool, resource controls, and validation.
- Unsupported or non-comparable cells are explicitly labeled instead of hidden.
- Public reports show Incursa results beside comparable peers with warnings when evidence is local or non-isolated.

## 9. Build Regression Gates Without Premature Hard Thresholds

We need automated protection from obvious regressions, but local noise makes strict thresholds risky.

Done when:

- Smoke gates fail only on validation failure, infrastructure failure, or extreme metric changes.
- Confidence gates report performance movement but do not block without enough repetitions.
- Publishable gates can enforce thresholds once lab variance is understood.
- Threshold rules are checked into source control and reviewed like code.

## 10. Improve Counter And Trace Artifact Import

ProtocolLab captures useful artifacts, but analysis still requires manual spelunking.

Done when:

- Counter summaries, trace summaries, qlog status, validation proof, and benchmark metrics are imported into a single evidence document.
- Reports include links to raw artifacts.
- Exception type/count and allocation hot spots are first-class report fields.
- The public site can show whether a run is diagnostic, confidence, or publishable.

## 11. Make Source-Backed And Package-Backed Runs Equivalent

Source-backed runs are good for development, but package-backed controller jobs are the long-term boundary.

Done when:

- The same scenario can run source-backed locally and package-backed on the controller with matching implementation identity.
- Package manifests record the exact quic-dotnet commit, package version, build mode, and supported scenario list.
- A package-backed run can reproduce the smoke lane on lab hardware.
- Differences between source-backed and package-backed results are understood and documented.

## 12. Add Public API Stream Transfer Benchmarks

Existing public comparison work is mostly connection establishment. We need public stream transfer workloads that compare real user-facing APIs.

Done when:

- BenchmarkDotNet includes public facade stream upload, download, bidirectional echo, and many-stream workloads.
- Incursa and `System.Net.Quic` are compared only where both can run the same public workload honestly.
- The benchmark does not use internal runtime helpers.
- Results are documented separately from HTTP/3 and raw internal transport benchmarks.

## 13. Profile Scheduler, Timers, And Send Queue Hot Paths

If throughput stalls under concurrency, likely culprits include send queue ordering, timer processing, ACK/loss effects, and packet assembly.

Done when:

- CPU traces identify top runtime hot paths under raw QUIC and HTTP/3 concurrency.
- Send queue and timer hot paths have BenchmarkDotNet microbenchmarks tied to real ProtocolLab scenarios.
- Changes show improvement in both microbenchmarks and at least one end-to-end scenario.
- No protocol scheduling semantics are weakened to gain speed.

## 14. Improve Buffer Pool Diagnostics And Tuning

Buffer reuse is central to reducing allocations, but pool behavior needs better visibility.

Done when:

- Buffer pool diagnostics can be enabled per ProtocolLab run without code changes.
- Reports show rent/return counts, misses, peak outstanding buffers, oversized rents, and retained memory.
- The default pool sizes are justified by scenario evidence.
- Pool tuning improves allocation rate without increasing retained memory unreasonably.

## 15. Keep Requirement Trace And Performance Evidence Connected

Performance changes can accidentally weaken protocol behavior. Every optimization should preserve traceability.

Done when:

- Performance fixes that alter runtime behavior cite the nearest requirement/spec/verification artifact.
- Verification artifacts distinguish correctness evidence from performance evidence.
- Full test, focused requirement-home tests, ProtocolLab validation, and diff hygiene are recorded before commit.
- Known standing SpecTrace validation backlog is separated from new-change validation.

## 16. Build A Small “Performance Triage” Command

We need one command that answers “what got slower, what got noisier, and why should I care?”

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

# Performance Helpers

This folder contains local performance and ProtocolLab integration helpers for
`quic-dotnet` development.

## Exception Attribution

Use `Invoke-QuicExceptionAttribution.ps1` when you need a repeatable
ProtocolLab-backed answer to "where are first-chance exceptions coming from?"
The wrapper runs one source-backed ProtocolLab scenario with EventPipe
exception capture, then writes JSON and Markdown exception groups by exception
type, message, attribution frame, raw stack top frame, and first Incursa frame.
It supports HTTP/3 and raw QUIC scenarios through the same ProtocolLab local
benchmark path, and writes run-level metadata including git commit, source mode,
scenario, and load shape.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicExceptionAttribution.ps1 `
  -Protocol h3 `
  -ProtocolLabRoot C:\shared\src\incursa\protocol-lab `
  -ProtocolLabExecutionRoot C:\shared\src\incursa\protocol-lab-internal `
  -Scenario http3.payload.bytes.64kb `
  -DurationSeconds 5 `
  -WarmupSeconds 1 `
  -Connections 16 `
  -StreamsPerConnection 10
```

Raw QUIC example:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicExceptionAttribution.ps1 `
  -Protocol quic `
  -ProtocolLabRoot C:\shared\src\incursa\protocol-lab `
  -ProtocolLabExecutionRoot C:\shared\src\incursa\protocol-lab-internal `
  -Scenario quic.transport.stream-throughput.1mb `
  -DurationSeconds 5 `
  -WarmupSeconds 1 `
  -Connections 1 `
  -StreamsPerConnection 1
```

The wrapper writes under:

```text
.artifacts/perf/exception-attribution/{runId}/
```

The run root includes:

```text
exception-attribution-run.json
exception-attribution-run.md
protocol-lab-command.txt
exception-attribution/exception-attribution.json
exception-attribution/exception-attribution.md
protocol-lab-runs/**/trace.nettrace
```

To analyze an existing `.nettrace` without rerunning ProtocolLab:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Analyze-QuicExceptionTrace.ps1 `
  -TracePath C:\path\to\trace.nettrace `
  -OutputRoot .\.artifacts\perf\exception-attribution\manual-review
```

The analyzer emits:

```text
exception-attribution.json
exception-attribution.md
exception-attribution-command.txt
trace.etlx
```

The JSON schema is `incursa.quic.exception-attribution.v2`. `stackTopFrame`
preserves the raw managed top frame from the trace, which is often runtime
exception dispatch. `attributionFrame` is the deterministic action frame used
for grouping: the first configured project frame, or the first non-runtime frame
when no project frame is present. By default project frames start with
`Incursa.`. Each group also includes `category`, `isActionable`, and
`actionabilityReason`. Runtime cancellation groups with no project or
non-runtime frame are classified as `runtime-only-cancellation`; they still
count toward total first-chance exceptions, but they do not count toward
`actionableExceptions`. Incursa terminal-flow cleanup should focus first on
rows where `category` is `project-attributed` or `external-attributed`.

## QUIC Local Performance Lanes

Use `Invoke-QuicPerformanceLane.ps1` when you want one repeatable local command
that combines the repo's BenchmarkDotNet developer-feedback suites with the
ProtocolLab source-reference validation path.

The lanes are intentionally different from controlled infrastructure runs:

- `Smoke` is a quick developer check. It runs matching BenchmarkDotNet suites
  with `Dry` and, when the selected surface maps to ProtocolLab, runs one
  source-reference ProtocolLab repetition with one second of warmup and one
  second of measurement.
- `Confidence` is report-only repeated local evidence. It runs matching
  BenchmarkDotNet suites with `Short` and, when the selected surface maps to
  ProtocolLab, runs nine ProtocolLab repetitions with five seconds of warmup
  and fifteen seconds of measurement. It does not enforce thresholds.
- Controlled runner evidence is the future hosted lane for well-known compute
  nodes. It should consume the same lane and surface vocabulary, but it is not
  implemented by this local wrapper.

Example smoke run for the current raw QUIC multiplex focus:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 `
  -Lane Smoke `
  -Surface RawQuicMultiplex
```

Example smoke run for raw QUIC stream-throughput isolation:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 `
  -Lane Smoke `
  -Surface RawQuicStreamThroughput
```

Example core ProtocolLab smoke run for both HTTP/3 and raw QUIC:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 `
  -Lane Smoke `
  -Surface CoreProtocolLab `
  -SkipBenchmarks
```

The `CoreProtocolLab` surface runs the default raw QUIC scenario
`quic.transport.multiplex.100x64kb`. For HTTP/3, `Smoke` defaults to
`http3.core.status` so the lane stays a fast protocol-validation check; other
lanes default to `http3.payload.bytes.64kb` for payload pressure. Override them
with `-Http3Scenario` and `-RawQuicScenario` when a narrower or heavier
ProtocolLab slice is needed. Override `-Http3Connections`,
`-Http3StreamsPerConnection`, `-RawQuicConnections`, and
`-RawQuicStreamsPerConnection` when the same scenario needs a different load
shape. Use `-SkipHttp3ProtocolLab` or `-SkipRawQuicProtocolLab` to isolate one
side of the `CoreProtocolLab` surface when only HTTP/3 or raw QUIC evidence is
wanted. This surface continues through all selected ProtocolLab jobs by default and reports
`completed-with-diagnostic-failures` if any aggregate contains validation,
benchmark, or runner errors. Add `-FailOnProtocolLabError` when fail-fast
behavior is required.

After the first restore/build, add `-NoRestore` and `-NoBuild` for faster
BenchmarkDotNet iteration:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 `
  -Lane Smoke `
  -Surface RawQuicMultiplex `
  -NoRestore `
  -NoBuild
```

Example confidence run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 `
  -Lane Confidence `
  -Surface RawQuicMultiplex
```

Example high-concurrency HTTP/3 small-payload confidence run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-QuicPerformanceLane.ps1 `
  -Lane Confidence `
  -Surface CoreProtocolLab `
  -SkipBenchmarks `
  -Http3Scenario http3.payload.bytes.1kb `
  -Http3Connections 32 `
  -Http3StreamsPerConnection 1 `
  -SkipRawQuicProtocolLab `
  -CaptureCounters
```

The wrapper writes a report under:

```text
.artifacts/perf-lanes/{runIdPrefix}/summary.md
.artifacts/perf-lanes/{runIdPrefix}/lane-summary.json
```

`lane-summary.json` uses schema
`incursa.quic.performance-lane-summary.v1` and preserves the lane identity,
git state, effective load shape, selected commands, ProtocolLab run roots,
validation/benchmark health, failure categories, evidence quality, metric
median/best/worst values, relative ranges, and publishability gate blockers.
Use the JSON file when comparing repeated local confidence runs or feeding
results into a later dashboard; use `summary.md` for human review.

## ProtocolLab Baseline Reports

Use `New-QuicProtocolLabBaselineReport.ps1` to roll up existing
`aggregate-results.json` files for the core QUIC performance scenarios. The
report picks the current, previous, and best known rows per scenario and
implementation, then records validation, benchmark status, evidence quality,
throughput or request rate, latency, allocation rate, GC counts, exception
rate, repetition count, and publishability blockers.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\New-QuicProtocolLabBaselineReport.ps1
```

Create an Incursa-focused report from the shared local run store:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\New-QuicProtocolLabBaselineReport.ps1 `
  -ImplementationId incursa-http3,incursa-raw-quic-adapter-v1
```

To limit the report to specific run roots:

```powershell
$runRoots = @(
  "C:\shared\src\incursa\protocol-lab-internal\.artifacts\runs\codex-core-lane-smoke-20260708d-h3-h3-local-v1",
  "C:\shared\src\incursa\protocol-lab-internal\.artifacts\runs\codex-core-lane-smoke-20260708d-raw-quic-quic-transport-v1-comparison"
)

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\New-QuicProtocolLabBaselineReport.ps1 `
  -ProtocolLabRunRoot $runRoots
```

Output is written under:

```text
.artifacts/perf-baselines/{runId}/baseline-report.md
.artifacts/perf-baselines/{runId}/baseline-report.json
```

## ProtocolLab Performance Triage

Use `Compare-QuicProtocolLabRuns.ps1` when you need one closeout command for
"what changed?" between two retained ProtocolLab runs. The script accepts either
run IDs resolvable under the ProtocolLab run store or direct run-root paths that
contain `aggregate-results.json`, then emits markdown and JSON comparing
validation, benchmark health, throughput/request rate, latency, allocation, GC,
exceptions, CPU, warnings, repetition count, qlog/counter presence, and evidence
quality changes.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Compare-QuicProtocolLabRuns.ps1 `
  -BaselineRun C:\path\to\baseline-run-root `
  -CurrentRun C:\path\to\current-run-root `
  -RunId codex-h3-before-after-triage
```

Output is written under:

```text
.artifacts/perf-triage/{runId}/performance-triage.md
.artifacts/perf-triage/{runId}/performance-triage.json
```

## H3 Allocation Hotspot Reports

Use `New-QuicH3AllocationHotspotReport.ps1` to roll up one or more existing
Incursa H3 profile packs into a single allocation investigation report. The
report preserves the counter metrics plus parsed `dotnet-trace report topN`
CPU/GC method highlights, while explicitly treating them as investigation
evidence rather than safe proof for pooling or buffer ownership changes. When
adjacent supplied profile packs use the same scenario, the report also emits a
before/after delta table for request rate, p95 latency, allocation rate,
bytes/request, and GC deltas.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\New-QuicH3AllocationHotspotReport.ps1 `
  -OutputRoot .\.artifacts\perf-hotspots `
  -ProfilePackRoot ".\.artifacts\perf\incursa-h3-profile-pack\codex-h3-1kb-quic-profile-20260708a,.\.artifacts\perf\incursa-h3-profile-pack\codex-h3-64kb-quic-profile-20260708a"
```

Output is written under:

```text
.artifacts/perf-hotspots/{runId}/allocation-hotspots.md
.artifacts/perf-hotspots/{runId}/allocation-hotspots.json
```

For stack-attributed allocation evidence, run the trace-analysis tool against a
GC allocation trace captured by `Invoke-IncursaH3ProfilePack.ps1`:

```powershell
dotnet run --project .\eng\tools\Incursa.Quic.TraceAnalysis -c Release -- `
  --trace .\.artifacts\perf\incursa-h3-profile-pack\{profileRun}\gc-trace\trace.nettrace `
  --analysis allocations `
  --output .\.artifacts\perf-analysis\{analysisRun} `
  --top 30 `
  --max-frames 48
```

Output is written under:

```text
.artifacts/perf-analysis/{analysisRun}/allocation-attribution.md
.artifacts/perf-analysis/{analysisRun}/allocation-attribution.json
```

Allocation tick bytes are sampled/estimated EventPipe evidence. Use these
reports to choose focused code-review targets, not as exact total allocation
accounting.

## ProtocolLab Readiness Evidence

Use `New-QuicProtocolLabReadinessEvidence.ps1` before handing the repo to a
package-backed rack-lab run or live integration operator. It builds the HTTP/3
and raw QUIC `.plabpkg` archives with stable readiness versions, records their
SHA-256 hashes, discovers the latest local HTTP/3 runner proof, and writes the
operator checklist under:

```text
.artifacts/protocol-lab/readiness/{runId}/README.md
.artifacts/protocol-lab/readiness/{runId}/readiness-manifest.json
```

The readiness manifest uses the `quic-dotnet-protocol-lab-readiness-v2` schema.
It distinguishes four evidence classes:

- `local-lab`: developer or rack-local validation using localhost, shared host
  resources, local Docker, managed load tools, or otherwise non-isolated
  resources.
- `isolated-local`: local/private lab evidence with stronger controls, but
  without complete external-reference provenance.
- `external-reference`: separated target/load resources and external-reference
  tooling, but still missing at least one publishable gate.
- `publishable`: external-reference benchmark evidence with isolated resources,
  complete implementation/environment identity, checksum-retained artifacts,
  stable repeated runs, and no unresolved publishability blockers.

Create a full package-backed readiness bundle:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\New-QuicProtocolLabReadinessEvidence.ps1 `
  -ProtocolLabRoot C:\shared\src\incursa\protocol-lab
```

Create a checklist without rebuilding packages:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\New-QuicProtocolLabReadinessEvidence.ps1 `
  -SkipPackageBuild
```

Summarize existing ProtocolLab run artifacts and quality gates:

```powershell
$runRoots = @(
  "C:\shared\src\incursa\protocol-lab-internal\.artifacts\runs\final-local-quic-perf-proof1-quic-transport-v1-comparison",
  "C:\shared\src\incursa\protocol-lab-internal\.artifacts\runs\final-package-raw-proof1-quic-transport-v1-comparison"
)

& .\scripts\perf\New-QuicProtocolLabReadinessEvidence.ps1 `
  -SkipPackageBuild `
  -ProtocolLabRunRoot $runRoots
```

For each supplied run root, the manifest records `aggregate-results.json`
identity, evidence class, claim level, per-cell local repeatability status,
relative-range quality gates, isolated-local gate status, exact blocker details,
and a SHA-256 checksum inventory of retained run artifacts. The per-cell
environment gates classify host topology, CPU isolation, network isolation,
target resource metrics, and load-generator saturation telemetry. Shared-host
or loopback runs remain useful local proof, but they are explicitly blocked from
isolated-local and publishable benchmark claims until those gates pass.

The generated manifest separates local developer/regression evidence from live
provider/platform execution. Live DNSSEC validation, provider publication,
IKEv2/IPsec sessions, resolver application, DHCP/RA emission, and encrypted DNS
establishment remain blocked until the corresponding credential, authority,
endpoint, OS privilege, network infrastructure, or operator decision is present.
It also records the public ProtocolLab contract checkout and the runnable
ProtocolLab execution checkout separately. The executable checkout must contain
`scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1`, which is required
for the source-reference performance lane.

Before publishing benchmark evidence, run a repeated controlled collection with
at least three repetitions, separated SUT/load-generator resources, external
reference load tooling, captured CPU/OS/runtime/network isolation metadata,
load-generator saturation telemetry, package/source hashes, retained artifacts,
and the generated checksum inventory. The README generated by the readiness
script includes a local repeatability command and an external-reference command
template for the operator.

Supported surfaces:

- `CoreProtocolLab`: source-reference ProtocolLab HTTP/3
  `http3.payload.bytes.64kb` and raw QUIC
  `quic.transport.multiplex.100x64kb` in one report. It does not run
  BenchmarkDotNet filters unless another surface is selected.
- `RawQuicStreamThroughput`: ProtocolLab
  `quic.transport.stream-throughput.1mb` plus send/scheduler/parsing BDN
  suites.
- `RawQuicMultiplex`: ProtocolLab `quic.transport.multiplex.100x64kb` plus
  send/scheduler/parsing BDN suites.
- `RawQuicDuplex`: ProtocolLab `quic.transport.duplex-streams` plus the same
  send/scheduler/parsing suites and stream-state BDN coverage.
- `RawQuicSendCore`: BDN-only send/congestion core by default; pass
  `-Scenario <id>` when a specific ProtocolLab raw QUIC scenario should also
  run.
- `PublicApiStream`: BDN public stream-transfer comparison only. ProtocolLab is
  skipped by default because this is not a one-to-one public facade workload.

The wrapper always uses ProtocolLab source/project references when ProtocolLab
runs. It never packs NuGet packages, publishes packages, uploads R2 bundles, or
changes ProtocolLab benchmark semantics.

Current local raw QUIC execution status:

- The source-reference loop reaches
  `scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1` in
  `protocol-lab-internal`.
- The Incursa raw QUIC adapter validates and starts a local QUIC endpoint for
  `quic.transport.multiplex.100x64kb`.
- `protocol-lab-internal` includes the local `quic-go-raw-load` source
  directory at `src\Incursa.ProtocolLab.Adapters.QuicGo`. Its manifest invokes
  `go -C src/Incursa.ProtocolLab.Adapters.QuicGo run ./cmd/quic-go-raw-load`.
- Local source-reference proof now reaches the raw QUIC load generator and
  produces parseable metrics for `quic.transport.stream-throughput.1mb`,
  `quic.transport.multiplex.100x64kb`, and `quic.transport.duplex-streams`.
  Successful proof artifacts should show `validation=Passed`,
  `benchmark=succeeded`, and `loadTool=quic-go-raw-load`.
- This remains local shared-host evidence. It is useful for regression and
  operator readiness, but not publishable benchmark evidence without isolated
  runner resources and the live worker conditions listed in readiness evidence.

## ProtocolLab Local QUIC Benchmark Loop

Use `Invoke-ProtocolLabLocalQuicBenchmark.ps1` when you want ProtocolLab to run
against the current local `quic-dotnet` checkout instead of the published
`Incursa.Quic` packages.

The helper:

- can run in fast source-reference mode against the current `quic-dotnet`
  working tree;
- keeps `-ProtocolLabRoot` as the public contract checkout and resolves the
  runnable checkout from `-ProtocolLabExecutionRoot`,
  `PROTOCOL_LAB_EXECUTION_ROOT`, or a sibling `protocol-lab-internal`
  checkout;
- can still run in compatibility local-package mode, where it packs local
  `Incursa.Qpack`, `Incursa.Quic`, and `Incursa.Quic.Http3`;
- runs the selected ProtocolLab suite with nested PowerShell script output
  streamed to the current console;
- optionally uploads the generated publication bundle to R2.

For tight performance iteration, use project references and focused filters:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 `
  -UseProjectReferences `
  -Suite quic-transport-v1-comparison `
  -Implementation incursa-raw-quic-adapter-v1 `
  -Scenario quic.transport.multiplex.100x64kb `
  -DurationSeconds 1 `
  -WarmupSeconds 1 `
  -Repetitions 1 `
  -Connections 1 `
  -StreamsPerConnection 1
```

After the first source-mode restore, add `-NoRestore` to avoid restore work in
the close loop:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 `
  -UseProjectReferences `
  -NoRestore `
  -Suite quic-transport-v1-comparison `
  -Implementation incursa-raw-quic-adapter-v1 `
  -Scenario quic.transport.multiplex.100x64kb `
  -DurationSeconds 1 `
  -WarmupSeconds 1 `
  -Repetitions 1 `
  -Connections 1 `
  -StreamsPerConnection 1
```

Use local packages only when you explicitly need package restore compatibility
coverage. By default the helper packs local `Incursa.Qpack`, `Incursa.Quic`,
and `Incursa.Quic.Http3` packages using ProtocolLab's pinned Incursa package
version from `Directory.Packages.props` or `Directory.Build.props`. Pass
`-PackageVersion` when you need to override that local compatibility version.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 `
  -UseLocalPackages `
  -Suite h3-local-v1-comparison `
  -WorkflowProfile Quick
```

Choose the suite explicitly:

```powershell
-Suite ci-public-report
-Suite h3-local-v1-comparison
-Suite quic-transport-v1-comparison
```

`Quick` is the fastest close-loop proof. `Regression` uses the local regression
load shape. `Comparison` keeps ProtocolLab's full comparison behavior and is
intentionally slower.

## Codex Performance Work

When asking Codex to improve QUIC performance with ProtocolLab evidence, point
it at this file and ask it to use the source-reference loop above. The default
close-loop target should be:

```text
suite: quic-transport-v1-comparison
implementation: incursa-raw-quic-adapter-v1
scenario: quic.transport.multiplex.100x64kb
```

Use `-UseProjectReferences` so ProtocolLab consumes the current quic-dotnet
working tree directly. Use `-NoRestore` after the first successful source-mode
restore. Do not use `-UploadAfterRun` for local performance iteration.

ProtocolLab-owned scenario and suite files live in the sibling ProtocolLab
checkouts, not in this repo. For the standard shared Windows checkout, the
public contract root is:

```text
C:\shared\src\incursa\protocol-lab
```

The local executable benchmark-set wrapper belongs to:

```text
C:\shared\src\incursa\protocol-lab-internal
```

If either path is not valid, pass `-ProtocolLabRoot <public-contract-root>` and
`-ProtocolLabExecutionRoot <internal-runner-root>` to
`Invoke-ProtocolLabLocalQuicBenchmark.ps1`, or set `PROTOCOL_LAB_ROOT` and
`PROTOCOL_LAB_EXECUTION_ROOT` before using the xUnit bridge.

To inspect or add a raw QUIC scenario, use these ProtocolLab files first:

```text
docs\scenarios\authoring-guide.md
docs\scenarios\catalog.md
docs\runner\raw-quic-foundation.md
scenarios\quic\transport\*.yaml
suites\quic-transport-v1-comparison.yaml
tests\Incursa.ProtocolLab.Tests\SuiteDefinitionTests.cs
```

For a new benchmarkable raw QUIC scenario:

1. Add the scenario YAML under `scenarios\quic\transport\` with a stable
   `quic.transport.*` ID.
2. Add that scenario ID to `suites\quic-transport-v1-comparison.yaml`.
3. Update ProtocolLab docs/catalog entries when the scenario should be
   discoverable by humans.
4. Extend ProtocolLab tests that lock the suite contents, especially
   `SuiteDefinitionTests`.
5. If the scenario needs new protocol behavior, update the ProtocolLab raw QUIC
   adapter/load validation path before treating benchmark numbers as evidence.
6. Run the focused source-reference command from this quic-dotnet repo with the
   new `-Scenario <id>`.

Keep performance tasks scoped: preserve ProtocolLab benchmark semantics unless
the task explicitly asks to change the benchmark harness itself. For quic-dotnet
runtime changes, prefer focused unit/behavior tests first, then run the smallest
ProtocolLab source-reference scenario that exercises the changed path.

## xUnit Opt-In Bridge

Normal `dotnet test` skips ProtocolLab performance benchmarks. To run the
focused bridge test intentionally:

```powershell
$env:INCURSA_RUN_PROTOCOLLAB_PERF = "1"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --filter "Category=Performance&BenchmarkHarness=ProtocolLab"
```

The test invokes `Invoke-ProtocolLabLocalQuicBenchmark.ps1` with
`-UseProjectReferences`, tiny load settings, and no R2 upload. It fails on a
nonzero helper exit and writes ProtocolLab artifact paths to the test output.

## Run And Upload

To run one suite and upload the resulting bundle to R2:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 `
  -Suite h3-local-v1-comparison `
  -WorkflowProfile Quick `
  -UploadAfterRun
```

The upload uses ProtocolLab's R2-only uploader and does not pass a custom
prefix. Objects are written under:

```text
public/runs/{runId}/
```

The default bucket is:

```text
protocol-lab-reports
```

By default the helper verifies uploaded objects. Use `-NoUploadVerification`
only when you need a faster credentialed smoke.

The helper allows diagnostic/non-publishable local bundles by default because
`Quick` and local shared-host runs are not publishable benchmark evidence. Use
`-RequirePublishableUpload` only when you want the upload step to reject
diagnostic local bundles.

## R2 Credentials

Do not commit R2 credentials and do not rely on repo-local secret files. The
helper resolves credentials in this order:

1. Existing environment variables.
2. A file passed with `-R2CredentialsPath`.
3. A file path in `PROTOCOL_LAB_R2_CREDENTIALS_PATH`.
4. PowerShell SecretManagement secrets.

The environment variable contract is:

```text
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...        # optional, for temporary credentials
CLOUDFLARE_ACCOUNT_ID=...    # or R2_ENDPOINT=...
AWS_DEFAULT_REGION=auto
```

For a local file outside source control, set one durable user environment
variable and keep the file wherever your workstation secrets live:

```powershell
[Environment]::SetEnvironmentVariable(
  "PROTOCOL_LAB_R2_CREDENTIALS_PATH",
  "C:\Users\$env:USERNAME\.config\incursa\protocol-lab-r2.env",
  "User")
```

That file may contain either the S3-compatible names above or the R2-specific
aliases:

```text
CLOUDFLARE_ACCOUNT_ID=...
R2_ACCESS_KEY_ID=...
R2_SECRET_ACCESS_KEY=...
```

Secret values are mapped to the S3-compatible environment variables expected by
ProtocolLab's uploader and are not printed.

For a stronger local setup, use PowerShell SecretManagement with your preferred
vault and store these secret names:

```powershell
Set-Secret -Name ProtocolLab-R2-AccessKeyId -Secret "<access-key-id>"
Set-Secret -Name ProtocolLab-R2-SecretAccessKey -Secret "<secret-access-key>"
Set-Secret -Name ProtocolLab-CloudflareAccountId -Secret "<account-id>"
```

If your vault is not the default vault, pass `-R2SecretVault <vault-name>`.
Override the secret names with `-R2AccessKeyIdSecretName`,
`-R2SecretAccessKeySecretName`, `-CloudflareAccountIdSecretName`,
`-R2EndpointSecretName`, and `-R2SessionTokenSecretName`.

## Failure Semantics

ProtocolLab can still produce a publication bundle when some benchmark cells
fail. With `-UploadAfterRun`, the helper uploads that diagnostic bundle if it
exists, then exits nonzero after the upload so the failed benchmark result is
not hidden.

Use the generated run summary in ProtocolLab to inspect failures:

```text
C:\shared\src\incursa\protocol-lab\.artifacts\runs\{runId}\summary.md
```

Use the generated bundle for uploaded public-safe artifacts:

```text
C:\shared\src\incursa\protocol-lab\.artifacts\publication\{runId}
```

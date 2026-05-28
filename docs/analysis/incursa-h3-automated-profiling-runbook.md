# Incursa H3 Automated Profiling Runbook

Date: 2026-05-27

This runbook documents the automation-only profiling pack for Incursa HTTP/3
ProtocolLab h2load runs. It does not change Incursa protocol behavior,
ProtocolLab benchmark semantics, benchmark categories, or production code.

## What The Pack Collects

`scripts/perf/Invoke-IncursaH3ProfilePack.ps1` runs the existing ProtocolLab
Incursa-only HTTP/3 h2load command shape and preserves diagnostic artifacts
under a profile-pack run directory.

The default pack collects separate, clearly labeled runs:

- ProtocolLab h2load benchmark artifacts and raw stdout/stderr.
- `dotnet-counters` `System.Runtime` counters through the ProtocolLab counter
  path.
- `dotnet-trace` CPU trace, `topN` reports, and Speedscope conversion when the
  CLI supports conversion.
- `dotnet-trace` GC/allocation trace and `topN` reports.
- Optional `dotnet-gcdump` before/after live heap snapshots.
- Optional PerfView ETL/ZIP capture when `PerfView.exe` is supplied or found on
  `PATH`.
- `summary.md` generated from the preserved artifacts.

Counters, CPU traces, GC traces, gcdumps, and PerfView captures are separate
ProtocolLab passes unless the artifact explicitly says otherwise. Do not treat
them as one shared process interval.

## Restore Tools

The repo-local tool manifest is `.config/dotnet-tools.json`.

```powershell
dotnet tool restore
dotnet tool run dotnet-counters --version
dotnet tool run dotnet-trace --version
dotnet tool run dotnet-gcdump --version
```

These tools are repo-local. Do not require global diagnostic tools for the
default pack.

## ProtocolLab Command Shape

The pack delegates benchmark semantics to the existing ProtocolLab Incursa H3
path:

```powershell
dotnet run --project src/Incursa.ProtocolLab.Cli -- run `
  --implementations incursa-http3 `
  --scenarios http.core.plaintext `
  --protocol h3 `
  --load-tool h2load `
  --load-tool-mode docker `
  --connections 16 `
  --streams-per-connection 10 `
  --duration 10 `
  --warmup 2 `
  --repetitions 1
```

The profile pack invokes this through
`scripts/perf/Run-ProtocolLabIncursaH3H2Load.ps1` for the counter, CPU trace,
and GC trace passes so it can reuse the existing `diagnostic-target.json` PID
resolution.

## Full Plaintext Pack

```powershell
pwsh -NoProfile -File scripts\perf\Invoke-IncursaH3ProfilePack.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenario plaintext `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 1 `
  -Connections 16 `
  -StreamsPerConnection 10
```

Equivalent explicit scenario:

```powershell
pwsh -NoProfile -File scripts\perf\Invoke-IncursaH3ProfilePack.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenario http.core.plaintext
```

## Full JSON Pack

```powershell
pwsh -NoProfile -File scripts\perf\Invoke-IncursaH3ProfilePack.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenario json `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 1 `
  -Connections 16 `
  -StreamsPerConnection 10
```

## Short Smoke Pack

Use this only when it will not conflict with another active P-phase run using
the Incursa HTTP/3 sample port and Docker h2load image.

```powershell
pwsh -NoProfile -File scripts\perf\Invoke-IncursaH3ProfilePack.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenario http.core.plaintext `
  -DurationSeconds 3 `
  -WarmupSeconds 1 `
  -Repetitions 1 `
  -Connections 4 `
  -StreamsPerConnection 4
```

## Output Layout

Default output root:

```text
.artifacts\perf\incursa-h3-profile-pack\{runId}
```

Important files:

- `profile-pack.json`: machine-readable run manifest.
- `summary.md`: generated human summary.
- `tools\dotnet-tool-restore.*`: local tool restore command and output.
- `counters\wrapper.*`: counter pass wrapper command/stdout/stderr.
- `cpu-trace\trace.nettrace`: raw CPU trace.
- `cpu-trace\topN-exclusive.txt`: CPU exclusive report.
- `cpu-trace\topN-inclusive.txt`: CPU inclusive report.
- `cpu-trace\*.speedscope.json`: Speedscope export when conversion succeeds.
- `gc-trace\trace.nettrace`: GC/allocation trace.
- `gc-trace\topN-inclusive.txt`: GC-profile method evidence.
- `gcdump\before.gcdump` and `gcdump\after.gcdump`: optional live heap dumps.
- `perfview\perfview.etl.zip`: optional PerfView capture.
- `protocol-lab-runs\{runId-*}`: ProtocolLab run roots with h2load stdout,
  stderr, command files, result JSON, aggregate JSON, summaries, and
  diagnostic target records.

Regenerate the summary after manual artifact edits:

```powershell
pwsh -NoProfile -File scripts\perf\Summarize-IncursaH3ProfilePack.ps1 `
  -ProfilePackRoot .artifacts\perf\incursa-h3-profile-pack\{runId}
```

## Opening Speedscope

Open the generated `*.speedscope.json` file in
<https://www.speedscope.app/> or a local Speedscope viewer.

If conversion fails, inspect:

```text
cpu-trace\dotnet-trace-convert-speedscope.stdout.txt
cpu-trace\dotnet-trace-convert-speedscope.stderr.txt
```

The raw `.nettrace` remains the authoritative artifact.

## Opening Nettrace Files

Open `.nettrace` files in Visual Studio diagnostics tooling or PerfView. CPU
topN reports are convenience summaries; they are not a replacement for stack
inspection.

For allocation stacks, prefer PerfView or Visual Studio and inspect GC
allocation stacks for:

- `System.Byte[]`
- `Incursa.Quic`
- `Incursa.Quic.Http3`
- `Incursa.Qpack`
- packet build/open, STREAM payload, HTTP/3 frame payload, and QPACK
  encode/decode boundaries

## PerfView

Automatic PerfView capture is optional:

```powershell
pwsh -NoProfile -File scripts\perf\Invoke-IncursaH3ProfilePack.ps1 `
  -Scenario plaintext `
  -CollectPerfView `
  -PerfViewPath C:\tools\PerfView\PerfView.exe
```

If PerfView is unavailable, the pack records manual instructions in
`perfview\perfview-unavailable.txt` and continues.

Manual capture shape:

```powershell
PerfView.exe /AcceptEula /NoGui collect /MaxCollectSec:30 /DataFile:incursa-h3.etl.zip /Process:<pid>
```

Use `diagnostic-target.json` from the ProtocolLab run root to find the Incursa
server PID.

## dotnet-gcdump

Enable optional heap snapshots:

```powershell
pwsh -NoProfile -File scripts\perf\Invoke-IncursaH3ProfilePack.ps1 `
  -Scenario plaintext `
  -CollectGcDump
```

`dotnet-gcdump` shows live heap composition at the collection point. It does
not prove transient allocation rate and should not be used as the only evidence
for the h2load allocation path. It is useful for retained-object review.

## dotnet-trace Limitations

`dotnet-trace report topN` provides method-level sampled evidence. It is useful
for CPU orientation and rough GC-profile overlap, but it does not reliably give
per-type allocation call stacks such as exact `System.Byte[]` stack roots.

When the next P-phase requires allocation-stack attribution, attach the
generated `.nettrace` or PerfView `.etl.zip` to the phase document and state
which tool produced the stack evidence.

## Attaching Findings To P-Phase Work

For the current Incursa H3 performance investigation, attach:

- the profile-pack `summary.md`;
- the ProtocolLab benchmark run root;
- raw `.nettrace` paths;
- Speedscope path if generated;
- PerfView `.etl.zip` path if available;
- manual allocation-stack screenshots or exported tables when PerfView/Visual
  Studio is used;
- a clear statement of whether the evidence is counter-only, CPU sampled,
  GC-profile sampled, live-heap only, or true allocation-stack evidence.

Do not record a new optimization target unless the artifact proves the source
well enough to justify behavior tests and a bounded benchmark.

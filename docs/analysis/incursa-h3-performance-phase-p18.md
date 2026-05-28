# Incursa H3 Performance Phase P18

Date: 2026-05-28

## Scope

Phase P18 is post-P17 allocation attribution and next-source selection. No protocol optimization was made in this phase.

Guardrails held:

- ProtocolLab benchmark semantics unchanged.
- QUIC scheduling, UDP send, packet protection, ACK/loss recovery, QPACK semantics, and HTTP/3 semantics unchanged.
- No `/plaintext`, `/json`, h2load, or TechEmpower special-casing was added.

## P17 Recap

P17 removed the per-request 16 KiB scratch/read buffer allocation in `Http3Server.ReadRequestAsync`:

```csharp
byte[] buffer = new byte[readBufferSize];
```

The replacement rents from `ArrayPool<byte>.Shared`, reads only up to the configured `readBufferSize`, and returns the buffer in `finally`.

Selected P17 BenchmarkDotNet result:

| Benchmark | Before allocated | After allocated | Delta |
| --- | ---: | ---: | ---: |
| `RequestReadBuffer_FrameReaderPlaintextHeaders` | 16,632 B | 224 B | -16,408 B |
| `ReadRequestAsync_HeadersOnlyGetPlaintext` | 18,104 B | 1,696 B | -16,408 B |
| `ReadRequestAsync_HeadersOnlyGetJson` | 18,080 B | 1,672 B | -16,408 B |
| `ReadRequestAsync_FragmentedHeaders` | 18,256 B | 1,848 B | -16,408 B |
| `ReadRequestAsync_HeadersAndSmallData` | 18,912 B | 2,504 B | -16,408 B |

P17 ProtocolLab counters moved Incursa from the previous 33-36 KB/request range down to roughly 21-23 KB/request. The change is worth keeping.

## ArrayPool Clearing Decision

The pooled `ReadRequestAsync` buffer can contain decrypted HTTP request bytes while the request stream is being parsed.

`clearArray: false` remains acceptable for this library because:

- the buffer is private scratch storage and is not returned through request, body, header, or frame objects;
- `Http3FrameReader` copies complete frame payloads and pending fragmented bytes into owned storage;
- request DATA is copied from frame payload storage into the request body writer;
- returning without clearing matches common hot-path `ArrayPool<T>` usage where the pool is trusted process-local infrastructure.

`clearArray: true` should be considered only if this library adopts a stronger in-process data-remanence policy for decrypted request bytes. The expected tradeoff is a per-request 16 KiB memory clear on the same hot path P17 just improved. That cost should be benchmarked before changing the decision.

No code comment was added in P18. The P17/P18 analysis documents record the lifetime and clearing rationale, and the current implementation is compact. A future comment would be reasonable if the clearing decision becomes a recurring review concern.

## Fresh Incursa-Only Counters

Command:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.plaintext,http.core.json `
  -Connections 16 `
  -StreamsPerConnection 10 `
  -DurationSeconds 10 `
  -WarmupSeconds 2 `
  -Repetitions 3 `
  -RunId local-incursa-h3-p18-counters-20260528 `
  -CaptureCounters
```

Artifacts:

- `C:\src\incursa\protocol-lab\.artifacts\runs\local-incursa-h3-p18-counters-20260528`

All 6 validation and benchmark cells passed. Runtime counters were captured for all 6 cells.

| Scenario | Rep | Req/s | p50 ms | p95 ms | p99 ms | Allocation rate B/s | B/request est. | CPU mean/max | GC gen0/gen1/gen2 | Exceptions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `http.core.json` | 1 | 3,597.9 | 18.413 | 28.891 | 36.639 | 76,074,049 | 21,144 | 69.3% / 164.1% | 95 / 30 / 4 | 401 |
| `http.core.json` | 2 | 3,791.0 | 9.907 | 16.265 | 21.095 | 81,029,315 | 21,374 | 71.1% / 135.9% | 103 / 31 / 5 | 81 |
| `http.core.json` | 3 | 3,255.5 | 26.363 | 39.458 | 49.167 | 72,360,498 | 22,227 | 67.4% / 129.7% | 91 / 28 / 4 | 417 |
| `http.core.plaintext` | 1 | 3,627.1 | 20.827 | 33.151 | 39.444 | 78,166,795 | 21,551 | 71.0% / 159.4% | 97 / 31 / 4 | 685 |
| `http.core.plaintext` | 2 | 3,510.0 | 24.708 | 35.748 | 45.159 | 75,349,146 | 21,467 | 67.0% / 157.8% | 94 / 29 / 4 | 336 |
| `http.core.plaintext` | 3 | 3,702.9 | 15.344 | 23.681 | 29.992 | 78,016,955 | 21,069 | 68.3% / 151.6% | 99 / 31 / 4 | 196 |

Current Incursa range:

- JSON: 21.1-22.2 KB/request.
- Plaintext: 21.1-21.6 KB/request.

Run stability:

- all cells passed;
- local shared-host warnings remain: no CPU isolation, no network isolation, host-docker-internal rewrite, missing load-generator metrics, and no repeated stable median;
- JSON showed visible latency/throughput variation across reps;
- exception counts varied and should remain on the future attribution list, but are not enough by themselves to select a P19 target.

## Fresh Allocation Profiling

PerfView was not available on PATH. The repo-local `dotnet-trace` tool was available:

- `dotnet-trace 9.0.661903+d7b455b46332b31fd9ba3a3f3e020387984c511a`

Two post-P17 GC allocation traces were collected with the same c16/s10 h2load shape and 30-second workload duration:

```powershell
pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.plaintext `
  -Connections 16 -StreamsPerConnection 10 `
  -DurationSeconds 30 -WarmupSeconds 2 -Repetitions 1 `
  -RunId local-incursa-h3-p18-plaintext-gc-20260528 `
  -CaptureCounters -TraceMode gc-allocation `
  -TraceArtifactRoot C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p18\plaintext-gc-allocation `
  -TraceDurationSeconds 40

pwsh -NoProfile -File scripts\perf\Run-ProtocolLabIncursaH3H2Load.ps1 `
  -ProtocolLabRoot C:\src\incursa\protocol-lab `
  -Scenarios http.core.json `
  -Connections 16 -StreamsPerConnection 10 `
  -DurationSeconds 30 -WarmupSeconds 2 -Repetitions 1 `
  -RunId local-incursa-h3-p18-json-gc-20260528 `
  -CaptureCounters -TraceMode gc-allocation `
  -TraceArtifactRoot C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p18\json-gc-allocation `
  -TraceDurationSeconds 40
```

Trace artifacts:

| Scenario | Trace | Analysis |
| --- | --- | --- |
| Plaintext | `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p18\plaintext-gc-allocation\trace.nettrace` | `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p18\plaintext-byte-stack-analysis\byte-stack-summary.md` |
| JSON | `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p18\json-gc-allocation\trace.nettrace` | `C:\src\incursa\quic-dotnet\.artifacts\perf\incursa-h3-p18\json-byte-stack-analysis\byte-stack-summary.md` |

`dotnet-trace report topN` failed on the plaintext trace with `System.FormatException: Read past end of stream`. TraceEvent could read allocation tick payloads, but stack extraction returned empty stacks for this post-P17 trace. The fresh evidence is therefore strong for allocated type ranking, but weak for exact call-stack/source-line attribution.

## Top Allocated Types

Plaintext sampled allocation:

- total sampled allocation bytes: 3,185,173,584;
- sampled `System.Byte[]`: 443,862,848 bytes;
- sampled `System.Byte[]` share: 13.9%.

Top plaintext types:

| Type | Count | Sampled bytes | Share |
| --- | ---: | ---: | ---: |
| `Incursa.Qpack.QPackFieldLine[]` | 5,921 | 630,965,304 | 19.8% |
| `System.Byte[]` | 4,165 | 443,862,848 | 13.9% |
| `System.Object` | 1,280 | 136,418,040 | 4.3% |
| `Incursa.Quic.Http3.Http3DiagnosticEvent` | 1,244 | 132,574,456 | 4.2% |
| `Entry<System.UInt64>[]` | 876 | 93,339,408 | 2.9% |
| `Incursa.Quic.QuicConnectionSendDatagramEffect` | 729 | 77,682,688 | 2.4% |
| `Enumerator<System.UInt64, Incursa.Quic.QuicRecoverySentPacketState>` | 718 | 76,512,560 | 2.4% |
| `Incursa.Quic.QuicAckFrame` | 635 | 67,662,176 | 2.1% |
| `Incursa.Quic.QuicConnectionEffect[]` | 612 | 65,221,288 | 2.0% |

JSON sampled allocation:

- total sampled allocation bytes: 3,231,502,488;
- sampled `System.Byte[]`: 448,146,952 bytes;
- sampled `System.Byte[]` share: 13.9%.

Top JSON types:

| Type | Count | Sampled bytes | Share |
| --- | ---: | ---: | ---: |
| `Incursa.Qpack.QPackFieldLine[]` | 5,941 | 633,102,256 | 19.6% |
| `System.Byte[]` | 4,205 | 448,146,952 | 13.9% |
| `Incursa.Quic.Http3.Http3DiagnosticEvent` | 1,356 | 144,503,176 | 4.5% |
| `System.Object` | 1,276 | 135,973,064 | 4.2% |
| `Entry<System.UInt64>[]` | 927 | 98,788,816 | 3.1% |
| `Enumerator<System.UInt64, Incursa.Quic.QuicRecoverySentPacketState>` | 731 | 77,892,360 | 2.4% |
| `Incursa.Quic.QuicAckFrame` | 653 | 69,603,920 | 2.2% |
| `System.Net.IPAddress` | 629 | 67,067,312 | 2.1% |
| `Incursa.Quic.QuicConnectionSendDatagramEffect` | 627 | 66,813,008 | 2.1% |

## Source Split

The fresh post-P17 evidence supports this split:

| Bucket | Evidence | P18 conclusion |
| --- | --- | --- |
| HTTP/3 frame reader payload buffers | `System.Byte[]` remains 13.9%, but stack extraction was empty. Source review still shows `Http3FrameReader` payload/pending `ToArray()` sites. | Still a candidate, but no longer the dominant sampled type and not stack-attributed in this trace. |
| QPACK decode/encode arrays | `QPackFieldLine[]` is top sampled type in both plaintext and JSON: 19.8% and 19.6%. Source review points at `QPackDecoder.DecodeAvailableFieldSection(...).WrittenSpan.ToArray()`. | New dominant allocation family by type. Select for P19 measurement/benchmarking. |
| Request object/header materialization | Request lifecycle benchmarks remain around 1.2-1.3 KB/op after P17; `QPackFieldLine[]` may include request header decode/materialization. | Needs source-stack or focused BDN split before optimization. |
| STREAM payload construction | Not top by type; older sources remain possible. | Not selected. |
| Packet build/protection buffers | Byte[] stacks unavailable; packet/effect-related types are visible but individually smaller. | Not selected for P19. |
| Packet open/decrypt buffers | No direct post-P17 stack proof. | Not selected. |
| UDP receive/datagram ownership | No direct post-P17 stack proof. | Not selected. |
| ACK/frame model allocation | `QuicAckFrame` is about 2.1-2.2%; ACK generation collection arrays also appear. | Real but not dominant. |
| Lifecycle/timer/effect arrays | `QuicConnectionEffect[]`, transition slots, timer tuples, and volatile nodes appear below the top two types. | Real but not dominant. |
| Diagnostics/qlog/event allocations | `Http3DiagnosticEvent` is 4.2-4.5% even though event construction happens before the `IsEnabled` check. | Significant and bounded, but not the top source. Keep as a later candidate if QPACK is not safely reducible. |
| Async/task/read lifecycle allocation | `AsyncStateMachineBox<WriteFinalStreamAsync>` and task objects appear below the top buckets. | Real but not selected. |
| Unknown/unclassified | All `System.Byte[]` stack buckets were unknown because stack extraction was empty. | Needs manual Visual Studio/PerfView attribution before a byte-array optimization. |

## Did `System.Byte[16384]` Disappear?

P18 did not have a Visual Studio source-line allocation profile, so it cannot independently prove the Visual Studio `System.Byte[16384]` row disappeared.

The evidence is nevertheless consistent with P17 removing it:

- the source allocation is gone from `Http3Server.ReadRequestAsync`;
- P17 BDN removed 16,408 B/op from server-shaped request-read rows;
- P18 sampled `System.Byte[]` share is 13.9%, far below the old pre-P17 41-44% sampled byte-array share;
- the fresh traces did not provide object-size or stack detail for `System.Byte[]`, so no new `System.Byte[16384]` row was identified.

## P18 Decision

No optimization was performed in P18.

Reason:

- the new top sampled allocation type is clear: `Incursa.Qpack.QPackFieldLine[]`;
- the source stack is not clear from the available EventPipe trace;
- QPACK decode/header materialization is behavior-sensitive and must be benchmarked and tested before edits;
- `System.Byte[]` call stacks were not extractable, so byte-array source selection would be speculative.

## Selected P19 Target

Selected P19 target:

- QPACK request field-line array allocation and request header materialization under the HTTP/3 ingress path.

Initial source candidate:

- `src\Incursa.Qpack\QPackDecoder.cs`
- `DecodeAvailableFieldSection`
- `return fields.WrittenSpan.ToArray();`

This should start as measurement and tests, not an immediate rewrite. The P19 work should split:

- QPACK decode array allocation;
- validator/header ownership;
- `Http3Request` header retention;
- response-side QPACK arrays if they appear in source-stack evidence.

## Validation

Commands run:

```powershell
dotnet build
dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj
git diff --check
$errors = @()
Get-ChildItem -Path scripts\perf -Filter *.ps1 | ForEach-Object {
  $tokens = $null
  $parseErrors = $null
  $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors) {
    $errors += $parseErrors | ForEach-Object { "$($_.Extent.File):$($_.Extent.StartLineNumber):$($_.Message)" }
  }
}
if ($errors.Count -gt 0) { $errors; exit 1 } else { 'PowerShell parser check passed for scripts\perf\*.ps1' }
```

Results:

- `dotnet build benchmarks\Incursa.Quic.Benchmarks.csproj`: passed.
- First parallel `dotnet build`: failed with `CS2012` on `Incursa.Qpack.dll` because the benchmark build and solution build wrote the same project output concurrently while Defender held the file. This was a validation-command collision, not a source failure.
- Serial rerun of `dotnet build`: passed with 0 warnings and 0 errors.
- `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`: failed with the known baseline only: 5 trace-link failures and 2 DoQ cancellation exact-type failures; 5,947 passed, 7 failed, 5,954 total.
- `git diff --check`: passed.
- PowerShell parser check for `scripts\perf\*.ps1`: passed.

Since P18 made no production, benchmark, or test code changes, focused tests and BDN reruns were not required beyond the profiling runs.

## Recommended P19 Prompt

Continue Incursa H3 Performance Phase P19: QPACK field-line allocation attribution and bounded reduction.

Work in `C:\src\incursa\quic-dotnet`.

Context:

- P17 removed the per-request 16 KiB `Http3Server.ReadRequestAsync` scratch buffer allocation.
- P18 fresh counters keep Incursa around 21-22 KB/request.
- P18 post-P17 allocation traces show `Incursa.Qpack.QPackFieldLine[]` as the top sampled allocation type:
  - plaintext: 630,965,304 sampled bytes, 19.8%;
  - JSON: 633,102,256 sampled bytes, 19.6%.
- `System.Byte[]` is now 13.9% in both traces, and EventPipe stack extraction returned empty stacks.
- Do not optimize byte arrays from stale pre-P17 stack data.
- Do not change QUIC scheduling, UDP send, packet protection, ACK/loss recovery, ProtocolLab semantics, endpoint behavior, or request validation semantics.

Primary goal:

Attribute and reduce exactly one QPACK/request-header field-line array allocation if fresh source-stack or focused BDN evidence proves it is bounded and behavior-testable.

Required steps:

1. Add or refine focused BDN rows that isolate:
   - `QPackDecoder.DecodeFieldSection` for plaintext and JSON request field sections;
   - `Http3RequestMessageValidator.ReceiveOwnedHeaders`;
   - `TryCreateNoBodyGetRequest`;
   - full request decode/validate/materialize lifecycle.
2. Add behavior tests first for:
   - valid pseudo-header order;
   - duplicate pseudo-headers;
   - missing pseudo-headers;
   - malformed QPACK field sections;
   - unknown regular headers;
   - HEADERS-only GET `/plaintext` and `/json`;
   - HEADERS plus DATA request body preservation.
3. Optimize only one proven allocation source.
4. Preserve QPACK ordering, header validation semantics, request header ownership, and public defensive-copy behavior unless tests and docs explicitly justify a narrower internal ownership path.
5. Run before/after BDN, focused tests, `dotnet build`, full test project, `git diff --check`, and PowerShell parser checks.
6. Rerun ProtocolLab Incursa-only counters only if the selected BDN row moves meaningfully.
7. Document whether B/request moved and classify any failures against the known baseline.

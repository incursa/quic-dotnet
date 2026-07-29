---
title: "Adaptive Runtime Send-Admission Performance Pilot"
---

# Adaptive Runtime Send-Admission Performance Pilot

The bounded four-cell ProtocolLab rack pilot completed from clean source commit
`fc82651ce20ec2cdd55a5ea6c902e9ff285bd13d`. It ran eight measured
repetitions on independent physical hosts: `plab-worker-x64-02` hosted the
system under test and `plab-worker-x64-03` hosted the load generator. All
repetitions transferred the exact requested bytes with zero request failures,
zero timeouts, and no detected load-generator saturation.

The canonical machine-readable result is
[`adaptive-runtime-send-admission-performance-pilot-result-v1.json`](../../eng/adaptive-runtime/experiment-control/adaptive-runtime-send-admission-performance-pilot-result-v1.json),
with content SHA-256
`2887fed8f5769acbd90bafaf18418f0de81ed8f969ad2c23705e422f292ff610`.

## Directional results

Each value below is descriptive, not an acceptance statistic. The midpoint is
the arithmetic mean of the two retained repetitions.

| Cell | R1 requests/s | R2 requests/s | Midpoint requests/s | Midpoint p95 latency | Requests/s versus A0 | p95 versus A0 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A0 | 112.18 | 118.89 | 115.53 | 909.04 ms | baseline | baseline |
| A4 | 118.89 | 118.13 | 118.51 | 902.80 ms | +2.57% | -0.69% |
| A3 | 117.81 | 114.94 | 116.37 | 894.49 ms | +0.73% | -1.60% |
| A7 | 114.62 | 120.55 | 117.58 | 882.57 ms | +1.77% | -2.91% |

The pilot therefore produced usable numbers, but no stable winner or adaptive
rule. A4 had the highest descriptive requests-per-second midpoint and A7 had
the lowest descriptive p95 midpoint. Two repetitions per cell, serial
nonrandomized execution, worker CPU asymmetry, unavailable target-process
metrics, and unknown load-generator CPU utilization prevent either observation
from becoming a performance-acceptance claim. The selected cells also combine
the batch and buffer treatments, so this pilot cannot attribute their effects
independently.

## Bounded evidence

Runtime evidence was retained as fixed-memory, once-per-second cumulative
aggregates. The four compact server stdout artifacts were 41,827, 42,775,
43,740, and 43,684 bytes, all below the 65,536-byte bound. Every cell retained
positive batch, oversized-write, buffer-copy, and owner-release counts without
arithmetic saturation. This replaces the earlier multi-gigabyte raw-output
failure mode for this pilot.

Reproduce and verify the canonical result from a retained execution directory
with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/New-AdaptiveRuntimeAdmissionPerformancePilotResult.ps1 `
  -ExecutionRoot <execution-root>

pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeAdmissionPerformancePilotResult.ps1 `
  -ExecutionRoot <execution-root>
```

The verifier also runs portably without `-ExecutionRoot`; in that mode it
validates the committed result, schema, hash, safety gates, bounded aggregates,
and negative authorization cases without replaying external rack artifacts.

## Covering-array and next-campaign decision

Covering arrays do not block numbers for this family. The current reviewed
family has eight effective cells, so exhaustive A0 through A7 enumeration is
smaller than the reviewed covering-array trigger of 65. No generator is
implemented or needed for this milestone.

The next credible performance campaign should add randomized or
counterbalanced blocks, substantially more repetitions, and target/load
resource metrics. Expanding from the four-cell pilot to all eight reviewed
cells would also separate the batch and buffer effects. A covering-array
generator becomes implementation work only when a future reviewed factor
family reaches at least 65 effective cells or additional factors make
exhaustive enumeration impractical.

Performance acceptance, adaptive-rule derivation, `active_internal`, and
production activation remain unauthorized.

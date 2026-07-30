---
title: "Adaptive Runtime Send-Admission Performance Pilot"
---

# Adaptive Runtime Send-Admission Performance Pilot

The bounded four-cell ProtocolLab rack pilot completed from clean source commit
`c9ff68a9811a01902cdc09549f843239f5dd4016`. It ran eight measured
repetitions on independent physical hosts: `plab-worker-x64-02` hosted the
system under test and `plab-worker-x64-03` hosted the load generator. All
repetitions transferred the exact requested bytes with zero request failures,
zero timeouts, and no detected load-generator saturation.

The canonical machine-readable result is
[`adaptive-runtime-send-admission-performance-pilot-result-v1.json`](../../eng/adaptive-runtime/experiment-control/adaptive-runtime-send-admission-performance-pilot-result-v1.json),
with content SHA-256
`2bdad29055956afea81f468700dd78602cf8381c35564ce7f5f61ccab5ee4412`.

## Directional results

Each value below is descriptive, not an acceptance statistic. The midpoint is
the arithmetic mean of the two retained repetitions.

| Cell | R1 requests/s | R2 requests/s | Midpoint requests/s | Midpoint p95 latency | Requests/s versus A0 | p95 versus A0 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A0 | 112.26 | 113.06 | 112.66 | 930.14 ms | baseline | baseline |
| A4 | 115.53 | 118.78 | 117.16 | 898.88 ms | +3.99% | -3.36% |
| A3 | 115.42 | 117.73 | 116.58 | 896.05 ms | +3.48% | -3.67% |
| A7 | 110.56 | 111.81 | 111.18 | 923.28 ms | -1.31% | -0.74% |

The pilot therefore produced usable numbers, but no stable winner or adaptive
rule. A4 had the highest descriptive requests-per-second midpoint and A3 had
the lowest descriptive p95 midpoint. Two repetitions per cell, serial
nonrandomized execution, worker CPU asymmetry, unavailable target-process
metrics, and unknown load-generator CPU utilization prevent either observation
from becoming a performance-acceptance claim. The selected cells also combine
the batch and buffer treatments, so this pilot cannot attribute their effects
independently.

## Bounded evidence

Runtime evidence was retained as fixed-memory cumulative aggregates. The
adaptive-runtime aggregate remained once per second; the additional raw-stream
outcome aggregate was reduced to a five-second cadence while preserving
immediate first-error output. The four compact server stdout artifacts were
46,806, 48,313, 47,792, and 47,738 bytes, all below the 65,536-byte bound.
Every cell retained positive batch, oversized-write, buffer-copy, and
owner-release counts without arithmetic saturation. This replaces the earlier
multi-gigabyte raw-output failure mode for this pilot.

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

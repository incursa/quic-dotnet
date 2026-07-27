---
title: "Adaptive Runtime Send-Composition Holdout Extension Review"
---

# Adaptive Runtime Send-Composition Holdout Extension Review

Status: passed bounded measurement integrity; decision
`measurement_completed_no_stable_rule`

## Authority and execution

The extension measured exact committed source
`e8c62e82af8111fe8adb3fd05c2d9c494821f9e0` through the existing production
QUIC mechanism harness. The source worktree was clean. The campaign document
hash was
`21835708e640c57a5bd90ba37632763f62793c0833549cabd5b758c0d785c7b6`,
the manifest hash was
`22bce631f18b637fafd5154bdf24fee26c6d883d15ae1321124820a9d8f7334a`,
and the binary hash was
`eb74daff04582fc31619446da82dffb040b89aee914f9dff062a7d9c8769ff04`.
The host fingerprint was
`ec0ab0b29e4e646d980fdc7919280d12de84fa63e86fb352eae7eae1f573cad5`.

The clean pilot had 16 runs and passed its variance and activation gates. A
separate 64-run activation preflight inspected only correctness, release, and
mechanism activation. The sealed campaign then retained 176 runs: 16 pilot, 96
training, and 64 holdout.

## Classification and mechanism result

| Classification | Count |
| --- | ---: |
| `performance_eligible` | 93 |
| `expected_equivalent` | 30 |
| `inactive_control` | 40 |
| `activation_missing` | 13 |

All three new activation-expected holdouts had four repetitions of each
configured cell. B and D actuated batch formation, C actuated buffer
coalescing, and D retained the reviewed B-equivalent effective signature.
Every inactive-control cell remained inactive. Every run passed correctness,
and combined owner rents and releases reconciled exactly.

## Deterministic rebuild

Behavior materialization hash:
`2223a544c624131132bc5339d64837eccd37f4cf5454a0b5b9bac004293446d4`

Outcome materialization hash:
`1393133ad1047f9f5e78394a64ac9dd589357f8c6e0e1c0587e4f7bd345636fd`

Projection content hash:
`578067eca23c8af10c4560f2ef265a8c64a1beeb9f15be125c3e984df2008c7e`

Analysis content hash:
`c558895ea812fe99d2df9dca5930aca40468b17f6c198a36510bbc436bfb49a2`

Independent repeated projection and analysis builds were byte-identical. The
holdout-result regression independently revalidated all 176 raw documents,
classification totals, activation, expected equivalence, exact release,
document schemas and hashes, and the no-rule conclusion.

## Statistical and selection result

Training and holdout batch, buffer, and configured-interaction confidence
intervals all crossed zero. The holdout medians were -1.63%, 2.12%, and
-2.89%, respectively. D versus B remained expected-equivalent at 0.68%.

The only evaluated selector inputs were the legitimate bounded observations
`legal_eligible_write_count` and `source_segment_count`. Held-out accuracy was
2/3. Since no effect passed the predeclared practical and confidence gates,
the correct result is `no_stable_rule`. No shadow selector, runtime rule,
model, threshold, or production actuation was added.

## Commands

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionPerformanceHoldoutExtension.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionPerformanceHoldoutResults.ps1 `
  -EvidenceRoot C:\shared\temp\quic-send-composition-holdout-e8c62e82-full
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionPerformancePilot.ps1 `
  -EvidenceRoot C:\shared\temp\quic-send-composition-holdout-e8c62e82-full
pwsh -NoProfile -File eng/adaptive-runtime/New-AdaptiveRuntimeSendCompositionPerformanceProjection.ps1 `
  -EvidenceRoot C:\shared\temp\quic-send-composition-holdout-e8c62e82-full
pwsh -NoProfile -File eng/adaptive-runtime/Measure-AdaptiveRuntimeSendCompositionPerformance.ps1 `
  -EvidenceRoot C:\shared\temp\quic-send-composition-holdout-e8c62e82-full
```

All measurement remained offline and limited to the reviewed two-axis family.
`active_internal`, performance acceptance, shadow implementation, and
production activation remain unauthorized.

---
title: "Adaptive Runtime Send-Composition Selector Assessment"
---

# Adaptive Runtime Send-Composition Selector Assessment

Decision: `measurement_completed_no_stable_rule`

No shadow selector was implemented. The initial campaign and its
`measurement_completed_more_context_required` result remain retained; this
assessment records the completed, predeclared activation-qualified extension.

## Sealed evidence

The extension assessment uses the manifest-v2 campaign rooted at:

```text
C:\shared\temp\quic-send-composition-holdout-e8c62e82-full
```

The measured source commit is
`e8c62e82af8111fe8adb3fd05c2d9c494821f9e0`, the binary SHA-256 is
`eb74daff04582fc31619446da82dffb040b89aee914f9dff062a7d9c8769ff04`,
and the manifest content hash is
`22bce631f18b637fafd5154bdf24fee26c6d883d15ae1321124820a9d8f7334a`.
The deterministic analysis content hash is
`c558895ea812fe99d2df9dca5930aca40468b17f6c198a36510bbc436bfb49a2`.

The full extension retained 176 runs: 93 `performance_eligible`, 30
`expected_equivalent`, 40 `inactive_control`, and 13 `activation_missing`.
All three new activation-expected holdouts supplied a complete
eligible/equivalent A/B/C/D block.

## Effect result

| Effect | Training median (95% interval) | Holdout median (95% interval) |
| --- | ---: | ---: |
| Batch B versus A | -0.82% (-2.90% to 1.75%) | -1.63% (-4.49% to 2.59%) |
| Buffer C versus A | 3.48% (-1.41% to 8.74%) | 2.12% (-2.40% to 3.34%) |
| Configured interaction | -3.04% (-9.92% to 1.65%) | -2.89% (-6.67% to 1.86%) |
| Expected equivalence D versus B | 0.04% (-1.31% to 1.80%) | 0.68% (-4.46% to 3.40%) |

No training or holdout main effect or interaction excluded zero. Descriptive
pooled holdout medians showed no guardrail reason to override that uncertainty:
B and C had 5.26% and 6.63% lower P95 latency than A and 5.28% and 4.29% lower
CPU per operation, while allocated bytes were within 0.06% and fairness stayed
near one. These pooled summaries are guardrails, not substitutes for the
blocked effect estimates.

## Held-out result

The predeclared extension holdouts were `holdout_segment_rich_medium`,
`holdout_many_stream_medium`, `holdout_copy_pressure_upload`, and
`inactive_control`. Every activation-expected context reached batch actuation
in B and D and buffer actuation in C for all four repetitions. D remained
expected-equivalent to B because batch shortening leaves buffer coalescing
inactive at the production seam. The inactive control remained inactive.

The only permitted selector inputs evaluated were
`legal_eligible_write_count` and `source_segment_count`. The training-only
candidate reached 1.0 training accuracy, but held-out accuracy was 2/3. Median
held-out regret was zero because the missed context had no practically stable
winner. The analysis records
`shadow_implementation_authorized=false`.

## Conclusion

The activation gap is closed, and the data continues to support the
mechanism-level B/D equivalence. It does not support a stable selection rule:
training and holdout estimates are uncertain, the predeclared practical gates
are not met, and held-out classification is incomplete. No speculative rule
was created. Workload identity, scenario, host, peer, URL, application
identity, and requested benchmark concurrency remain prohibited runtime
inputs. Production activation and `active_internal` remain unauthorized.

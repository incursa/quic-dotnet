---
title: "Adaptive Runtime Send-Composition Selector Assessment"
---

# Adaptive Runtime Send-Composition Selector Assessment

Decision: `measurement_completed_more_context_required`

No shadow selector was implemented.

## Sealed evidence

The assessment uses the manifest-v2 campaign rooted at:

```text
C:\shared\temp\quic-send-composition-performance-b3c39539-full
```

The measured source commit is
`b3c3953907483566cc2b049a2238febe98a166eb`, the binary SHA-256 is
`594ef8b2fcea3cc6279778292e9c78418350c2bf85dc8c026ff1900a35949e86`,
and the manifest content hash is
`1cd5dddf82653e5b149a0f760036056fd229c5573de7f12e738bb5c9f4f52226`.
The deterministic analysis content hash is
`4cda64682936f3a7abd82451e43b656e36ce60983066ca2a772435cac4dd74e2`.

The full campaign retained 160 runs: 66 `performance_eligible`, 18
`expected_equivalent`, 40 `inactive_control`, and 36 `activation_missing`.
Four training contexts supplied a complete eligible/equivalent A/B/C/D block:
`few_stream_bulk`, `many_stream_saturation`, `segment_rich_writes`, and
`small_chatty_bursty`.

## Effect result

| Training effect | Median | 95% blocked bootstrap interval | Classification |
| --- | ---: | ---: | --- |
| Batch B versus A | -2.71% | -4.35% to 0.19% | `uncertain` |
| Buffer C versus A | -1.95% | -6.68% to 1.26% | `uncertain` |
| Configured interaction | 2.52% | -1.71% to 5.61% | `uncertain` |
| Expected equivalence D versus B | -0.03% | -0.73% to 1.03% | `expected_equivalent` |

The eligible training contexts did not identify a stable broad winner. Pooled
cell medians also showed tradeoffs: B and C reduced copied and retained bytes,
but their P95 completion-latency medians were more than five percent above A
and their CPU-per-operation medians were higher. Fairness stayed near one and
all owner releases remained exact.

## Held-out result

The predeclared holdout contexts were `copy_memory_pressure`,
`backpressure_slow_drain`, and `inactive_control`. The first two did not reach
the required batch and buffer activation for B, C, and D; the third was
deliberately inactive. All 48 holdout runs remain retained, but no holdout
context supplies an eligible four-cell counterfactual.

The only permitted selector inputs evaluated were
`legal_eligible_write_count` and `source_segment_count`. A training-only
candidate reached 0.75 accuracy, but held-out accuracy and regret are
undefined in substance because eligible holdout labels are absent. The
analysis records zero eligible holdout contexts and
`shadow_implementation_authorized=false`.

## Conclusion

The data supports the mechanism-level B/D equivalence and proves the bounded
measurement chain, but it does not support a generalizable selection rule.
Additional predeclared holdout contexts that reliably activate the reviewed
mechanisms are required before selector work can resume. Workload identity,
scenario, host, peer, URL, application identity, and requested benchmark
concurrency remain prohibited runtime inputs. Production activation and
`active_internal` remain unauthorized.

---
title: "Adaptive Runtime Send-Composition Performance Review Package"
---

# Adaptive Runtime Send-Composition Performance Review Package

Status: bounded offline measurement complete; more eligible holdout context
required; no selector implemented; production activation unauthorized

## Repository recovery and consolidation

The primary worktree originally held coherent experiment-control ancestry and
an internally inconsistent Stage 5 ACK continuation. Before integration, the
complete repository state was copied or bundled under:

```text
C:\shared\temp\quic-pre-consolidation-20260726-114246
```

The preservation package contains staged and unstaged binary-safe patches,
untracked files, branch and worktree inventories, a 30,831,942-byte Git
bundle, 4,149 ignored worktree-evidence files totaling 757,923,731 bytes, and
SHA-256 inventories. The accepted adaptive-runtime chain was fast-forwarded
into `main`; the coherent retained buffer-schema compatibility slice was
integrated separately as `eb618b02`. The inconsistent ACK continuation was
preserved externally and was not represented as production-ready work.

Thirty-nine obsolete linked worktrees were removed after validation and stale
registrations were pruned. Fourteen merged or externally preserved local
branches were deleted. Two unrelated unique branches remain:

- `backup/machine-wipe-20260720/quic-flow-credit-bdn-baseline`;
- `codex/ci-recovery-20260717`.

No remote branch was deleted and nothing was pushed.

## Measurement authority

The canonical campaign hash is
`75cde5a89eca604d78b1e72f95007cf7bfdef5a8f14e76bae87100292fa53f45`.
It authorizes exactly:

| Cell | Batch formation | Buffer coalescing | Primary semantics |
| --- | --- | --- | --- |
| A | `legacy_current` | `legacy_current` | legacy batch and exact buffer prefix |
| B | `single_eligible` | `legacy_current` | single eligible prefix; buffer inactive |
| C | `legacy_current` | `memory_conservative` | legacy batch; two-source cap when reached |
| D | `single_eligible` | `memory_conservative` | expected-equivalent to B |

All adjacent axes remained `legacy_current`. Active behavior, performance
acceptance, and production activation authorizations remained false.

An adversarial audit discovered that manifest v1's canonical array handling
retained cell membership but erased visible execution ordering. Manifest v2
adds an exact order-preserving `execution_sequence` and retains sorted
`cell_ids` for set validation. The campaign was rerun from the corrected
committed source; earlier evidence was preserved as superseded diagnostic
evidence.

## Exact execution identity

| Fact | Value |
| --- | --- |
| Measured source commit | `b3c3953907483566cc2b049a2238febe98a166eb` |
| Binary SHA-256 | `594ef8b2fcea3cc6279778292e9c78418350c2bf85dc8c026ff1900a35949e86` |
| Manifest content hash | `1cd5dddf82653e5b149a0f760036056fd229c5573de7f12e738bb5c9f4f52226` |
| Host fingerprint | `ec0ab0b29e4e646d980fdc7919280d12de84fa63e86fb352eae7eae1f573cad5` |
| Host | Windows `10.0.26200`, x64, 12 logical processors, .NET SDK `10.0.204` |
| Pilot evidence | `C:\shared\temp\quic-send-composition-performance-b3c39539-pilot` |
| Full evidence | `C:\shared\temp\quic-send-composition-performance-b3c39539-full` |

The pilot completed 16 runs in about one minute. The full campaign completed
160 serial runs in 10 minutes 29 seconds. Every workload/cell/block record has
its own stdout, stderr, raw JSON, immutable identity, and checksum.

## Workloads and pilot

The campaign covered single-stream bulk, few-stream bulk, many-stream
saturation, sparse and bursty chatty writes, mixed bulk/interactive,
segment-rich writes, copy/memory pressure, bounded backpressure/slow drain,
and inactive controls. Workload names are offline context only.

The corrected pilot maximum useful-goodput coefficient of variation was
11.47 percent against the predeclared 15-percent maximum. Required batch and
buffer activation occurred, correctness passed, and the full campaign gate
opened without changing warmup, duration, repetition, split, or order.

## Run classification and mechanism integrity

| Classification | Count |
| --- | ---: |
| `performance_eligible` | 66 |
| `expected_equivalent` | 18 |
| `inactive_control` | 40 |
| `activation_missing` | 36 |
| Failed command or correctness | 0 |

Every combined owner rent had exactly one release; invalid releases were zero.
Behavior and outcome mappings resolve through the reviewed catalog. The
projection accounts for every operation and retains inactive and
activation-missing runs. No performance conclusion uses those excluded cells.

## Effects and guardrails

The four complete training contexts supplied 16 blocked observations for each
effect.

| Effect | Median | 95% interval | Result |
| --- | ---: | ---: | --- |
| Batch B versus A | -2.71% | -4.35% to 0.19% | uncertain |
| Buffer C versus A | -1.95% | -6.68% to 1.26% | uncertain |
| Configured interaction | 2.52% | -1.71% to 5.61% | uncertain |
| D versus B | -0.03% | -0.73% to 1.03% | expected-equivalent |

Pooled complete-context medians are descriptive guardrails, not replacements
for the blocked estimates:

| Cell | Goodput vs A | P95 vs A | CPU/op vs A | Allocation/op vs A | Copy/op vs A | Retained/op vs A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| B | +2.79% | +7.26% | +5.38% | +1.66% | -40.18% | -35.14% |
| C | +3.84% | +6.76% | +8.78% | -1.02% | -12.23% | -4.84% |
| D | -1.93% | -0.36% | +9.99% | +0.05% | -45.26% | -40.64% |

Fairness medians remained above 0.9998 with negligible cell deltas. The
goodput intervals cross zero in training, B and C exceed the declared five
percent P95 regression guardrail in the pooled descriptive view, and CPU
medians increased. No broad performance winner or stable configured
interaction is established.

## Immutable rebuild

| Artifact | Content hash or file SHA-256 |
| --- | --- |
| Behavior materialization | `df24951c8618506a6d5a1a130e13cabf8f6439bae8d74580a11350c1b581162d` |
| Outcome materialization | `64ad310332ecabd2c3542c776b5fc1bfb1f10b8508dffbe189685215d8173b5f` |
| Projection content hash | `34cad6ff0eb09cabe44b9ccc8fabdcc865411aeda5bb65a1b8ea791c19b31dc7` |
| Projection file SHA-256 | `f8b8792af86f1641a455cf826622c80ae85a71d3e892af3053089343edd6f464` |
| Analysis content hash | `4cda64682936f3a7abd82451e43b656e36ce60983066ca2a772435cac4dd74e2` |
| Analysis file SHA-256 | `f64bc6398b090eb2a19d31d93a99c9c0c4b8b8d3e5414c6782ff301003af6e2a` |
| Raw checksum inventory SHA-256 | `cf54d1a55ba1a7042efd169de9127ce190fe0a6247c67c011c5f1e6b6502a40d` |

Repeated projection and analysis builds were byte-identical. Seven
adversarial mutations were rejected: active authorization, duplicate cell,
wrong proof reference, stale binary identity, wrong runtime cell, duplicate
owner release, and projection input substitution.

## Selector and held-out assessment

The permitted observations examined were legal eligible-write count and source
segment count. Four complete training contexts existed. The three predeclared
holdout contexts supplied zero complete eligible four-cell comparisons:
`copy_memory_pressure` and `backpressure_slow_drain` missed required treatment
activation, while `inactive_control` was deliberately inactive.

The outcome is `measurement_completed_more_context_required`.
`shadow_implementation_authorized` is false. No selector, model, threshold, or
runtime rule was added.

## Safety and scope closeout

- BenchmarkDotNet and ProtocolLab were not used.
- Treatments ran serially on one host.
- No policy mechanism or unrelated axis was migrated.
- `active_internal` and production activation remain unauthorized.
- CI was untouched.
- Nothing was pushed.

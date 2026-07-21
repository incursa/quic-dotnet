---
title: "Adaptive Runtime Shadow Foundation Evidence - 2026-07-21"
---

# Adaptive Runtime Shadow Foundation Evidence - 2026-07-21

Status: local shadow foundation verified; non-promoting

This record covers the internal forced receive-credit seam, bounded connection
observations, deterministic legacy-selector shadow replay, offline-only
evidence validation, and cost benchmarks. It does not authorize
`active_internal`, widen receive-credit behavior, publish a performance claim,
or represent a completed matched forced-policy campaign.

## Repository Checkpoints

- `24cd5456` - canonical ARC/WI/VER trace foundation
- `55cea560` - internal forced receive-credit modes
- `8e578c6f` - bounded versioned connection observations
- `6e408789` - deterministic receive-credit shadow replay
- `aacb8e46` - schema-backed evidence validation and examples
- `9804fc25` - permanent adaptive-runtime cost benchmarks
- `fec7a047` - reflection-free offline-boundary proof

The accepted receive-credit authority and rollback target remains `1b2611e1`.
No controller output is consumed by the runtime behavior path. Shadow mode
records `legacy_current` as applied and cannot be combined with an internal
forced mode.

## Focused Verification

- Release build of `src/Incursa.Quic/Incursa.Quic.csproj`: passed with zero
  warnings and zero errors.
- `REQ-QUIC-CRT-0164` through `REQ-QUIC-CRT-0169`: 34 passed, 0 failed,
  0 skipped.
- Adjacent receive-credit terminal/final-read guards: 17 passed, 0 failed,
  0 skipped.
- Existing application-send pressure classifier: 13 passed, 0 failed,
  0 skipped.
- Private-reflection guard plus `REQ-QUIC-CRT-0168`: 2 passed, 0 failed,
  0 skipped after the owned proof correction.
- The canonical shadow local-result and epoch-row examples validated against
  both v1 schemas and joined by run/campaign/cell and policy contract versions.
- A schema-valid `negative_retained` variant preserved its retained evidence
  reference. Malformed ABBA sequencing, contradictory exclusion flags, and
  missing provenance were rejected.
- `git diff --check` passed at every committed checkpoint.

Steady-state unit proofs observed zero managed allocation across 1,024 bounded
observation captures and 1,024 shadow evaluations. Duplicate and out-of-order
epochs are rejected; missing, stale, contradictory, saturated, version-mismatch,
disposal, and terminal inputs select bounded deterministic outcomes. The sticky
application-write fact never clears during replay.

## Cost Evidence

BenchmarkDotNet 0.15.8 ran on .NET 10.0.10 using the permanent
`QuicAdaptiveRuntimePolicyBenchmarks` suite.

| Case | Short mean | Managed allocation |
| --- | ---: | ---: |
| Frozen legacy receive-credit decision | 1.090 ns | none reported |
| Bounded connection observation | 4.609 ns | none reported |
| Standalone shadow evaluation | 21.025 ns | none reported |
| Combined observation and shadow evaluation | 18.759 ns | none reported |

The Short job uses three measured iterations. Its confidence interval is wide
for the combined case, so these values establish order of magnitude and
allocation behavior only. They are not a tuning result or performance claim.

- Dry report SHA-256:
  `6f9a5d8a0414bb8e18cf6b182bf4f7627a8cdaa3392bfe2f6b47831750afb682`
- Short report SHA-256:
  `5ba172071f6f034ca524f510fffcffd962df01626193c0142aa006d57564cf74`

## Full Release Suite Classification

The first complete Release run retained 9,745 passed, 4 skipped, and 2 failed
of 9,751 tests. One failure was owned: `REQ-QUIC-CRT-0168` used private
reflection outside the repository quarantine. The proof was removed and the
private-reflection guard passed in isolation. The other failure was the
unmodified
`Http3MinimalServerTests.PostDataRequest_WithIncompleteContentLength_ClosesConnectionWithMessageError`
connection-close timeout; it passed immediately in isolation.

The clean-checkpoint complete rerun retained 9,744 passed, 4 skipped, and 2
failed of 9,750 tests. The same unmodified HTTP/3 test timed out, and
`DoqStreamLifecycleTests.DanglingStreamLimitClosesConnectionWithExcessiveLoad`
observed a connection termination. Both unmodified cases pass in isolation:

- HTTP/3 isolated rerun: 1 passed, 0 failed, 0 skipped.
- DoQ isolated rerun: 1 passed, 0 failed, 0 skipped.

The original failing runs remain the authoritative suite-context evidence; the
isolated reruns classify rather than erase them.

### Follow-up suite audit after end-to-end epoch export

After checkpoints `5fbed292`, `228023be`, `5ed514ca`, and `20a139ee`, the two
previously retained sensitivities again passed in isolation, one test each.
The complete Release suite then retained 9,752 passed, 4 skipped, and 1 failed
of 9,757 tests. Neither prior sensitivity recurred. Instead, the unmodified
`Http3MinimalServerTests.RequestInvalidQPackStaticIndex_ClosesConnectionWithDecompressionFailed`
timed out waiting for the peer HTTP/3 connection close. Its immediate isolated
rerun passed 1/1. This is a new member of the same suite-load close-wait
sensitivity class; it is not erased by the isolated pass and it prevents a
clean full-suite gate.

| Follow-up artifact | SHA-256 |
| --- | --- |
| Full-suite TRX | `a21ce9cce2872dee3f9e5ff8ac98ca38c4dc4afbac2384b2a91de83ffcd8580d` |
| Full-suite log | `bb7c5851bb836c5af29b3be9de1bc73ccbe3583cf0ee0516b3e2c8f436a67c73` |
| Prior HTTP/3 sensitivity isolated TRX | `d26d10d9e63b72441bee5d37549ca4cbfc8d30d9746a10cfdf4fbd8a707d6c36` |
| Prior DoQ sensitivity isolated TRX | `f2f5a60cb61a53dd63ff1a45a62b65fdea8fd8ba95aa5a78dcccaf5449e6e974` |
| New HTTP/3 sensitivity isolated TRX | `2dac07b726571f7f14acf61869a08ed154c28126b3325c5523af42c4104d15ae` |

| Artifact | SHA-256 |
| --- | --- |
| First full-suite TRX | `875a2348bd3b39ece42759c3a6b1b0ff0c7c412e103d42d7e725f882490694be` |
| Clean-checkpoint full-suite TRX | `b9637f49237496916444312ac809de7b9918bce031aa1b3caf5b7733a8b4ce38` |
| HTTP/3 isolated TRX | `4fff264ff4487e3334d14f0559e09e3ecf2274ba2741245b1a608238e7a1da3d` |
| DoQ isolated TRX | `7799579d2ad041dea4e782166f80d8968692a340eb3467de032eb3867430cf86` |
| First full-suite log | `403aa85640c1b1b021ab264efea7dc0b66336ad3322e52c63e1ec8a0601b8354` |
| Clean-checkpoint full-suite log | `60a2680f5d94b9d2651f560137cd4e3462c2e756586eec901b1872deae6bdd2e` |

The local artifact paths are under `.artifacts/adaptive-runtime-*`. They are
not checked into Git; the hashes above make the retained files independently
identifiable on this machine.

## Retained Negative Evidence

The universal batching, half-window duplex-reactivating, quarter-window
duplex-reactivating, non-sticky duplex fallback, and lock-based selector
variants remain negative experiments as recorded in
[`../adaptive-runtime-policy-planning.md`](../adaptive-runtime-policy-planning.md).
Nothing in this implementation incorporates or discards them. The frozen
shadow rule reproduces only the accepted selector at `1b2611e1`.

## Promotion Status And Remaining Gates

This evidence is non-promoting. Before any active-policy review:

1. complete the remaining sparse, target, neighboring, and retained-negative
   local matrix with materially improved host isolation;
2. resolve or explicitly accept the repeated suite-context HTTP/3 close-wait
   sensitivity under repository release policy;
3. review the local counterfactual and shadow evidence; and
4. only then consider ProtocolLab submission as a later eligibility gate.

The ProtocolLab controller at `http://10.10.99.176:5088` was reachable by
read-only root and package-list probes on 2026-07-21. No job, upload, package
mutation, or controller state change was performed during this verification.

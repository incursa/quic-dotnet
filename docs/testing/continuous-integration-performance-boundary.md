# Continuous-Integration and Performance Boundary

## Purpose

Pull-request and push CI protects correctness. It does not run BenchmarkDotNet,
local throughput or latency campaigns, ProtocolLab campaigns, or any comparison
that treats a shared hosted runner as performance evidence.

The required workflow boundary is:

| Lane | Trigger | Permitted work | Evidence status |
| --- | --- | --- | --- |
| `CI` | pull request and push | build, deterministic correctness tests, trace validation, package construction and package smoke | correctness and packaging only |
| `Nightly Performance Diagnostics` | scheduled or manually dispatched | bounded BenchmarkDotNet baseline execution and retained raw reports | diagnostic only |
| ProtocolLab | reviewed, operator-controlled campaign | forced-policy/shadow counterfactuals and independent-host measurements | evaluated only under the adaptive-runtime campaign contracts |

## Test classification

Tests that measure or compare throughput, latency, allocation rates, timing,
resource consumption, or benchmark scores MUST declare the xUnit trait
`[Trait("Category", "Performance")]`. The CI test command excludes that trait
with `Category!=Performance`.

Deterministic conformance remains in CI even when it transfers a substantial
payload or exercises concurrent streams. For example, exact payload, EOF,
flow-control progress, cancellation, reset, recovery, and shutdown checks are
correctness tests; they do not become performance tests merely because they
exercise a non-trivial workload.

## Nightly diagnostic limits

The nightly workflow retains BenchmarkDotNet artifacts for regression triage,
but its hosted runner is not a stable performance cohort. It MUST NOT provide a
policy acceptance result, set a production threshold, rank implementations, or
replace local or independent-host ProtocolLab evidence. A failed nightly run is
retained diagnostic evidence and must be investigated without relabeling it as
an accepted performance result.

ProtocolLab policy evidence remains subject to the version, provenance,
classification, counterfactual, and host-fingerprint rules in the adaptive
runtime campaign contracts.

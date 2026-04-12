# Quality Scripts

## Scripts

- [`run-smoke-tests.ps1`](run-smoke-tests.ps1) runs the fast `Category=Smoke` lane against `Incursa.Quic.slnx`.
- [`run-blocking-tests.ps1`](run-blocking-tests.ps1) runs the `Category=Blocking` lane against `Incursa.Quic.slnx`.
- [`run-quality-evidence.ps1`](run-quality-evidence.ps1) runs the full repository test-project suite and records the evidence expected by `quality/attestation.yaml`.
- [`run-benchmark-evidence.ps1`](run-benchmark-evidence.ps1) runs the header benchmark dry lane and writes benchmark evidence under `quality/benchmarks/`.
- [`run-aot-publish.ps1`](run-aot-publish.ps1) packs the QUIC library, creates a downstream `PackageReference` consumer, and publishes it under Native AOT in regular or fallback toolchain mode.
- [`QualityLane.Common.ps1`](QualityLane.Common.ps1) hosts the shared helpers used by the quality scripts.

## Attestation

- The root-level [`run-quality-attestation.ps1`](../../run-quality-attestation.ps1) wrapper refreshes evidence, syncs the quality contract, and emits the derived HTML and JSON attestation artifacts.

## Supporting commands

- [`cleanup.ps1`](../../cleanup.ps1) configures git hooks and runs the manual pre-commit lanes.
- [`cleanup.sh`](../../cleanup.sh) does the same from a POSIX shell.
- [`scripts/setup-git-hooks.ps1`](../setup-git-hooks.ps1) sets `core.hooksPath` to `.githooks`.

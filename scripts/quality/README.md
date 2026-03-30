# Quality Scripts

## Scripts

- [`run-smoke-tests.ps1`](run-smoke-tests.ps1) runs the fast `Category=Smoke` lane against `Incursa.Quic.slnx`.
- [`run-blocking-tests.ps1`](run-blocking-tests.ps1) runs the `Category=Blocking` lane against `Incursa.Quic.slnx`.
- [`run-quality-evidence.ps1`](run-quality-evidence.ps1) runs both lanes in the order expected by `quality/attestation.yaml`.
- [`QualityLane.Common.ps1`](QualityLane.Common.ps1) hosts the shared helpers used by the quality scripts.

## Supporting commands

- [`cleanup.ps1`](../../cleanup.ps1) configures git hooks and runs the manual pre-commit lanes.
- [`cleanup.sh`](../../cleanup.sh) does the same from a POSIX shell.
- [`scripts/setup-git-hooks.ps1`](../setup-git-hooks.ps1) sets `core.hooksPath` to `.githooks`.

# Scripts

This directory holds repository automation entry points.

## Areas

- [`spec-trace/`](spec-trace/README.md): JSON validation, migration, backup, and parity-check helpers
- [`quality/`](quality/README.md): smoke, blocking, and quality-report lanes
- [`interop/`](interop/README.md): local-only helper entry points for exercising the QUIC interop harness against a local runner checkout
- [`Start-QuicCoverageLanes.ps1`](Start-QuicCoverageLanes.ps1): creates QUIC coverage worktrees and launches parallel Codex lanes
- [`release/`](release/README.md): versioning and release-policy checks
- [`compliance/`](compliance/update-notice.ps1): dependency notice updates
- [`setup-git-hooks.ps1`](setup-git-hooks.ps1): git hook configuration

# Scripts

This directory holds the repository's supported automation entry points.

## Areas

- [`spec-trace/`](spec-trace/README.md): JSON validation, migration, backup, and parity-check helpers.
- [`quality/`](quality/README.md): smoke, blocking, and quality-report lanes.
- [`interop/`](interop/README.md): local helper entry points for exercising the QUIC interop harness against a local runner checkout.
- [`release/`](release/README.md): versioning and release-policy checks.
- [`Get-QuicAutopilotStateSummary.ps1`](Get-QuicAutopilotStateSummary.ps1): read-only summary of local autopilot state roots with mergeable paused work highlighted. Example: `pwsh -File scripts/Get-QuicAutopilotStateSummary.ps1 -StateRoot @('C:\src\incursa\quic-dotnet.local\sender-recovery-next\state','C:\src\incursa\quic-dotnet.local\leaf-packets\state')`
- [`compliance/`](compliance/update-notice.ps1): dependency notice updates.
- [`setup-git-hooks.ps1`](setup-git-hooks.ps1): Git hook configuration.

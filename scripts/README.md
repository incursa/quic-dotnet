# Scripts

This directory holds the repository's supported automation entry points.

## Areas

- [`spec-trace/`](spec-trace/README.md): JSON validation, migration, backup, and parity-check helpers.
- [`quality/`](quality/README.md): smoke, blocking, and quality-report lanes.
- [`interop/`](interop/README.md): local helper entry points for exercising the QUIC interop harness against a local runner checkout.
- [`release/`](release/README.md): versioning and release-policy checks.
- [`parallel-codex/`](parallel-codex/quic-parallel-lanes.json): manifest and lane prompts for launching multiple Codex workers in isolated git worktrees.
- [`compliance/`](compliance/update-notice.ps1): dependency notice updates.
- [`perf/`](perf/README.md): local performance helpers, including the ProtocolLab source-reference benchmark loop and optional R2 upload path.
- [`setup-git-hooks.ps1`](setup-git-hooks.ps1): Git hook configuration.

## Parallel Codex lanes

Start the default non-overlapping lane set from a clean `main`:

```powershell
pwsh -NoProfile -File scripts/Start-QuicParallelCodex.ps1
```

The launcher creates worktrees under `C:/src/incursa/quic-dotnet.worktrees`, branches under `codex/`, lane prompts under `.artifacts/codex-parallel-launches/<timestamp>/`, and starts one background Codex autopilot process per selected lane.

By default the launcher uses `gpt-5.4-mini` with `xhigh` reasoning so the common path stays cost-aware while still giving each lane enough thinking depth. Override with `-Model` and `-ReasoningEffort` only for lanes that are genuinely blocked.

Check progress:

```powershell
pwsh -NoProfile -File scripts/Show-QuicParallelCodexStatus.ps1
```

Dry-run the merge readiness gate:

```powershell
pwsh -NoProfile -File scripts/Merge-QuicParallelCodex.ps1 -DryRun
```

Merge ready lane branches back into the current `main` worktree:

```powershell
pwsh -NoProfile -File scripts/Merge-QuicParallelCodex.ps1
```

Use `-LaneIds <id>` to launch or merge specific lanes. The default set includes one runtime lane (`streams-runtime`) and several non-runtime lanes; `path-runtime`, `tls-zero-rtt-runtime`, and `runtime-decomposition` are opt-in because they are runtime-exclusive and more likely to conflict.

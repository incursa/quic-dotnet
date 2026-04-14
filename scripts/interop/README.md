# Interop Helpers

This folder holds local-only helpers for exercising the QUIC interop harness against a local checkout of [`quic-interop-runner`](https://github.com/quic-interop/quic-interop-runner).

## `Invoke-QuicInteropRunner.ps1`

This wrapper:

1. Builds the local `Incursa.Quic.InteropHarness` Docker image.
2. Invokes the external `quic-interop-runner` from a local checkout.
3. Uses the runner's `--replace` path to swap one existing both-role slot with the locally built harness image.
4. Captures the runner JSON, Markdown, stderr, build log, and runner log directory under a repo-local artifact tree.

Default behavior:

- Runner checkout: `C:\src\quic-interop\quic-interop-runner`
- Replacement slot: `quic-go`
- Testcases: `handshake,retry,transfer`
- Artifact root: `artifacts/interop-runner/<timestamp>-<slot>/`

Example:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```

Override the replacement slot or runner checkout when needed:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1 `
  -ImplementationSlot ngtcp2 `
  -RunnerRoot C:\src\quic-interop\quic-interop-runner
```

The helper only accepts both-role slots from the runner's `implementations_quic.json`, because it runs the same implementation slot as both client and server.
The helper stays on runner-supported QUIC testcases so it can produce the runner's JSON and Markdown execution reports without needing any registry changes in the runner repo.

## Artifact Layout

Each run creates a timestamped directory containing:

- `docker-build.log`
- `invocation.txt`
- `runner-report.json`
- `runner-report.md`
- `runner.stderr.log`
- `runner-logs/`
- `artifact-tree.txt`

The runner itself writes its testcase-specific log tree into `runner-logs/` using the runner's own `--log-dir` path.

## Troubleshooting

- If the runner aborts with `Unable to create certificates`, check `runner.stderr.log` first. That comes from the upstream runner's shell-based certificate bootstrap, not from the helper itself.
- The helper still keeps the build log, runner stdout/Markdown, stderr, invocation summary, and the partial log tree so you can inspect the failure without rerunning with extra flags.

# Interop Helpers

This folder holds local-only helpers for exercising the QUIC interop harness against a local checkout of [`quic-interop-runner`](https://github.com/quic-interop/quic-interop-runner).

## `Invoke-QuicInteropRunner.ps1`

This wrapper:

1. Builds the local `Incursa.Quic.InteropHarness` Docker image.
2. Invokes the external `quic-interop-runner` from a local checkout.
3. Uses the runner's `--replace` path to swap the local-side implementation slot with the locally built harness image.
4. Captures the runner JSON, Markdown, stderr, build log, and runner log directory under a repo-local artifact tree.

Default behavior:

- Runner checkout: local `quic-interop-runner` clone configured in the script or passed with `-RunnerRoot`
- Replacement slot: `quic-go`
- Testcases: `handshake,retry,transfer`
- The helper also accepts `multiconnect` when you want the sequential managed transfer path.
- The helper translates local `multiconnect` into the runner's CLI testcase name `handshakeloss`, because the upstream runner uses `multiconnect` only for the container-facing `TESTCASE_*` values.
- The smaller `post-handshake-stream` proof remains available through the local harness requirement-home lane; this helper does not expose that testcase yet.
- Artifact root: `artifacts/interop-runner/<timestamp>-<slot>/`

Example:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```

Override the replacement slot or runner checkout when needed:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1 `
  -LocalRole client `
  -RunnerRoot <path-to-quic-interop-runner>
```

The helper defaults to a mode-appropriate local slot so the same checkout can run in either `both`, `client`, or `server` mode without accidentally replacing the peer slot:

- `both` mode defaults to the runner's `quic-go` slot and uses that same slot on both sides.
- `client` mode defaults to the runner's `chrome` slot and runs the local image against peer server slots such as `quic-go` and `msquic`.
- `server` mode defaults to the runner's `nginx` slot and runs the local image against peer client slots such as `quic-go` and `msquic`.

Use `-ImplementationSlot` to override the local-side slot and `-PeerImplementationSlots` to choose the established peer slots.
The helper stays on runner-supported QUIC testcases so it can produce the runner's JSON and Markdown execution reports without needing any registry changes in the runner repo.

Hosted corroboration:

- `.github/workflows/interop-runner-handshake.yml` exposes a manual `workflow_dispatch` lane for the narrow server-role `handshake` cell.
- The workflow checks out this repository and `quic-interop-runner` separately, then runs this helper with `-LocalRole server -PeerImplementationSlots quic-go -TestCases handshake`.
- The workflow pins Python 3.12 for the external runner dependencies instead of floating to the newest hosted-toolcache Python.
- The workflow installs the latest stable Docker Engine through `docker/setup-docker-action@v5` before the helper runs because the upstream runner compose file uses `interface_name`, which requires Docker Engine 28.1 or later.
- The workflow installs `tshark` and `editcap` through Ubuntu packages so the runner can perform its packet trace post-check.
- It uploads `artifacts/interop-runner/` with `if: always()` so success, advisory, and failure outcomes all preserve the runner bundle for audit.
- The hosted lane is advisory. It is not part of ordinary push, pull-request, build, test, package, or support-readiness gates.
- The helper marks only the explicitly selected runner slots as compliant for the runner's registry compliance preflight so the advisory lane reaches the requested testcase rather than skipping on an unrelated unsupported-testcase precheck.

Plan-only mode:

- `-DryRun` is aliased as `-PlanOnly`.
- It resolves the effective repo root, runner root, slot selection, testcase list, artifact paths, and runner arguments.
- It prints the plan and exits `0` without building the image or launching the runner.
- It does not require Docker or a live `quic-interop-runner` checkout.
- Real runs stage a pruned Docker build context with PowerShell/.NET file-copy APIs rather than Windows-only tools, so the same helper path can run on Windows workstations and hosted Ubuntu runners.

Example:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1 -DryRun
```

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
When `QLOGDIR` is enabled by the runner, the harness writes contained qlog JSON files into that same log tree so you can inspect the transport trace alongside the runner's own logs.

## Troubleshooting

- If the runner aborts with `Unable to create certificates`, check `runner.stderr.log` first. That comes from the upstream runner's shell-based certificate bootstrap, not from the helper itself.
- The helper still keeps the build log, runner stdout/Markdown, stderr, invocation summary, and the partial log tree so you can inspect the failure without rerunning with extra flags.
- On the narrow advisory-only `FileNotFoundError` path, the helper itself exits `0` and prints an `Advisory:` line, but it intentionally preserves the upstream runner's own inner exit code plus the failed `runner-report.json` and `runner-report.md` bundle for audit. Treat the helper exit code and advisory text as the local classification result, and treat the preserved runner report as evidence of the external post-check failure rather than a managed transport regression.

## `Invoke-QuicInteropAutopilot.ps1`

This orchestrator manages the trace-first lane loop for the local QUIC repo checkout. It can:

1. Plan the next eligible lane from the current requirement/gap state.
2. Prepare a disposable worker worktree for the selected lane.
3. Run or resume the active worker lane.
4. Merge verified commits back to `main`.
5. Clean up the active worktree after merge.
6. Supervise the loop so it can continue through the next eligible lane without manual restarts.

Use `-Mode supervise` when you want a bounded watch loop. It now:

- resumes any recorded active lane first
- merges and cleans up finished lanes through the existing `resume`/`merge`/`cleanup` guardrails
- sleeps and re-plans when the queue is empty instead of exiting on the first empty poll
- prints the current active lane, pending reconciliation lanes, and completed lane count before each supervise decision
- stops only when work resumes, an idle limit is exceeded, an overall cycle limit is reached, or a real guardrail/error trips

The default supervise settings are conservative (`300` second poll interval, `12` empty polls allowed). Use `-Overnight` to apply a longer unattended preset without removing the safety limits:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-QuicInteropAutopilot.ps1 -Mode supervise -Overnight
```

Tune the watch behavior when needed:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-QuicInteropAutopilot.ps1 `
  -Mode supervise `
  -SupervisorPollIntervalSeconds 120 `
  -SupervisorMaxIdleCycles 30 `
  -SupervisorMaxIdleMinutes 180 `
  -SupervisorMaxCycles 80
```

Use `-Mode run` for a single bounded lane cycle, `-Mode resume` to continue or reconcile the current active lane, and `-Mode plan` to inspect the next eligible lane without starting Codex. `-Mode smoke` performs a local supervisor decision-logic check, then prints a compact result summary covering the active-lane, pending-reconciliation, empty-queue, idle-stop, and backlog-synthesis cases without starting a worker lane.

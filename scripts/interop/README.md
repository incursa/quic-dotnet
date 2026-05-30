# Interop Helpers

This folder holds local-only helpers for exercising the QUIC interop harness against a local checkout of [`quic-interop-runner`](https://github.com/quic-interop/quic-interop-runner).

## `Invoke-QuicNetworkSimulatorScenario.ps1`

This wrapper is the first manual evidence helper for the simulator-backed correctness model in `REQ-QUIC-INT-0026`.
It is intentionally narrower than the interop-runner wrapper:

- Supported scenario ids: `SIM-QUIC-BASE-0001` and `SIM-QUIC-LOSS-0001`.
- Baseline profile: `simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25`.
- Deterministic-loss profile: `droplist --delay=15ms --bandwidth=10Mbps --queue=25 --drops_to_client=<ip-packet-indexes> --drops_to_server=<ip-packet-indexes>`.
- Droplist indexes are upstream bottleneck-link IP packet indexes, not QUIC packet numbers.
- Execution model: upstream `docker compose up --build --force-recreate` with `CLIENT`, `SERVER`, `CLIENT_PARAMS`, `SERVER_PARAMS`, and `SCENARIO`.
- Artifact root: `artifacts/network-simulator/<scenario-id>/<run-id>/`.
- Evidence bundle: `scenario-summary.json`, `invocation.txt`, `simulator.stdout.log`, `simulator.stderr.log`, and `artifact-tree.txt`.
- Promotion status stays `not-promoted` until linked verification records requirement-specific runtime evidence for the expected observable behavior.

Plan-only mode does not require a simulator checkout:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1 -DryRun
```

Preserve the baseline compose plan against a local [`quic-network-simulator`](https://github.com/quic-interop/quic-network-simulator) checkout without launching Docker:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1 `
  -SimulatorRoot <path-to-quic-network-simulator>
```

Preserve the deterministic droplist compose plan with explicit upstream packet indexes:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1 `
  -ScenarioId SIM-QUIC-LOSS-0001 `
  -SimulatorRoot <path-to-quic-network-simulator> `
  -DropsToClient 4,8 `
  -DropsToServer 6
```

Launch Docker with helper-staged Incursa.Quic endpoints:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1 `
  -SimulatorRoot <path-to-quic-network-simulator> `
  -Execute
```

Or launch Docker with explicit simulator endpoint directories for both sides:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1 `
  -SimulatorRoot <path-to-quic-network-simulator> `
  -Client <client-endpoint-directory> `
  -Server <server-endpoint-directory> `
  -Execute
```

The helper preserves invocation evidence by default and requires `-Execute` before running Docker. When explicit endpoint directories are omitted, it stages Incursa.Quic client/server Docker contexts, a compose override, `/www`, `/downloads`, and `/certs` under the run artifact root. Execute mode also preserves the current-run simulator qlog/pcap tree under `simulator-logs/`, but it still does not add runtime transport behavior, hosted workflow dispatch, qlog/pcap analysis, or broad simulator-matrix promotion.

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
- The helper also recognizes the documented upstream inventory, classifies each cell explicitly, and writes `testcase-inventory.json` beside the runner outputs so blocked cells stay visible instead of collapsing into a generic unsupported bucket.
- The smaller `post-handshake-stream` proof remains available through the local harness requirement-home lane; this helper does not expose that testcase.
- Artifact root: `artifacts/interop-runner/<timestamp>-<slot>/`
- Non-`DryRun` execution now preflights Docker, Python, `tshark`, and `editcap` before the image build starts, because the upstream runner needs packet-analysis tools for its post-checks.

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

Use `-ImplementationSlot` to override the local-side slot and `-PeerImplementationSlots` to choose the established peer slots. In split-role mode, `-PeerImplementationSlots all` expands from the runner's `implementations_quic.json`: local client mode selects every server-capable peer, and local server mode selects every client-capable peer.
The helper stays on runner-supported QUIC testcases so it can produce the runner's JSON and Markdown execution reports without needing any registry changes in the runner repo.
The current supported/executed cells are `handshake`, `transfer`, `http3`, `longrtt`, `multiplexing`, `retry`, `multiconnect`, `versionnegotiation`, `chacha20`, `keyupdate`, `resumption`, `zerortt`, `amplificationlimit`, `blackhole`, `transferloss`, `ipv6`, `v2`, and `connectionmigration`; the remaining documented cells are surfaced as explicit inventory entries that are still red or blocked. `http3` uses ALPN `h3`, serves GET responses from `/www`, and stores client downloads in `/downloads` through the minimal HTTP/3/QPACK layer. `versionnegotiation` is now backed by explicit reserved-version dispatch in the harness. `longrtt`, `multiplexing`, `amplificationlimit`, `blackhole`, `transferloss`, and `ipv6` are transfer-backed runner cells that reuse the existing HTTP/0.9 transfer path until live proof says otherwise. `chacha20` is now supported/executed after a local quic-go/quic-go runner run completed successfully, and the harness routes it through the runnable transfer-backed dispatch path. `zerortt` is now supported/executed after the hosted Linux `zerortt-server-proof` run completed successfully with buffered request-line reads and packet-analysis proof; `resumption` is green only for the runner's TLS session-resumption cell with managed SSLKEYLOGFILE export proof. These cells do not imply anti-replay, port or address rebinding, corruption-test, ECN, or broader API support.

Run the local Incursa image against itself for the QUIC interop runner HTTP/3 testcase:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1 `
  -RunnerRoot C:\src\quic-interop\quic-interop-runner `
  -LocalRole both `
  -ImplementationSlot quic-go `
  -PeerImplementationSlots quic-go `
  -TestCases http3 `
  -RunnerTimeoutSeconds 240 `
  -ArtifactsRoot .artifacts\interop-runner\http3-local
```

Hosted corroboration:

- `.github/workflows/interop-runner-handshake.yml` exposes manual `workflow_dispatch` advisory profiles.
- The default `hosted-handshake` profile runs only the narrow server-role `handshake` cell against `quic-go`.
- The explicit `supported-subset` profile runs the hosted handshake job and fans out the additional helper-supported cells: same-slot `retry`, split-role `transfer`, and client-role `multiconnect` mapped to the runner's `handshakeloss` testcase.
- The explicit `major-peer-matrix` profile runs Incursa.Quic as the local client and as the local server against `quic-go` and `msquic` for the currently executable major non-HTTP/3 cells: `handshake`, `retry`, `transfer`, `keyupdate`, and `resumption`. Each role/peer/testcase cell gets its own artifact bundle. This profile is still advisory evidence collection; it feeds the generated `interop-major-peer-matrix-inventory` and `interop-major-peer-matrix-evidence-25904716076` reports, excludes `http3`, `zerortt`, `versionnegotiation`, `v2`, `rebind-port`, `rebind-addr`, and `connectionmigration`, and stays conservative because those cells do not have fresh live runner evidence. `chacha20` is green in the inventory but has not been expanded into this peer-matrix coverage slice.
- The explicit `all-implementation-matrix` profile reads the upstream runner's `implementations_quic.json` at dispatch time and runs handshake-only role-compatible cells: Incursa.Quic as local client against every server-capable upstream slot, and Incursa.Quic as local server against every client-capable upstream slot. This profile is advisory evidence collection and does not add Incursa.Quic to the upstream registry, run every testcase, or claim broad support readiness.
- Client-role cells use the known source-length completion boundary when the requested response body is mounted locally and otherwise read until the peer sends FIN. This keeps the quic-go download-liveness guard while allowing upstream-runner generated files that exist only in the peer server container.
- The explicit `zerortt-server-proof` profile runs only the server-role `zerortt` attempt against a `quic-go` client on hosted Linux so the runner can get past the Windows long-filename setup blocker. This is advisory proof collection for the now supported/executed `zerortt` inventory cell; hosted run `25777328991` completed successfully with `0-RTT size: 10570` and `1-RTT size: 2379`, and the server helper now reads HTTP/0.9 request lines in buffered chunks rather than one byte at a time, which reduces the receive-credit and ACK chatter inside the proof path.
- The explicit `connectionmigration-server-proof` profile runs the server-role `connectionmigration` attempt by replacing the distinct local `nginx` slot while reporting `neqo-peer` as the peer alias, normalizing the actual runner client slot to `neqo`, and using the `ghcr.io/mozilla/neqo-qns:latest` peer image so live corroboration can be refreshed without widening the generated `interop-major-peer-matrix-inventory` / `interop-major-peer-matrix-evidence-25904716076` reports. It remains advisory proof collection for the `REQ-QUIC-INT-0022` lane and does not imply `rebind-port` or `rebind-addr` support.
- The companion `connectionmigration-server-proof-blocked` profile keeps `ngtcp2`, `lsquic`, `quiche`, `quic-go`, `msquic`, and `aioquic` visible as a blocked comparison lane. It remains advisory evidence collection and does not imply `rebind-port` or `rebind-addr` support.
- The smaller `post-handshake-stream` proof remains local-harness coverage only; there is no hosted external-runner profile for it.
- The workflow checks out this repository and `quic-interop-runner` separately, then runs this helper once per selected matrix cell.
- The workflow pins Python 3.12 for the external runner dependencies instead of floating to the newest hosted-toolcache Python.
- The workflow uses Node 24-compatible action majors for Python setup and artifact upload; Docker setup remains on v5, whose v5 release also defaults to Node 24.
- The workflow installs the latest stable Docker Engine through `docker/setup-docker-action@v5` before the helper runs because the upstream runner compose file uses `interface_name`, which requires Docker Engine 28.1 or later.
- The workflow installs `tshark` and `editcap` through Ubuntu packages so the runner can perform its packet trace post-check.
- It pre-pulls the simulator and quic-go peer images before each timed runner cell so first-use Docker image downloads do not consume the runner testcase timeout.
- The major peer matrix pre-pulls the selected peer image for each cell in the advisory inventory/evidence reports, including `ghcr.io/microsoft/msquic/qns:main` for `msquic`.
- Hosted transfer cells pass a narrow runner timeout override because GitHub-hosted Docker startup is slower than the local cached-image path; local helper runs keep the upstream runner's default timeout unless `-RunnerTimeoutSeconds` is supplied.
- It uploads a distinct per-cell `artifacts/interop-runner/<cell>/` bundle with `if: always()` so success, advisory, and failure outcomes all preserve the runner bundle for audit.
- The hosted lane is advisory. It is not part of ordinary push, pull-request, build, test, package, or support-readiness gates. The generated `interop-major-peer-matrix-inventory` report keeps the current cell set explicit, and the generated `interop-major-peer-matrix-evidence-25904716076` report preserves the completed hosted evidence.
- The helper marks only the explicitly selected runner slots as compliant for the runner's registry compliance preflight so the advisory lane reaches the requested testcase rather than skipping on an unrelated unsupported-testcase precheck.
- If the runner reaches managed success and then fails only its trace-analysis post-check with `FileNotFoundError`, the helper's advisory downgrade remains testcase-specific: `keyupdate` requires preserved key-update initiation plus managed download or response markers, and `resumption` requires preserved ticket/resumed-connection or first/resumed server-connection markers. Ambiguous, unsupported, blocked, or incomplete cells still fail.

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

Dispatch the major peer matrix after the branch containing the workflow change is on GitHub to refresh the generated `interop-major-peer-matrix-inventory` and `interop-major-peer-matrix-evidence-25904716076` reports:

```powershell
gh workflow run interop-runner-handshake.yml --repo incursa/quic-dotnet --ref main -f coverage_profile=major-peer-matrix
```

Plan the all-upstream handshake peer sets locally:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole client -ImplementationSlot chrome -PeerImplementationSlots all -TestCases handshake
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole server -ImplementationSlot nginx -PeerImplementationSlots all -TestCases handshake
```

Dispatch the all-upstream handshake matrix after the branch containing the workflow change is on GitHub:

```powershell
gh workflow run interop-runner-handshake.yml --repo incursa/quic-dotnet --ref main -f coverage_profile=all-implementation-matrix
```

## Artifact Layout

Each run creates a timestamped directory containing:

- `docker-build.log`
- `invocation.txt`
- `runner-report.json`
- `runner-report.md`
- `runner.stderr.log`
- `testcase-inventory.json`
- `runner-logs/`
- `artifact-tree.txt`

The runner itself writes its testcase-specific log tree into `runner-logs/` using the runner's own `--log-dir` path.
When `QLOGDIR` is enabled by the runner, the harness writes contained qlog JSON files into that same log tree so you can inspect the transport trace alongside the runner's own logs.

## Troubleshooting

- If the runner aborts with `Unable to create certificates`, check `runner.stderr.log` first. That comes from the upstream runner's shell-based certificate bootstrap, not from the helper itself.
- The helper still keeps the build log, runner stdout/Markdown, stderr, invocation summary, and the partial log tree so you can inspect the failure without rerunning with extra flags.
- On the narrow advisory-only `FileNotFoundError` path, the helper itself exits `0` and prints an `Advisory:` line, but it intentionally preserves the upstream runner's own inner exit code plus the failed `runner-report.json` and `runner-report.md` bundle for audit. Treat the helper exit code and advisory text as the local classification result, and treat the preserved runner report as evidence of the external post-check failure rather than a managed transport regression.
- If a real local run fails preflight because `tshark` or `editcap` is missing, install Wireshark or add its tools directory to `PATH`, then rerun. On Windows, the helper also recognizes the standard per-user Wireshark install under `%LOCALAPPDATA%\Programs\Wireshark`. A `DryRun` plan does not require these tools.

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

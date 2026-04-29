# Next Codex Prompt: Runtime Control-Packet Protection Stabilization

Copy this prompt into a fresh Codex thread when you want to start the next
bounded runtime repair.

````text
You are Codex working in C:\src\incursa\quic-dotnet.

Follow AGENTS.md and the repo's trace-first order. This is a single-lane runtime stabilization task; skip delegation unless local evidence proves the work must split.

Goal:
Repair the active-path Application Data control-packet protection regression that currently breaks transfer and multiconnect paths with errors like:

- "The connection runtime could not protect the MAX_DATA packet."
- "The connection runtime could not protect the MAX_STREAM_DATA packet."
- "The connection runtime could not protect the stream capacity release packet."

Current verified baseline from 2026-04-27:
- `git status --short --branch`: clean `main`, tracking `origin/main`.
- `dotnet build Incursa.Quic.slnx -c Release`: passed with 0 warnings and 0 errors.
- `dotnet test Incursa.Quic.slnx -c Release --no-build -m:1`: failed, 3,233 passed / 38 failed / 0 skipped / 3,271 total.
- Repo-wide SpecTrace validation is already noisy. Do not spend this slice on global validation cleanup unless your changes make it worse.

Required source map before editing:
1. Read `docs/requirements-workflow.md`.
2. Read the relevant entries in `specs/requirements/quic/REQUIREMENT-GAPS.md`.
3. Inspect these canonical requirement/design/proof owners before changing code:
   - `specs/requirements/quic/SPEC-QUIC-INT.json`
   - `specs/requirements/quic/SPEC-QUIC-RFC9000.json`
   - `specs/architecture/quic/ARC-QUIC-INT-0003.json`
   - `specs/architecture/quic/ARC-QUIC-INT-0007.json`
   - `specs/architecture/quic/ARC-QUIC-INT-0008.json`
   - `specs/architecture/quic/ARC-QUIC-RFC9000-0009.json`
   - `specs/work-items/quic/WI-QUIC-INT-0003.json`
   - `specs/work-items/quic/WI-QUIC-INT-0007.json`
   - `specs/work-items/quic/WI-QUIC-INT-0008.json`
   - `specs/work-items/quic/WI-QUIC-RFC9000-0009.json`
   - `specs/verification/quic/VER-QUIC-INT-0003.json`
   - `specs/verification/quic/VER-QUIC-INT-0007.json`
   - `specs/verification/quic/VER-QUIC-INT-0008.json`
   - `specs/verification/quic/VER-QUIC-RFC9000-0009.json`

Initial repro command:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_INT_0010|FullyQualifiedName~REQ_QUIC_INT_0014|FullyQualifiedName~REQ_QUIC_INT_0015|FullyQualifiedName~REQ_QUIC_INT_0008"
```

Likely implementation files:
- `src/Incursa.Quic/QuicConnectionRuntime.Streams.cs`
- `src/Incursa.Quic/QuicConnectionRuntime.cs`
- `src/Incursa.Quic/QuicConnectionSendRuntime.cs`
- nearby packet-protection, sender/recovery, and flow-control helpers found through tight `rg` queries for `MAX_DATA`, `MAX_STREAM_DATA`, `stream capacity release`, `TryProtectAndAccountApplicationPayload`, and the exact failure messages.

Likely proof files:
- `tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0008.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0010.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0014.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0015.cs`
- targeted RFC9000 requirement homes around MAX_DATA / MAX_STREAM_DATA only if the root cause lands there.

Scope:
- Fix the smallest runtime cause that prevents Application Data control packets from being protected on the active transfer/multiconnect path.
- Keep support claims narrow.
- Preserve public API shape.
- Preserve `IsSupported` semantics.
- Do not broaden 0-RTT, key-update, retry, or interop promises.
- Do not perform repo-wide SpecTrace cleanup in this slice.

Expected workflow:
1. Reproduce the focused INT failure set.
2. Inspect only the source map and likely files above unless a concrete missing file blocks the investigation.
3. Implement the smallest runtime fix.
4. Add or adjust focused requirement-home proof only if needed to make the behavior explicit.
5. If canonical JSON trace artifacts need status/evidence updates, update only the owning artifacts and run scoped render/check for those touched artifacts.
6. Run `dotnet build Incursa.Quic.slnx -c Release`.
7. Run the focused INT test filter again.
8. If the focused filter is green, run adjacent tests for touched RFC9000 or stream/control-packet homes.
9. Run `git diff --check`.
10. Commit the bounded change if it is useful and verified.

Report format:
- Current branch and dirty state.
- Files changed.
- Root cause.
- Behavior fixed.
- Exact commands run and outcomes.
- Remaining red tests, if any, with a clear statement that they are outside this slice unless directly caused by the change.
````

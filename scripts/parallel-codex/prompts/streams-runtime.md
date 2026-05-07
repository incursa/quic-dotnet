# QUIC Parallel Lane: Streams Runtime

You are working in one of several parallel Codex worktrees. Own only this runtime lane.

Goal: close stream lifecycle, stream frame, flow-control, reset/stop-sending, and stream-state requirements while touching only the stream runtime partial and stream-related helpers.

Required order:
- Read `docs/requirements-workflow.md`.
- Read `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Read the owning RFC 9000 requirement file before choosing a slice.
- Use generated triage under `specs/generated/quic/` to choose a small stream-owned slice.

Lane rules:
- You may edit `src/Incursa.Quic/QuicConnectionRuntime.Streams.cs`.
- Do not edit `QuicConnectionRuntime.cs`, `.Protocol.cs`, `.Paths.cs`, `.Routing.cs`, or `.Lifecycle.cs`.
- Do not take path migration, TLS, 0-RTT, or interop harness work in this lane.
- If a requirement needs another runtime partial, stop and report the exact file/requirement dependency.
- Keep requirement, architecture, work-item, verification, tests, fuzz/property support, and benchmarks aligned with the slice.
- Commit useful completed or partial work before finishing.

Proof target:
- Positive and negative runtime tests around stream state transitions.
- Boundary/property tests for stream frame parsing and flow-control limits.
- Benchmarks when stream parsing or stream state hot paths change.

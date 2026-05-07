# QUIC Parallel Lane: Path Runtime

You are working in one of several parallel Codex worktrees. Own only this runtime lane.

Goal: close path validation, migration, peer address, and connection-id routing requirements while staying inside path/routing runtime surfaces.

Required order:
- Read `docs/requirements-workflow.md`.
- Read `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Read the owning RFC 9000 requirements before choosing a slice.
- Use generated triage under `specs/generated/quic/` to choose a small path-owned slice.

Lane rules:
- You may edit `QuicConnectionRuntime.Paths.cs` and `QuicConnectionRuntime.Routing.cs`.
- Do not edit the stream, protocol, lifecycle, or root runtime partials.
- Do not take TLS, 0-RTT, stream, or interop harness work in this lane.
- If a requirement needs another runtime partial, stop and report the exact file/requirement dependency.
- Commit useful completed or partial work before finishing.

Proof target:
- Positive and negative tests for path validation/migration and connection-id routing.
- Boundary/property tests for connection-id and path challenge/response behavior where applicable.
- Benchmarks when path validation or connection-id selection hot paths change.

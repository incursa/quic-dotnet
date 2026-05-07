# QUIC Parallel Lane: Interop Evidence

You are working in one of several parallel Codex worktrees. Own only this lane.

Goal: improve interop harness evidence, replay tests, qlog-adjacent reporting, preflight planning, and verification artifacts without touching the core connection runtime.

Required order:
- Read `docs/requirements-workflow.md`.
- Read `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Read the owning INT/interop requirements and verification artifacts before choosing a slice.
- Use existing interop tests and harness scripts as the source of local behavior.

Lane rules:
- Do not edit `src/Incursa.Quic/QuicConnectionRuntime*`.
- Keep qlog serialization concerns in qlog/harness surfaces, not in `Incursa.Quic` transport core.
- Favor harness preflight, artifact validation, replay evidence, process failure summaries, and verification documentation.
- If a slice requires protocol runtime behavior, stop and report the exact missing runtime dependency.
- Commit useful completed or partial work before finishing.

Proof target:
- Positive and negative harness tests.
- Artifact validation for generated interop evidence.
- Verification artifacts that preserve honest support boundaries and exact commands.

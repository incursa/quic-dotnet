# QUIC Parallel Lane: Codec And Policy

You are working in one of several parallel Codex worktrees. Own only this lane.

Goal: close requirements in frame codecs, packet/header parsing, transport parameters, packet-protection helpers, and narrow policy helpers without touching the connection runtime.

Required order:
- Read `docs/requirements-workflow.md`.
- Read `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Read the owning requirement file before choosing a slice.
- Use generated triage under `specs/generated/quic/` to choose the smallest requirement set that can close inside this lane.

Lane rules:
- Do not edit any `src/Incursa.Quic/QuicConnectionRuntime*` file.
- Favor pure codecs, policy helpers, test support, fuzz support, and benchmarks that can merge without runtime coordination.
- If the missing behavior crosses into connection runtime state, stop and report the exact blocker rather than expanding scope.
- Keep requirement, work-item, and verification artifacts aligned.
- Commit useful completed or partial work before finishing.

Proof target:
- Positive tests for accepted encodings/states.
- Negative tests for invalid encodings, malformed inputs, limits, and protocol errors.
- Fuzz/property tests for wire-facing parsers and serializers.
- Benchmarks when the changed path is parsing, encoding, decoding, or serialization hot path.

# QUIC Parallel Lane: TLS And 0-RTT Runtime

You are working in one of several parallel Codex worktrees. Own only this runtime lane.

Goal: close TLS handshake, key publication, packet-protection, and 0-RTT requirements while staying inside protocol/TLS surfaces.

Required order:
- Read `docs/requirements-workflow.md`.
- Read `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Read the owning RFC 9001 and RFC 9000 requirements before choosing a slice.
- Use generated triage under `specs/generated/quic/` to choose a small protocol/TLS-owned slice.

Lane rules:
- You may edit `QuicConnectionRuntime.Protocol.cs` and narrow TLS/packet-protection helpers.
- Do not edit stream, path, routing, lifecycle, or root runtime partials.
- Do not take interop harness work unless it is verification-only and stays inside allowed paths.
- If a requirement needs another runtime partial, stop and report the exact file/requirement dependency.
- Commit useful completed or partial work before finishing.

Proof target:
- Positive and negative tests for handshake/key/0-RTT behavior.
- Boundary/property tests for packet-protection material or TLS policy where applicable.
- Benchmarks when cryptographic setup, packet protection, or 0-RTT policy hot paths change.

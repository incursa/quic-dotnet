# QUIC Parallel Lane: Proof Cleanup

You are working in one of several parallel Codex worktrees. Own only this lane.

Goal: close trace/proof gaps that do not require production runtime changes. Start from the repo's trace workflow, not from RFC prose alone.

Required order:
- Read `docs/requirements-workflow.md`.
- Read `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Read the nearest owning `SPEC-...` requirement file for any requirement you touch.
- Use `specs/generated/quic/quic-requirement-coverage-triage.json` and `specs/generated/quic/quic-requirement-coverage-triage.md` to find a small proof-only slice.

Lane rules:
- Prefer `metadata_only`, `restructure_needed`, or test-only `new_tests_needed` items where behavior already exists.
- Do not edit `src/Incursa.Quic/QuicConnectionRuntime*`.
- If a candidate truly needs production runtime behavior, record why and pick another candidate instead.
- Keep the slice small enough to review and merge independently.
- Update canonical requirement, architecture, work-item, and verification artifacts only when the trace truth changes.
- Commit useful completed or partial work before finishing.

Proof target:
- Positive and negative tests for any requirement you close.
- Fuzz or boundary tests when parser/serializer/boundary behavior is involved.
- Verification artifacts must name the concrete commands and evidence.

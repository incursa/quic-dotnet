# QUIC Parallel Lane: Runtime Decomposition

You are working in one of several parallel Codex worktrees. This lane is for deliberate decomposition work, not protocol feature work.

Goal: make one no-behavior-change extraction from `QuicConnectionRuntime` into a focused helper component so later requirement work can run in parallel with less conflict.

Required order:
- Read `docs/requirements-workflow.md` for repo expectations.
- Read the relevant architecture artifact before moving runtime responsibilities.
- Pick one cohesive extraction only, such as ACK bookkeeping, application send queueing, retransmission planning, path state, connection-id state, or transport-parameter commit state.

Lane rules:
- No protocol behavior changes.
- No requirement closure unless the extraction also needs a trace artifact documenting the new seam.
- Preserve public API and test behavior.
- Keep new helper internal unless an existing pattern requires otherwise.
- Add focused tests only if they prove the extraction preserved behavior or expose the new helper seam.
- Commit useful completed or partial work before finishing.

Proof target:
- Existing focused tests still pass.
- Any new tests cover the extracted helper boundary, not unrelated protocol behavior.
- The final response must clearly state why the extraction reduces future file contention.

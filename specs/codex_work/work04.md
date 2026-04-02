
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9002-03-loss-detection
- rfc: 9002
- section_tokens:
  - S6
  - S6P1
  - S6P1P1
  - S6P1P2
  - S6P2
  - S6P2P1
  - S6P2P2
  - S6P2P2P1
  - S6P2P3
  - S6P2P4
  - S6P3
  - S6P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9002-03-loss-detection.reconciliation.json
- ./specs/generated/quic/chunks/9002-03-loss-detection.implementation-summary.json

Tasks:
1. Enumerate all requirements in scope.
2. Verify each requirement has one of:
   - implementation evidence
   - test evidence
   - explicit deferred/blocker note
3. Verify tests reference the correct requirement IDs where the repo convention expects that.
4. Verify code refs or XML-comment refs use the correct requirement IDs where the repo convention expects that.
5. Flag any requirement that still appears uncovered.
6. Flag any test or code reference that points to a stale or wrong ID.
7. Produce a closeout report.

Write:
- ./specs/generated/quic/chunks/9002-03-loss-detection.closeout.md
- ./specs/generated/quic/chunks/9002-03-loss-detection.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.

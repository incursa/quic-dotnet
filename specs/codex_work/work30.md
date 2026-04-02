
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-20-datagram-and-mtu
- rfc: 9000
- section_tokens:
  - S13P4
  - S13P4P1
  - S13P4P2
  - S13P4P2P1
  - S13P4P2P2
  - S14
  - S14P1
  - S14P2
  - S14P2P1
  - S14P3
  - S14P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.reconciliation.json
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.closeout.md
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.

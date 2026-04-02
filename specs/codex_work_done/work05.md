
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-01-streams-core
- rfc: 9000
- section_tokens:
  - S2
  - S2P1
  - S2P2
  - S2P3
  - S2P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/import-audit-summary.md
- any relevant generated trace/quality outputs in the repo
- any existing test-attribute, XML-comment, or direct requirement-ref conventions used by this repo

Rules:
- Work only within the selected chunk, except for narrowly shared helpers that are required.
- Do not change unrelated chunks.
- Prefer updating existing requirement references to the new imported IDs over creating duplicate coverage.
- Preserve the repository’s existing conventions for:
  - test attributes carrying requirement IDs
  - XML comments or code refs carrying requirement IDs
  - generated reports or mapping files

Tasks:
1. Enumerate all requirements in scope.
2. Inventory existing code, tests, comments, and requirement references that appear to satisfy or verify those requirements.
3. Find any old requirement IDs that should now point to the new imported IDs.
4. Update old references to the new IDs where the mapping is clear.
5. For each requirement in scope, classify it as:
   - implemented and tested
   - implemented but missing tests
   - tested but implementation mapping unclear
   - partially implemented
   - not implemented
   - unclear / needs human review
6. Fix straightforward small gaps in this pass when they are low-risk and local:
   - missing requirement attributes on existing tests
   - missing code comments / direct refs where the repo expects them
   - small missing tests for clearly implemented behavior
   - small implementation omissions that are tightly scoped and obvious
7. Do not attempt large feature work in this pass.
8. Run the relevant tests for the chunk.
9. Produce a gap report and change summary.

Write:
- ./specs/generated/quic/chunks/9000-01-streams-core.reconciliation.md
- ./specs/generated/quic/chunks/9000-01-streams-core.reconciliation.json

The markdown report must include:
- requirements in scope
- existing implementation evidence
- existing test evidence
- old->new requirement ID mappings applied
- gaps fixed in this pass
- remaining gaps
- requirements needing deeper implementation work
- tests run and results

The JSON report must include, per requirement:
- requirement_id
- status
- implementation_refs
- test_refs
- old_requirement_refs_rewritten
- changes_made
- remaining_gap
- notes

Success criteria:
- All existing code/tests in scope point to the correct new requirement IDs where mapping is clear.
- Easy gaps are fixed.
- Remaining work is isolated into a clean list for the next implementation pass.

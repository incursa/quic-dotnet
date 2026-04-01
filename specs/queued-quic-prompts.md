# QUIC Codex Prompt Queue

Generated: 2026-03-31T23:13:38

Code roots:
  - ./src

Test roots:
  - ./tests

## 8999-01-invariants (RFC 8999; ~8 requirements)

Section tokens: S5P1

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 8999-01-invariants
- rfc: 8999
- section_tokens:
  - S5P1
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC8999.json
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
- ./specs/generated/quic/chunks/8999-01-invariants.reconciliation.md
- ./specs/generated/quic/chunks/8999-01-invariants.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 8999-01-invariants
- rfc: 8999
- section_tokens:
  - S5P1
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC8999.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/8999-01-invariants.reconciliation.md
- ./specs/generated/quic/chunks/8999-01-invariants.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/8999-01-invariants.implementation-summary.md
- ./specs/generated/quic/chunks/8999-01-invariants.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 8999-01-invariants
- rfc: 8999
- section_tokens:
  - S5P1
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC8999.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/8999-01-invariants.reconciliation.json
- ./specs/generated/quic/chunks/8999-01-invariants.implementation-summary.json

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
- ./specs/generated/quic/chunks/8999-01-invariants.closeout.md
- ./specs/generated/quic/chunks/8999-01-invariants.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9001-01-tls-core (RFC 9001; ~44 requirements)

Section tokens: S2, S3, S4, S5, S6

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9001-01-tls-core
- rfc: 9001
- section_tokens:
  - S2
  - S3
  - S4
  - S5
  - S6
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json
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
- ./specs/generated/quic/chunks/9001-01-tls-core.reconciliation.md
- ./specs/generated/quic/chunks/9001-01-tls-core.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9001-01-tls-core
- rfc: 9001
- section_tokens:
  - S2
  - S3
  - S4
  - S5
  - S6
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9001-01-tls-core.reconciliation.md
- ./specs/generated/quic/chunks/9001-01-tls-core.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.md
- ./specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9001-01-tls-core
- rfc: 9001
- section_tokens:
  - S2
  - S3
  - S4
  - S5
  - S6
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9001-01-tls-core.reconciliation.json
- ./specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.json

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
- ./specs/generated/quic/chunks/9001-01-tls-core.closeout.md
- ./specs/generated/quic/chunks/9001-01-tls-core.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9001-02-security-and-registry (RFC 9001; ~8 requirements)

Section tokens: S7, S8, S9, S10

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9001-02-security-and-registry
- rfc: 9001
- section_tokens:
  - S7
  - S8
  - S9
  - S10
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json
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
- ./specs/generated/quic/chunks/9001-02-security-and-registry.reconciliation.md
- ./specs/generated/quic/chunks/9001-02-security-and-registry.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9001-02-security-and-registry
- rfc: 9001
- section_tokens:
  - S7
  - S8
  - S9
  - S10
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9001-02-security-and-registry.reconciliation.md
- ./specs/generated/quic/chunks/9001-02-security-and-registry.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9001-02-security-and-registry.implementation-summary.md
- ./specs/generated/quic/chunks/9001-02-security-and-registry.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9001-02-security-and-registry
- rfc: 9001
- section_tokens:
  - S7
  - S8
  - S9
  - S10
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9001-02-security-and-registry.reconciliation.json
- ./specs/generated/quic/chunks/9001-02-security-and-registry.implementation-summary.json

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
- ./specs/generated/quic/chunks/9001-02-security-and-registry.closeout.md
- ./specs/generated/quic/chunks/9001-02-security-and-registry.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9001-03-appendix-b-aead-limits (RFC 9001; ~9 requirements)

Section tokens: SB, SBP1P1, SBP1P2, SBP2

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9001-03-appendix-b-aead-limits
- rfc: 9001
- section_tokens:
  - SB
  - SBP1P1
  - SBP1P2
  - SBP2
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json
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
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.reconciliation.md
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9001-03-appendix-b-aead-limits
- rfc: 9001
- section_tokens:
  - SB
  - SBP1P1
  - SBP1P2
  - SBP2
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.reconciliation.md
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.implementation-summary.md
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9001-03-appendix-b-aead-limits
- rfc: 9001
- section_tokens:
  - SB
  - SBP1P1
  - SBP1P2
  - SBP2
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9001.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.reconciliation.json
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.implementation-summary.json

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
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.closeout.md
- ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9002-01-transport-basics (RFC 9002; ~21 requirements)

Section tokens: S2, S3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9002-01-transport-basics
- rfc: 9002
- section_tokens:
  - S2
  - S3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
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
- ./specs/generated/quic/chunks/9002-01-transport-basics.reconciliation.md
- ./specs/generated/quic/chunks/9002-01-transport-basics.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9002-01-transport-basics
- rfc: 9002
- section_tokens:
  - S2
  - S3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9002-01-transport-basics.reconciliation.md
- ./specs/generated/quic/chunks/9002-01-transport-basics.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9002-01-transport-basics.implementation-summary.md
- ./specs/generated/quic/chunks/9002-01-transport-basics.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9002-01-transport-basics
- rfc: 9002
- section_tokens:
  - S2
  - S3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9002-01-transport-basics.reconciliation.json
- ./specs/generated/quic/chunks/9002-01-transport-basics.implementation-summary.json

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
- ./specs/generated/quic/chunks/9002-01-transport-basics.closeout.md
- ./specs/generated/quic/chunks/9002-01-transport-basics.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9002-02-rtt-estimation (RFC 9002; ~25 requirements)

Section tokens: S5, S5P1, S5P2, S5P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9002-02-rtt-estimation
- rfc: 9002
- section_tokens:
  - S5
  - S5P1
  - S5P2
  - S5P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
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
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.reconciliation.md
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9002-02-rtt-estimation
- rfc: 9002
- section_tokens:
  - S5
  - S5P1
  - S5P2
  - S5P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.reconciliation.md
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.implementation-summary.md
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9002-02-rtt-estimation
- rfc: 9002
- section_tokens:
  - S5
  - S5P1
  - S5P2
  - S5P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.reconciliation.json
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.implementation-summary.json

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
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.closeout.md
- ./specs/generated/quic/chunks/9002-02-rtt-estimation.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9002-03-loss-detection (RFC 9002; ~55 requirements)

Section tokens: S6, S6P1, S6P1P1, S6P1P2, S6P2, S6P2P1, S6P2P2, S6P2P2P1, S6P2P3, S6P2P4, S6P3, S6P4

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

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
- ./specs/generated/quic/chunks/9002-03-loss-detection.reconciliation.md
- ./specs/generated/quic/chunks/9002-03-loss-detection.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

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
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9002-03-loss-detection.reconciliation.md
- ./specs/generated/quic/chunks/9002-03-loss-detection.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9002-03-loss-detection.implementation-summary.md
- ./specs/generated/quic/chunks/9002-03-loss-detection.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
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
```

---

## 9002-04-congestion-control (RFC 9002; ~46 requirements)

Section tokens: S7, S7P1, S7P2, S7P3P1, S7P3P2, S7P3P3, S7P4, S7P5, S7P6, S7P6P1, S7P6P2, S7P7, S7P8

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9002-04-congestion-control
- rfc: 9002
- section_tokens:
  - S7
  - S7P1
  - S7P2
  - S7P3P1
  - S7P3P2
  - S7P3P3
  - S7P4
  - S7P5
  - S7P6
  - S7P6P1
  - S7P6P2
  - S7P7
  - S7P8
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
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
- ./specs/generated/quic/chunks/9002-04-congestion-control.reconciliation.md
- ./specs/generated/quic/chunks/9002-04-congestion-control.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9002-04-congestion-control
- rfc: 9002
- section_tokens:
  - S7
  - S7P1
  - S7P2
  - S7P3P1
  - S7P3P2
  - S7P3P3
  - S7P4
  - S7P5
  - S7P6
  - S7P6P1
  - S7P6P2
  - S7P7
  - S7P8
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9002-04-congestion-control.reconciliation.md
- ./specs/generated/quic/chunks/9002-04-congestion-control.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9002-04-congestion-control.implementation-summary.md
- ./specs/generated/quic/chunks/9002-04-congestion-control.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9002-04-congestion-control
- rfc: 9002
- section_tokens:
  - S7
  - S7P1
  - S7P2
  - S7P3P1
  - S7P3P2
  - S7P3P3
  - S7P4
  - S7P5
  - S7P6
  - S7P6P1
  - S7P6P2
  - S7P7
  - S7P8
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9002-04-congestion-control.reconciliation.json
- ./specs/generated/quic/chunks/9002-04-congestion-control.implementation-summary.json

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
- ./specs/generated/quic/chunks/9002-04-congestion-control.closeout.md
- ./specs/generated/quic/chunks/9002-04-congestion-control.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9002-05-appendix-a-recovery-state (RFC 9002; ~49 requirements)

Section tokens: SAP1, SAP1P1, SAP2, SAP4, SAP5, SAP6, SAP7, SAP8, SAP9, SAP10, SAP11

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9002-05-appendix-a-recovery-state
- rfc: 9002
- section_tokens:
  - SAP1
  - SAP1P1
  - SAP2
  - SAP4
  - SAP5
  - SAP6
  - SAP7
  - SAP8
  - SAP9
  - SAP10
  - SAP11
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
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
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.reconciliation.md
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9002-05-appendix-a-recovery-state
- rfc: 9002
- section_tokens:
  - SAP1
  - SAP1P1
  - SAP2
  - SAP4
  - SAP5
  - SAP6
  - SAP7
  - SAP8
  - SAP9
  - SAP10
  - SAP11
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.reconciliation.md
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.implementation-summary.md
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9002-05-appendix-a-recovery-state
- rfc: 9002
- section_tokens:
  - SAP1
  - SAP1P1
  - SAP2
  - SAP4
  - SAP5
  - SAP6
  - SAP7
  - SAP8
  - SAP9
  - SAP10
  - SAP11
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.reconciliation.json
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.implementation-summary.json

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
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.closeout.md
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9002-06-appendix-b-constants-and-examples (RFC 9002; ~28 requirements)

Section tokens: SBP1, SBP2, SBP3, SBP4, SBP5, SBP6, SBP7, SBP8, SBP9

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9002-06-appendix-b-constants-and-examples
- rfc: 9002
- section_tokens:
  - SBP1
  - SBP2
  - SBP3
  - SBP4
  - SBP5
  - SBP6
  - SBP7
  - SBP8
  - SBP9
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
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
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.reconciliation.md
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9002-06-appendix-b-constants-and-examples
- rfc: 9002
- section_tokens:
  - SBP1
  - SBP2
  - SBP3
  - SBP4
  - SBP5
  - SBP6
  - SBP7
  - SBP8
  - SBP9
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.reconciliation.md
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.implementation-summary.md
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9002-06-appendix-b-constants-and-examples
- rfc: 9002
- section_tokens:
  - SBP1
  - SBP2
  - SBP3
  - SBP4
  - SBP5
  - SBP6
  - SBP7
  - SBP8
  - SBP9
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.reconciliation.json
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.implementation-summary.json

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
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.closeout.md
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-01-streams-core (RFC 9000; ~44 requirements)

Section tokens: S2, S2P1, S2P2, S2P3, S2P4

### Prompt 2 - Reconciliation

```text
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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

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
- ./specs/generated/quic/chunks/9000-01-streams-core.reconciliation.md
- ./specs/generated/quic/chunks/9000-01-streams-core.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-01-streams-core.implementation-summary.md
- ./specs/generated/quic/chunks/9000-01-streams-core.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

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

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-01-streams-core.reconciliation.json
- ./specs/generated/quic/chunks/9000-01-streams-core.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-01-streams-core.closeout.md
- ./specs/generated/quic/chunks/9000-01-streams-core.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-02-stream-state (RFC 9000; ~66 requirements)

Section tokens: S3, S3P1, S3P2, S3P3, S3P4, S3P5

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-02-stream-state
- rfc: 9000
- section_tokens:
  - S3
  - S3P1
  - S3P2
  - S3P3
  - S3P4
  - S3P5
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
- ./specs/generated/quic/chunks/9000-02-stream-state.reconciliation.md
- ./specs/generated/quic/chunks/9000-02-stream-state.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-02-stream-state
- rfc: 9000
- section_tokens:
  - S3
  - S3P1
  - S3P2
  - S3P3
  - S3P4
  - S3P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-02-stream-state.reconciliation.md
- ./specs/generated/quic/chunks/9000-02-stream-state.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-02-stream-state.implementation-summary.md
- ./specs/generated/quic/chunks/9000-02-stream-state.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-02-stream-state
- rfc: 9000
- section_tokens:
  - S3
  - S3P1
  - S3P2
  - S3P3
  - S3P4
  - S3P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-02-stream-state.reconciliation.json
- ./specs/generated/quic/chunks/9000-02-stream-state.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-02-stream-state.closeout.md
- ./specs/generated/quic/chunks/9000-02-stream-state.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-03-flow-control (RFC 9000; ~50 requirements)

Section tokens: S4, S4P1, S4P2, S4P4, S4P5, S4P6

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-03-flow-control
- rfc: 9000
- section_tokens:
  - S4
  - S4P1
  - S4P2
  - S4P4
  - S4P5
  - S4P6
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
- ./specs/generated/quic/chunks/9000-03-flow-control.reconciliation.md
- ./specs/generated/quic/chunks/9000-03-flow-control.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-03-flow-control
- rfc: 9000
- section_tokens:
  - S4
  - S4P1
  - S4P2
  - S4P4
  - S4P5
  - S4P6
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-03-flow-control.reconciliation.md
- ./specs/generated/quic/chunks/9000-03-flow-control.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-03-flow-control.implementation-summary.md
- ./specs/generated/quic/chunks/9000-03-flow-control.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-03-flow-control
- rfc: 9000
- section_tokens:
  - S4
  - S4P1
  - S4P2
  - S4P4
  - S4P5
  - S4P6
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-03-flow-control.reconciliation.json
- ./specs/generated/quic/chunks/9000-03-flow-control.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-03-flow-control.closeout.md
- ./specs/generated/quic/chunks/9000-03-flow-control.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-04-connection-ids-basics (RFC 9000; ~44 requirements)

Section tokens: S5, S5P1, S5P1P1

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-04-connection-ids-basics
- rfc: 9000
- section_tokens:
  - S5
  - S5P1
  - S5P1P1
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
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.reconciliation.md
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-04-connection-ids-basics
- rfc: 9000
- section_tokens:
  - S5
  - S5P1
  - S5P1P1
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.reconciliation.md
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.implementation-summary.md
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-04-connection-ids-basics
- rfc: 9000
- section_tokens:
  - S5
  - S5P1
  - S5P1P1
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.reconciliation.json
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.closeout.md
- ./specs/generated/quic/chunks/9000-04-connection-ids-basics.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-05-connection-id-management (RFC 9000; ~61 requirements)

Section tokens: S5P1P2, S5P2, S5P2P1, S5P2P2, S5P2P3, S5P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-05-connection-id-management
- rfc: 9000
- section_tokens:
  - S5P1P2
  - S5P2
  - S5P2P1
  - S5P2P2
  - S5P2P3
  - S5P3
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
- ./specs/generated/quic/chunks/9000-05-connection-id-management.reconciliation.md
- ./specs/generated/quic/chunks/9000-05-connection-id-management.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-05-connection-id-management
- rfc: 9000
- section_tokens:
  - S5P1P2
  - S5P2
  - S5P2P1
  - S5P2P2
  - S5P2P3
  - S5P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-05-connection-id-management.reconciliation.md
- ./specs/generated/quic/chunks/9000-05-connection-id-management.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-05-connection-id-management.implementation-summary.md
- ./specs/generated/quic/chunks/9000-05-connection-id-management.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-05-connection-id-management
- rfc: 9000
- section_tokens:
  - S5P1P2
  - S5P2
  - S5P2P1
  - S5P2P2
  - S5P2P3
  - S5P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-05-connection-id-management.reconciliation.json
- ./specs/generated/quic/chunks/9000-05-connection-id-management.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-05-connection-id-management.closeout.md
- ./specs/generated/quic/chunks/9000-05-connection-id-management.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-06-version-negotiation (RFC 9000; ~11 requirements)

Section tokens: S6, S6P1, S6P2, S6P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-06-version-negotiation
- rfc: 9000
- section_tokens:
  - S6
  - S6P1
  - S6P2
  - S6P3
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
- ./specs/generated/quic/chunks/9000-06-version-negotiation.reconciliation.md
- ./specs/generated/quic/chunks/9000-06-version-negotiation.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-06-version-negotiation
- rfc: 9000
- section_tokens:
  - S6
  - S6P1
  - S6P2
  - S6P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-06-version-negotiation.reconciliation.md
- ./specs/generated/quic/chunks/9000-06-version-negotiation.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-06-version-negotiation.implementation-summary.md
- ./specs/generated/quic/chunks/9000-06-version-negotiation.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-06-version-negotiation
- rfc: 9000
- section_tokens:
  - S6
  - S6P1
  - S6P2
  - S6P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-06-version-negotiation.reconciliation.json
- ./specs/generated/quic/chunks/9000-06-version-negotiation.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-06-version-negotiation.closeout.md
- ./specs/generated/quic/chunks/9000-06-version-negotiation.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-07-handshake-properties (RFC 9000; ~34 requirements)

Section tokens: S7, S7P2, S7P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-07-handshake-properties
- rfc: 9000
- section_tokens:
  - S7
  - S7P2
  - S7P3
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
- ./specs/generated/quic/chunks/9000-07-handshake-properties.reconciliation.md
- ./specs/generated/quic/chunks/9000-07-handshake-properties.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-07-handshake-properties
- rfc: 9000
- section_tokens:
  - S7
  - S7P2
  - S7P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-07-handshake-properties.reconciliation.md
- ./specs/generated/quic/chunks/9000-07-handshake-properties.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-07-handshake-properties.implementation-summary.md
- ./specs/generated/quic/chunks/9000-07-handshake-properties.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-07-handshake-properties
- rfc: 9000
- section_tokens:
  - S7
  - S7P2
  - S7P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-07-handshake-properties.reconciliation.json
- ./specs/generated/quic/chunks/9000-07-handshake-properties.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-07-handshake-properties.closeout.md
- ./specs/generated/quic/chunks/9000-07-handshake-properties.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-08-transport-params-and-crypto-buffers (RFC 9000; ~22 requirements)

Section tokens: S7P4, S7P4P1, S7P4P2, S7P5

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-08-transport-params-and-crypto-buffers
- rfc: 9000
- section_tokens:
  - S7P4
  - S7P4P1
  - S7P4P2
  - S7P5
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
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.reconciliation.md
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-08-transport-params-and-crypto-buffers
- rfc: 9000
- section_tokens:
  - S7P4
  - S7P4P1
  - S7P4P2
  - S7P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.reconciliation.md
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.implementation-summary.md
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-08-transport-params-and-crypto-buffers
- rfc: 9000
- section_tokens:
  - S7P4
  - S7P4P1
  - S7P4P2
  - S7P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.reconciliation.json
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.closeout.md
- ./specs/generated/quic/chunks/9000-08-transport-params-and-crypto-buffers.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-09-address-validation-and-tokens (RFC 9000; ~42 requirements)

Section tokens: S8, S8P1, S8P1P1, S8P1P2, S8P1P3, S8P1P4

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-09-address-validation-and-tokens
- rfc: 9000
- section_tokens:
  - S8
  - S8P1
  - S8P1P1
  - S8P1P2
  - S8P1P3
  - S8P1P4
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
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.reconciliation.md
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-09-address-validation-and-tokens
- rfc: 9000
- section_tokens:
  - S8
  - S8P1
  - S8P1P1
  - S8P1P2
  - S8P1P3
  - S8P1P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.reconciliation.md
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.implementation-summary.md
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-09-address-validation-and-tokens
- rfc: 9000
- section_tokens:
  - S8
  - S8P1
  - S8P1P1
  - S8P1P2
  - S8P1P3
  - S8P1P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.reconciliation.json
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.closeout.md
- ./specs/generated/quic/chunks/9000-09-address-validation-and-tokens.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-10-path-validation (RFC 9000; ~21 requirements)

Section tokens: S8P2, S8P2P1, S8P2P2, S8P2P3, S8P2P4

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-10-path-validation
- rfc: 9000
- section_tokens:
  - S8P2
  - S8P2P1
  - S8P2P2
  - S8P2P3
  - S8P2P4
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
- ./specs/generated/quic/chunks/9000-10-path-validation.reconciliation.md
- ./specs/generated/quic/chunks/9000-10-path-validation.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-10-path-validation
- rfc: 9000
- section_tokens:
  - S8P2
  - S8P2P1
  - S8P2P2
  - S8P2P3
  - S8P2P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-10-path-validation.reconciliation.md
- ./specs/generated/quic/chunks/9000-10-path-validation.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-10-path-validation.implementation-summary.md
- ./specs/generated/quic/chunks/9000-10-path-validation.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-10-path-validation
- rfc: 9000
- section_tokens:
  - S8P2
  - S8P2P1
  - S8P2P2
  - S8P2P3
  - S8P2P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-10-path-validation.reconciliation.json
- ./specs/generated/quic/chunks/9000-10-path-validation.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-10-path-validation.closeout.md
- ./specs/generated/quic/chunks/9000-10-path-validation.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-11-migration-core (RFC 9000; ~40 requirements)

Section tokens: S9, S9P1, S9P2, S9P3, S9P3P1, S9P3P2, S9P3P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-11-migration-core
- rfc: 9000
- section_tokens:
  - S9
  - S9P1
  - S9P2
  - S9P3
  - S9P3P1
  - S9P3P2
  - S9P3P3
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
- ./specs/generated/quic/chunks/9000-11-migration-core.reconciliation.md
- ./specs/generated/quic/chunks/9000-11-migration-core.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-11-migration-core
- rfc: 9000
- section_tokens:
  - S9
  - S9P1
  - S9P2
  - S9P3
  - S9P3P1
  - S9P3P2
  - S9P3P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-11-migration-core.reconciliation.md
- ./specs/generated/quic/chunks/9000-11-migration-core.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-11-migration-core.implementation-summary.md
- ./specs/generated/quic/chunks/9000-11-migration-core.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-11-migration-core
- rfc: 9000
- section_tokens:
  - S9
  - S9P1
  - S9P2
  - S9P3
  - S9P3P1
  - S9P3P2
  - S9P3P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-11-migration-core.reconciliation.json
- ./specs/generated/quic/chunks/9000-11-migration-core.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-11-migration-core.closeout.md
- ./specs/generated/quic/chunks/9000-11-migration-core.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-12-migration-followup (RFC 9000; ~61 requirements)

Section tokens: S9P4, S9P5, S9P6, S9P6P1, S9P6P2, S9P6P3, S9P7

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-12-migration-followup
- rfc: 9000
- section_tokens:
  - S9P4
  - S9P5
  - S9P6
  - S9P6P1
  - S9P6P2
  - S9P6P3
  - S9P7
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
- ./specs/generated/quic/chunks/9000-12-migration-followup.reconciliation.md
- ./specs/generated/quic/chunks/9000-12-migration-followup.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-12-migration-followup
- rfc: 9000
- section_tokens:
  - S9P4
  - S9P5
  - S9P6
  - S9P6P1
  - S9P6P2
  - S9P6P3
  - S9P7
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-12-migration-followup.reconciliation.md
- ./specs/generated/quic/chunks/9000-12-migration-followup.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-12-migration-followup.implementation-summary.md
- ./specs/generated/quic/chunks/9000-12-migration-followup.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-12-migration-followup
- rfc: 9000
- section_tokens:
  - S9P4
  - S9P5
  - S9P6
  - S9P6P1
  - S9P6P2
  - S9P6P3
  - S9P7
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-12-migration-followup.reconciliation.json
- ./specs/generated/quic/chunks/9000-12-migration-followup.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-12-migration-followup.closeout.md
- ./specs/generated/quic/chunks/9000-12-migration-followup.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-13-idle-and-close (RFC 9000; ~52 requirements)

Section tokens: S10, S10P1, S10P1P1, S10P1P2, S10P2, S10P2P1, S10P2P2, S10P2P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-13-idle-and-close
- rfc: 9000
- section_tokens:
  - S10
  - S10P1
  - S10P1P1
  - S10P1P2
  - S10P2
  - S10P2P1
  - S10P2P2
  - S10P2P3
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
- ./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.md
- ./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-13-idle-and-close
- rfc: 9000
- section_tokens:
  - S10
  - S10P1
  - S10P1P1
  - S10P1P2
  - S10P2
  - S10P2P1
  - S10P2P2
  - S10P2P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.md
- ./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.md
- ./specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-13-idle-and-close
- rfc: 9000
- section_tokens:
  - S10
  - S10P1
  - S10P1P1
  - S10P1P2
  - S10P2
  - S10P2P1
  - S10P2P2
  - S10P2P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.json
- ./specs/generated/quic/chunks/9000-13-idle-and-close.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-13-idle-and-close.closeout.md
- ./specs/generated/quic/chunks/9000-13-idle-and-close.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-14-stateless-reset (RFC 9000; ~55 requirements)

Section tokens: S10P3, S10P3P1, S10P3P2, S10P3P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-14-stateless-reset
- rfc: 9000
- section_tokens:
  - S10P3
  - S10P3P1
  - S10P3P2
  - S10P3P3
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
- ./specs/generated/quic/chunks/9000-14-stateless-reset.reconciliation.md
- ./specs/generated/quic/chunks/9000-14-stateless-reset.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-14-stateless-reset
- rfc: 9000
- section_tokens:
  - S10P3
  - S10P3P1
  - S10P3P2
  - S10P3P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-14-stateless-reset.reconciliation.md
- ./specs/generated/quic/chunks/9000-14-stateless-reset.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-14-stateless-reset.implementation-summary.md
- ./specs/generated/quic/chunks/9000-14-stateless-reset.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-14-stateless-reset
- rfc: 9000
- section_tokens:
  - S10P3
  - S10P3P1
  - S10P3P2
  - S10P3P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-14-stateless-reset.reconciliation.json
- ./specs/generated/quic/chunks/9000-14-stateless-reset.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-14-stateless-reset.closeout.md
- ./specs/generated/quic/chunks/9000-14-stateless-reset.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-15-error-handling (RFC 9000; ~18 requirements)

Section tokens: S11, S11P1, S11P2

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-15-error-handling
- rfc: 9000
- section_tokens:
  - S11
  - S11P1
  - S11P2
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
- ./specs/generated/quic/chunks/9000-15-error-handling.reconciliation.md
- ./specs/generated/quic/chunks/9000-15-error-handling.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-15-error-handling
- rfc: 9000
- section_tokens:
  - S11
  - S11P1
  - S11P2
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-15-error-handling.reconciliation.md
- ./specs/generated/quic/chunks/9000-15-error-handling.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-15-error-handling.implementation-summary.md
- ./specs/generated/quic/chunks/9000-15-error-handling.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-15-error-handling
- rfc: 9000
- section_tokens:
  - S11
  - S11P1
  - S11P2
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-15-error-handling.reconciliation.json
- ./specs/generated/quic/chunks/9000-15-error-handling.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-15-error-handling.closeout.md
- ./specs/generated/quic/chunks/9000-15-error-handling.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-16-packet-protection-and-coalescing (RFC 9000; ~32 requirements)

Section tokens: S12P1, S12P2, S12P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-16-packet-protection-and-coalescing
- rfc: 9000
- section_tokens:
  - S12P1
  - S12P2
  - S12P3
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
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.reconciliation.md
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-16-packet-protection-and-coalescing
- rfc: 9000
- section_tokens:
  - S12P1
  - S12P2
  - S12P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.reconciliation.md
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.implementation-summary.md
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-16-packet-protection-and-coalescing
- rfc: 9000
- section_tokens:
  - S12P1
  - S12P2
  - S12P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.reconciliation.json
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.closeout.md
- ./specs/generated/quic/chunks/9000-16-packet-protection-and-coalescing.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-17-frame-and-space-rules (RFC 9000; ~28 requirements)

Section tokens: S12P4, S12P5

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-17-frame-and-space-rules
- rfc: 9000
- section_tokens:
  - S12P4
  - S12P5
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
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.reconciliation.md
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-17-frame-and-space-rules
- rfc: 9000
- section_tokens:
  - S12P4
  - S12P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.reconciliation.md
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.implementation-summary.md
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-17-frame-and-space-rules
- rfc: 9000
- section_tokens:
  - S12P4
  - S12P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.reconciliation.json
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.closeout.md
- ./specs/generated/quic/chunks/9000-17-frame-and-space-rules.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-18-ack-generation (RFC 9000; ~54 requirements)

Section tokens: S13, S13P1, S13P2, S13P2P1, S13P2P2, S13P2P3, S13P2P4, S13P2P5, S13P2P6, S13P2P7

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-18-ack-generation
- rfc: 9000
- section_tokens:
  - S13
  - S13P1
  - S13P2
  - S13P2P1
  - S13P2P2
  - S13P2P3
  - S13P2P4
  - S13P2P5
  - S13P2P6
  - S13P2P7
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
- ./specs/generated/quic/chunks/9000-18-ack-generation.reconciliation.md
- ./specs/generated/quic/chunks/9000-18-ack-generation.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-18-ack-generation
- rfc: 9000
- section_tokens:
  - S13
  - S13P1
  - S13P2
  - S13P2P1
  - S13P2P2
  - S13P2P3
  - S13P2P4
  - S13P2P5
  - S13P2P6
  - S13P2P7
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-18-ack-generation.reconciliation.md
- ./specs/generated/quic/chunks/9000-18-ack-generation.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-18-ack-generation.implementation-summary.md
- ./specs/generated/quic/chunks/9000-18-ack-generation.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-18-ack-generation
- rfc: 9000
- section_tokens:
  - S13
  - S13P1
  - S13P2
  - S13P2P1
  - S13P2P2
  - S13P2P3
  - S13P2P4
  - S13P2P5
  - S13P2P6
  - S13P2P7
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-18-ack-generation.reconciliation.json
- ./specs/generated/quic/chunks/9000-18-ack-generation.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-18-ack-generation.closeout.md
- ./specs/generated/quic/chunks/9000-18-ack-generation.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-19-retransmission-and-frame-reliability (RFC 9000; ~39 requirements)

Section tokens: S13P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-19-retransmission-and-frame-reliability
- rfc: 9000
- section_tokens:
  - S13P3
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
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.reconciliation.md
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-19-retransmission-and-frame-reliability
- rfc: 9000
- section_tokens:
  - S13P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.reconciliation.md
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.implementation-summary.md
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-19-retransmission-and-frame-reliability
- rfc: 9000
- section_tokens:
  - S13P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.reconciliation.json
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.closeout.md
- ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-20-datagram-and-mtu (RFC 9000; ~85 requirements)

Section tokens: S13P4, S13P4P1, S13P4P2, S13P4P2P1, S13P4P2P2, S14, S14P1, S14P2, S14P2P1, S14P3, S14P4, S15, S16

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

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
  - S15
  - S16
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
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.reconciliation.md
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

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
  - S15
  - S16
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.reconciliation.md
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.implementation-summary.md
- ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
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
  - S15
  - S16
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
```

---

## 9000-21-long-header-general-and-initial (RFC 9000; ~58 requirements)

Section tokens: S17, S17P1, S17P2, S17P2P1

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-21-long-header-general-and-initial
- rfc: 9000
- section_tokens:
  - S17
  - S17P1
  - S17P2
  - S17P2P1
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
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.reconciliation.md
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-21-long-header-general-and-initial
- rfc: 9000
- section_tokens:
  - S17
  - S17P1
  - S17P2
  - S17P2P1
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.reconciliation.md
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.implementation-summary.md
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-21-long-header-general-and-initial
- rfc: 9000
- section_tokens:
  - S17
  - S17P1
  - S17P2
  - S17P2P1
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.reconciliation.json
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.closeout.md
- ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-22-long-header-handshake-and-0rtt (RFC 9000; ~49 requirements)

Section tokens: S17P2P2, S17P2P3

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-22-long-header-handshake-and-0rtt
- rfc: 9000
- section_tokens:
  - S17P2P2
  - S17P2P3
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
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.reconciliation.md
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-22-long-header-handshake-and-0rtt
- rfc: 9000
- section_tokens:
  - S17P2P2
  - S17P2P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.reconciliation.md
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.implementation-summary.md
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-22-long-header-handshake-and-0rtt
- rfc: 9000
- section_tokens:
  - S17P2P2
  - S17P2P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.reconciliation.json
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.closeout.md
- ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-23-retry-version-short-header (RFC 9000; ~96 requirements)

Section tokens: S17P2P4, S17P2P5, S17P2P5P1, S17P2P5P2, S17P2P5P3, S17P3, S17P3P1, S17P4

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-23-retry-version-short-header
- rfc: 9000
- section_tokens:
  - S17P2P4
  - S17P2P5
  - S17P2P5P1
  - S17P2P5P2
  - S17P2P5P3
  - S17P3
  - S17P3P1
  - S17P4
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
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.reconciliation.md
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-23-retry-version-short-header
- rfc: 9000
- section_tokens:
  - S17P2P4
  - S17P2P5
  - S17P2P5P1
  - S17P2P5P2
  - S17P2P5P3
  - S17P3
  - S17P3P1
  - S17P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.reconciliation.md
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.implementation-summary.md
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-23-retry-version-short-header
- rfc: 9000
- section_tokens:
  - S17P2P4
  - S17P2P5
  - S17P2P5P1
  - S17P2P5P2
  - S17P2P5P3
  - S17P3
  - S17P3P1
  - S17P4
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.reconciliation.json
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.closeout.md
- ./specs/generated/quic/chunks/9000-23-retry-version-short-header.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-24-frame-encodings-part-1 (RFC 9000; ~47 requirements)

Section tokens: S18, S18P1, S18P2

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-24-frame-encodings-part-1
- rfc: 9000
- section_tokens:
  - S18
  - S18P1
  - S18P2
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
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.reconciliation.md
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-24-frame-encodings-part-1
- rfc: 9000
- section_tokens:
  - S18
  - S18P1
  - S18P2
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.reconciliation.md
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.implementation-summary.md
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-24-frame-encodings-part-1
- rfc: 9000
- section_tokens:
  - S18
  - S18P1
  - S18P2
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.reconciliation.json
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.closeout.md
- ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-25-frame-encodings-part-2 (RFC 9000; ~68 requirements)

Section tokens: S19P1, S19P2, S19P3, S19P3P1, S19P3P2, S19P4, S19P5

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-25-frame-encodings-part-2
- rfc: 9000
- section_tokens:
  - S19P1
  - S19P2
  - S19P3
  - S19P3P1
  - S19P3P2
  - S19P4
  - S19P5
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
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.reconciliation.md
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-25-frame-encodings-part-2
- rfc: 9000
- section_tokens:
  - S19P1
  - S19P2
  - S19P3
  - S19P3P1
  - S19P3P2
  - S19P4
  - S19P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.reconciliation.md
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.implementation-summary.md
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-25-frame-encodings-part-2
- rfc: 9000
- section_tokens:
  - S19P1
  - S19P2
  - S19P3
  - S19P3P1
  - S19P3P2
  - S19P4
  - S19P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.reconciliation.json
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.closeout.md
- ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-26-frame-encodings-part-3 (RFC 9000; ~78 requirements)

Section tokens: S19P6, S19P7, S19P8, S19P9, S19P10, S19P11

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-26-frame-encodings-part-3
- rfc: 9000
- section_tokens:
  - S19P6
  - S19P7
  - S19P8
  - S19P9
  - S19P10
  - S19P11
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
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.reconciliation.md
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-26-frame-encodings-part-3
- rfc: 9000
- section_tokens:
  - S19P6
  - S19P7
  - S19P8
  - S19P9
  - S19P10
  - S19P11
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.reconciliation.md
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.implementation-summary.md
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-26-frame-encodings-part-3
- rfc: 9000
- section_tokens:
  - S19P6
  - S19P7
  - S19P8
  - S19P9
  - S19P10
  - S19P11
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.reconciliation.json
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.closeout.md
- ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-27-frame-encodings-part-4 (RFC 9000; ~66 requirements)

Section tokens: S19P12, S19P13, S19P14, S19P15, S19P16, S19P17, S19P18

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-27-frame-encodings-part-4
- rfc: 9000
- section_tokens:
  - S19P12
  - S19P13
  - S19P14
  - S19P15
  - S19P16
  - S19P17
  - S19P18
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
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.reconciliation.md
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-27-frame-encodings-part-4
- rfc: 9000
- section_tokens:
  - S19P12
  - S19P13
  - S19P14
  - S19P15
  - S19P16
  - S19P17
  - S19P18
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.reconciliation.md
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.implementation-summary.md
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-27-frame-encodings-part-4
- rfc: 9000
- section_tokens:
  - S19P12
  - S19P13
  - S19P14
  - S19P15
  - S19P16
  - S19P17
  - S19P18
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.reconciliation.json
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.closeout.md
- ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-28-errors-registry-and-security (RFC 9000; ~70 requirements)

Section tokens: S19P19, S19P20, S19P21, S20P1, S20P2, S21P1P1P1, S21P2, S21P3, S21P4, S21P5, S21P5P3, S21P5P6, S21P6, S21P7, S21P9, S21P10, S21P11, S21P12

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-28-errors-registry-and-security
- rfc: 9000
- section_tokens:
  - S19P19
  - S19P20
  - S19P21
  - S20P1
  - S20P2
  - S21P1P1P1
  - S21P2
  - S21P3
  - S21P4
  - S21P5
  - S21P5P3
  - S21P5P6
  - S21P6
  - S21P7
  - S21P9
  - S21P10
  - S21P11
  - S21P12
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
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.reconciliation.md
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-28-errors-registry-and-security
- rfc: 9000
- section_tokens:
  - S19P19
  - S19P20
  - S19P21
  - S20P1
  - S20P2
  - S21P1P1P1
  - S21P2
  - S21P3
  - S21P4
  - S21P5
  - S21P5P3
  - S21P5P6
  - S21P6
  - S21P7
  - S21P9
  - S21P10
  - S21P11
  - S21P12
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.reconciliation.md
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.implementation-summary.md
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-28-errors-registry-and-security
- rfc: 9000
- section_tokens:
  - S19P19
  - S19P20
  - S19P21
  - S20P1
  - S20P2
  - S21P1P1P1
  - S21P2
  - S21P3
  - S21P4
  - S21P5
  - S21P5P3
  - S21P5P6
  - S21P6
  - S21P7
  - S21P9
  - S21P10
  - S21P11
  - S21P12
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.reconciliation.json
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.closeout.md
- ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

## 9000-29-iana-and-late-sections (RFC 9000; ~52 requirements)

Section tokens: S22P1P1, S22P1P2, S22P1P3, S22P1P4, S22P2, S22P3, S22P4, S22P5

### Prompt 2 - Reconciliation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-29-iana-and-late-sections
- rfc: 9000
- section_tokens:
  - S22P1P1
  - S22P1P2
  - S22P1P3
  - S22P1P4
  - S22P2
  - S22P3
  - S22P4
  - S22P5
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
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.reconciliation.md
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.reconciliation.json

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
```

### Prompt 3 - Implementation

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-29-iana-and-late-sections
- rfc: 9000
- section_tokens:
  - S22P1P1
  - S22P1P2
  - S22P1P3
  - S22P1P4
  - S22P2
  - S22P3
  - S22P4
  - S22P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.reconciliation.md
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- Only implement requirements in the selected chunk.
- Minimize changes outside the chunk, except for necessary shared helpers.
- Follow existing repository patterns rather than inventing new architecture.
- Add or update tests for every materially changed behavior in scope.
- Where the repo convention supports it, attach the relevant requirement IDs to tests and code refs.
- Do not fabricate canonical verification artifacts unless the repo already has an approved pattern for doing so.
- Leave unrelated gaps alone and report them.

Tasks:
1. Review all requirements in scope that remain:
   - partially implemented
   - not implemented
   - unclear but resolvable
2. Implement the minimum clean set of code changes required to satisfy them.
3. Add or update tests to prove the implemented behavior.
4. Update direct requirement refs in tests and code comments where the repo expects them.
5. Run relevant tests.
6. Produce a chunk completion report.

Write:
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.implementation-summary.md
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.implementation-summary.json

The markdown summary must include:
- requirements completed
- files changed
- tests added or updated
- tests run and results
- remaining open requirements in scope, if any
- risks or follow-up notes

The JSON summary must include:
- requirement_id
- completion_status
- files_changed
- tests_covering_requirement
- direct_refs_added_or_updated
- remaining_gap
- notes

Success criteria:
- Every requirement in the selected chunk is either:
  - implemented and tested
  - intentionally deferred with a clearly stated reason
  - still blocked by a concrete technical dependency
- The chunk can be reviewed independently.
```

### Prompt 4 - Closeout

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-29-iana-and-late-sections
- rfc: 9000
- section_tokens:
  - S22P1P1
  - S22P1P2
  - S22P1P3
  - S22P1P4
  - S22P2
  - S22P3
  - S22P4
  - S22P5
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.reconciliation.json
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.implementation-summary.json

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
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.closeout.md
- ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
```

---

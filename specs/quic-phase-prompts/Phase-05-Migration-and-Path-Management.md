# Phase 05 — Migration and Path Management

Once streams, ACK, and validation exist, implement migration and path-management behavior.

Code roots used in generated prompts:
- .\src

Test roots used in generated prompts:
- .\tests

## Chunk Order

- $(@{ChunkId=9000-11-migration-core; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield migration-core behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-11-migration-core; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield migration-core behavior.; Confidence=high}.Mode) — Greenfield migration-core behavior.
- $(@{ChunkId=9000-12-migration-followup; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield migration follow-up and preferred-address behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-12-migration-followup; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield migration follow-up and preferred-address behavior.; Confidence=high}.Mode) — Greenfield migration follow-up and preferred-address behavior.

## 9000-11-migration-core

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S9, S9P1, S9P2, S9P3, S9P3P1, S9P3P2, S9P3P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield migration-core behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.md
- code_roots:
  - .\src
- test_roots:
  - .\tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9000-11-migration-core.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-11-migration-core.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- If no reconciliation artifacts exist for this chunk, treat the chunk as greenfield and begin from the requirements in scope.
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

### Prompt 4

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.md

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

## 9000-12-migration-followup

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S9P4, S9P5, S9P6, S9P6P1, S9P6P2, S9P6P3, S9P7`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield migration follow-up and preferred-address behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.md
- code_roots:
  - .\src
- test_roots:
  - .\tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9000-12-migration-followup.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-12-migration-followup.reconciliation.json
- the repository’s existing conventions for tests, requirement attributes, and direct requirement refs

Rules:
- If no reconciliation artifacts exist for this chunk, treat the chunk as greenfield and begin from the requirements in scope.
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

### Prompt 4

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.md

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

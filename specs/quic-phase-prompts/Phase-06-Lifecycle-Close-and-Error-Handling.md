# Phase 06 — Lifecycle, Close, and Error Handling

Add idle timeout, connection close, stateless reset, and error signaling after the main path is alive.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9000-13-idle-and-close; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield idle-timeout and connection-close behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-13-idle-and-close; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield idle-timeout and connection-close behavior.; Confidence=high}.Mode) — Greenfield idle-timeout and connection-close behavior.
- $(@{ChunkId=9000-14-stateless-reset; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stateless-reset behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-14-stateless-reset; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stateless-reset behavior.; Confidence=high}.Mode) — Greenfield stateless-reset behavior.
- $(@{ChunkId=9000-15-error-handling; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport/application error-handling behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-15-error-handling; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport/application error-handling behavior.; Confidence=high}.Mode) — Greenfield transport/application error-handling behavior.

## 9000-13-idle-and-close

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S10, S10P1, S10P1P1, S10P1P2, S10P2, S10P2P1, S10P2P2, S10P2P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield idle-timeout and connection-close behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-13-idle-and-close.reconciliation.json
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

### Prompt 4

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

## 9000-14-stateless-reset

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S10P3, S10P3P1, S10P3P2, S10P3P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield stateless-reset behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-14-stateless-reset.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-14-stateless-reset.reconciliation.json
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

### Prompt 4

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

## 9000-15-error-handling

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S11, S11P1, S11P2`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield transport/application error-handling behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-15-error-handling.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-15-error-handling.reconciliation.json
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

### Prompt 4

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

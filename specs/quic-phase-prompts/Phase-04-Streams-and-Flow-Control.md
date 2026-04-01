# Phase 04 — Streams and Flow Control

With basic recovery in place, implement stream abstractions, stream state machines, and flow control.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9000-01-streams-core; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-01-streams-core; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.; Confidence=high}.Mode) — Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.
- $(@{ChunkId=9000-02-stream-state; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stream state-machine work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-02-stream-state; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stream state-machine work.; Confidence=high}.Mode) — Greenfield stream state-machine work.
- $(@{ChunkId=9000-03-flow-control; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stream and connection flow-control work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-03-flow-control; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stream and connection flow-control work.; Confidence=high}.Mode) — Greenfield stream and connection flow-control work.

## 9000-01-streams-core

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S2, S2P1, S2P2, S2P3, S2P4`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.

### Prompt 2

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

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-01-streams-core.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-01-streams-core.reconciliation.json
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

### Prompt 4

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

## 9000-02-stream-state

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S3, S3P1, S3P2, S3P3, S3P4, S3P5`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield stream state-machine work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-02-stream-state.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-02-stream-state.reconciliation.json
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

### Prompt 4

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

## 9000-03-flow-control

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S4, S4P1, S4P2, S4P4, S4P5, S4P6`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield stream and connection flow-control work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-03-flow-control.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-03-flow-control.reconciliation.json
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

### Prompt 4

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

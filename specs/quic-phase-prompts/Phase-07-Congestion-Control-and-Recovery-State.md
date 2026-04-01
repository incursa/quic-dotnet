# Phase 07 — Congestion Control and Recovery State

After loss detection exists, add congestion control and then review appendix-driven recovery-state implementation work.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9002-04-congestion-control; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield congestion-control, ECN, and persistent-congestion behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9002-04-congestion-control; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield congestion-control, ECN, and persistent-congestion behavior.; Confidence=high}.Mode) — Greenfield congestion-control, ECN, and persistent-congestion behavior.
- $(@{ChunkId=9002-05-appendix-a-recovery-state; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=REVIEW; Reason=Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.; Confidence=medium}.ChunkId) — mode $(@{ChunkId=9002-05-appendix-a-recovery-state; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=REVIEW; Reason=Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.; Confidence=medium}.Mode) — Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.

## 9002-04-congestion-control

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `S7, S7P1, S7P2, S7P3P1, S7P3P2, S7P3P3, S7P4, S7P5, S7P6, S7P6P1, S7P6P2, S7P7, S7P8`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield congestion-control, ECN, and persistent-congestion behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9002-04-congestion-control.reconciliation.md
- if present: ./specs/generated/quic/chunks/9002-04-congestion-control.reconciliation.json
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

### Prompt 4

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

## 9002-05-appendix-a-recovery-state

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `SAP1, SAP1P1, SAP2, SAP4, SAP5, SAP6, SAP7, SAP8, SAP9, SAP10, SAP11`
- Mode: `REVIEW`
- Confidence: `medium`
- Reason: Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.

This chunk was marked `human_review_first` by the inventory, so it gets a manual-review prompt instead of automatic Prompt 2/3/4 generation.

### Review Prompt

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Perform a focused human-review-style analysis for a selected QUIC appendix chunk before automation.

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

Context:
- Inventory marked this chunk as human_review_first because appendix overlap or appendix promotion risk is present.
- Do not implement broad behavior changes in this run.
- Do not rewrite canonical requirements in this run unless you find a concrete mismatch that must be corrected.

Tasks:
1. Enumerate all requirements in scope.
2. Check whether any requirements in scope are duplicates, near-duplicates, or appendix restatements of already planned implementation work.
3. Identify the minimal implementation-bearing subset that should move forward now.
4. Identify any requirements that should remain deferred until related core runtime work exists.
5. Inventory any existing code or tests that already touch these behaviors.
6. Recommend one of:
   - prompt3_then_prompt4 now
   - defer until a named dependency chunk is complete
   - split this appendix chunk into a smaller executable subset

Write:
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.review.md
- ./specs/generated/quic/chunks/9002-05-appendix-a-recovery-state.review.json

Success criteria:
- The appendix chunk is either cleared for implementation, explicitly deferred, or split into a safer subset.
- No accidental duplicate implementation work is queued.
```

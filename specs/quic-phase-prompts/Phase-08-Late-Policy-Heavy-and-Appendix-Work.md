# Phase 08 — Late, Policy-Heavy, and Appendix Work

Finish the smaller late-policy slices and then review the remaining appendix B material.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9001-02-security-and-registry; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield key-update, security-consideration, and registry behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9001-02-security-and-registry; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield key-update, security-consideration, and registry behavior.; Confidence=high}.Mode) — Greenfield key-update, security-consideration, and registry behavior.
- $(@{ChunkId=9001-03-appendix-b-aead-limits; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield appendix B AEAD limit behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9001-03-appendix-b-aead-limits; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield appendix B AEAD limit behavior.; Confidence=high}.Mode) — Greenfield appendix B AEAD limit behavior.
- $(@{ChunkId=9000-20-datagram-and-mtu; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield datagram-size and PMTU behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-20-datagram-and-mtu; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield datagram-size and PMTU behavior.; Confidence=high}.Mode) — Greenfield datagram-size and PMTU behavior.
- $(@{ChunkId=9000-28-errors-registry-and-security; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield error-code, security, and late-policy material.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-28-errors-registry-and-security; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield error-code, security, and late-policy material.; Confidence=high}.Mode) — Greenfield error-code, security, and late-policy material.
- $(@{ChunkId=9000-29-iana-and-late-sections; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield IANA and late-section work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-29-iana-and-late-sections; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield IANA and late-section work.; Confidence=high}.Mode) — Greenfield IANA and late-section work.
- $(@{ChunkId=9002-06-appendix-b-constants-and-examples; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=REVIEW; Reason=Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.; Confidence=medium}.ChunkId) — mode $(@{ChunkId=9002-06-appendix-b-constants-and-examples; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=REVIEW; Reason=Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.; Confidence=medium}.Mode) — Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.

## 9001-02-security-and-registry

- RFC: `9001`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9001.json`
- Section tokens: `S6, S7, S8, S9, S10`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield key-update, security-consideration, and registry behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9001-02-security-and-registry
- rfc: 9001
- section_tokens:
  - S6
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
- if present: ./specs/generated/quic/chunks/9001-02-security-and-registry.reconciliation.md
- if present: ./specs/generated/quic/chunks/9001-02-security-and-registry.reconciliation.json
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

### Prompt 4

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9001-02-security-and-registry
- rfc: 9001
- section_tokens:
  - S6
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

## 9001-03-appendix-b-aead-limits

- RFC: `9001`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9001.json`
- Section tokens: `SB, SBP1P1, SBP1P2, SBP2`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield appendix B AEAD limit behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.reconciliation.md
- if present: ./specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.reconciliation.json
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

### Prompt 4

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

## 9000-20-datagram-and-mtu

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S13P4, S13P4P1, S13P4P2, S13P4P2P1, S13P4P2P2, S14, S14P1, S14P2, S14P2P1, S14P3, S14P4`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield datagram-size and PMTU behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-20-datagram-and-mtu.reconciliation.json
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

### Prompt 4

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

## 9000-28-errors-registry-and-security

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S19P19, S19P20, S19P21, S20P1, S20P2, S21P1P1P1, S21P2, S21P3, S21P4, S21P5, S21P5P3, S21P5P6, S21P6, S21P7, S21P9, S21P10, S21P11, S21P12`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield error-code, security, and late-policy material.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-28-errors-registry-and-security.reconciliation.json
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

### Prompt 4

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

## 9000-29-iana-and-late-sections

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S22P1P1, S22P1P2, S22P1P3, S22P1P4, S22P2, S22P3, S22P4, S22P5`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield IANA and late-section work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-29-iana-and-late-sections.reconciliation.json
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

### Prompt 4

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

## 9002-06-appendix-b-constants-and-examples

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `SBP1, SBP2, SBP3, SBP4, SBP5, SBP6, SBP7, SBP8, SBP9`
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
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.review.md
- ./specs/generated/quic/chunks/9002-06-appendix-b-constants-and-examples.review.json

Success criteria:
- The appendix chunk is either cleared for implementation, explicitly deferred, or split into a safer subset.
- No accidental duplicate implementation work is queued.
```

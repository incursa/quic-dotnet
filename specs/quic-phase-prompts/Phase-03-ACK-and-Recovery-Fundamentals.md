# Phase 03 — ACK and Recovery Fundamentals

Once the handshake path exists, add acknowledgment generation, retransmission rules, RTT estimation, and loss detection so the connection can make forward progress reliably.

Code roots used in generated prompts:
- .\src

Test roots used in generated prompts:
- .\tests

## Chunk Order

- $(@{ChunkId=9000-18-ack-generation; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield ACK-generation behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-18-ack-generation; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield ACK-generation behavior.; Confidence=high}.Mode) — Greenfield ACK-generation behavior.
- $(@{ChunkId=9000-19-retransmission-and-frame-reliability; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield retransmission/frame-reliability work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-19-retransmission-and-frame-reliability; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield retransmission/frame-reliability work.; Confidence=high}.Mode) — Greenfield retransmission/frame-reliability work.
- $(@{ChunkId=9002-01-transport-basics; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9002-01-transport-basics; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.; Confidence=high}.Mode) — Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.
- $(@{ChunkId=9002-02-rtt-estimation; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield RTT-estimation behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9002-02-rtt-estimation; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield RTT-estimation behavior.; Confidence=high}.Mode) — Greenfield RTT-estimation behavior.
- $(@{ChunkId=9002-03-loss-detection; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield loss detection and PTO behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9002-03-loss-detection; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield loss detection and PTO behavior.; Confidence=high}.Mode) — Greenfield loss detection and PTO behavior.

## 9000-18-ack-generation

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S13, S13P1, S13P2, S13P2P1, S13P2P2, S13P2P3, S13P2P4, S13P2P5, S13P2P6, S13P2P7`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield ACK-generation behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.md
- code_roots:
  - .\src
- test_roots:
  - .\tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9000-18-ack-generation.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-18-ack-generation.reconciliation.json
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

### Prompt 4

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.md

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

## 9000-19-retransmission-and-frame-reliability

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S13P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield retransmission/frame-reliability work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-19-retransmission-and-frame-reliability
- rfc: 9000
- section_tokens:
  - S13P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.md
- code_roots:
  - .\src
- test_roots:
  - .\tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.reconciliation.json
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

### Prompt 4

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-19-retransmission-and-frame-reliability
- rfc: 9000
- section_tokens:
  - S13P3
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.md

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

## 9002-01-transport-basics

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.md`
- Section tokens: `S2, S3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.md
- code_roots:
  - .\src
- test_roots:
  - .\tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9002-01-transport-basics.reconciliation.md
- if present: ./specs/generated/quic/chunks/9002-01-transport-basics.reconciliation.json
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

### Prompt 4

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.md

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

## 9002-02-rtt-estimation

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.md`
- Section tokens: `S5, S5P1, S5P2, S5P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield RTT-estimation behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.md
- code_roots:
  - .\src
- test_roots:
  - .\tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9002-02-rtt-estimation.reconciliation.md
- if present: ./specs/generated/quic/chunks/9002-02-rtt-estimation.reconciliation.json
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

### Prompt 4

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.md

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

## 9002-03-loss-detection

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.md`
- Section tokens: `S6, S6P1, S6P1P1, S6P1P2, S6P2, S6P2P1, S6P2P2, S6P2P2P1, S6P2P3, S6P2P4, S6P3, S6P4`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield loss detection and PTO behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.md
- code_roots:
  - .\src
- test_roots:
  - .\tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9002-03-loss-detection.reconciliation.md
- if present: ./specs/generated/quic/chunks/9002-03-loss-detection.reconciliation.json
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

### Prompt 4

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9002.md

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

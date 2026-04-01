# Phase 01 — Foundation — Wire Format and Packet/Frame Substrate

Start here. RFC 8999 invariants are already complete, so this phase begins with the remaining transport substrate and frame/header work that other phases depend on.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=8999-01-invariants; Rfc=8999; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC8999.json; SectionTokens=System.String[]; Mode=SKIP; Reason=Already implemented, tested, fuzzed, benchmarked, and closed out.; Confidence=high}.ChunkId) — mode $(@{ChunkId=8999-01-invariants; Rfc=8999; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC8999.json; SectionTokens=System.String[]; Mode=SKIP; Reason=Already implemented, tested, fuzzed, benchmarked, and closed out.; Confidence=high}.Mode) — Already implemented, tested, fuzzed, benchmarked, and closed out.
- $(@{ChunkId=9000-21-long-header-general-and-initial; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Packet-header wire format and varint-related work already exists and carries stale VINT IDs.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-21-long-header-general-and-initial; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Packet-header wire format and varint-related work already exists and carries stale VINT IDs.; Confidence=high}.Mode) — Packet-header wire format and varint-related work already exists and carries stale VINT IDs.
- $(@{ChunkId=9000-22-long-header-handshake-and-0rtt; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-22-long-header-handshake-and-0rtt; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.; Confidence=high}.Mode) — Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.
- $(@{ChunkId=9000-23-retry-version-short-header; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.; Confidence=medium}.ChunkId) — mode $(@{ChunkId=9000-23-retry-version-short-header; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.; Confidence=medium}.Mode) — Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.
- $(@{ChunkId=9000-24-frame-encodings-part-1; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport-parameter, PADDING, PING, and ACK frame work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-24-frame-encodings-part-1; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport-parameter, PADDING, PING, and ACK frame work.; Confidence=high}.Mode) — Greenfield transport-parameter, PADDING, PING, and ACK frame work.
- $(@{ChunkId=9000-25-frame-encodings-part-2; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-25-frame-encodings-part-2; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.; Confidence=high}.Mode) — This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.
- $(@{ChunkId=9000-26-frame-encodings-part-3; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-26-frame-encodings-part-3; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.; Confidence=high}.Mode) — This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.
- $(@{ChunkId=9000-27-frame-encodings-part-4; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield frame-encoding work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-27-frame-encodings-part-4; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield frame-encoding work.; Confidence=high}.Mode) — Greenfield frame-encoding work.

## 8999-01-invariants

- RFC: `8999`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC8999.json`
- Section tokens: `S5P1`
- Mode: `SKIP`
- Confidence: `high`
- Reason: Already implemented, tested, fuzzed, benchmarked, and closed out.

This chunk is already complete and is included here only to preserve phase order.

## 9000-21-long-header-general-and-initial

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S17, S17P1, S17P2`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: Packet-header wire format and varint-related work already exists and carries stale VINT IDs.

### Prompt 2

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

### Prompt 3

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
- spec_file: ./specs/requirements/quic/SPEC-QUIC-RFC9000.json
- code_roots:
  - ./src
- test_roots:
  - ./tests

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-21-long-header-general-and-initial.reconciliation.json
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

### Prompt 4

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

## 9000-22-long-header-handshake-and-0rtt

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S17P2P1, S17P2P2, S17P2P3`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.

### Prompt 2

```text
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: 9000-22-long-header-handshake-and-0rtt
- rfc: 9000
- section_tokens:
  - S17P2P1
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

### Prompt 3

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: 9000-22-long-header-handshake-and-0rtt
- rfc: 9000
- section_tokens:
  - S17P2P1
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
- if present: ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-22-long-header-handshake-and-0rtt.reconciliation.json
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

### Prompt 4

```text
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: 9000-22-long-header-handshake-and-0rtt
- rfc: 9000
- section_tokens:
  - S17P2P1
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

## 9000-23-retry-version-short-header

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S17P2P4, S17P2P5, S17P2P5P1, S17P2P5P2, S17P2P5P3, S17P3, S17P3P1, S17P4`
- Mode: `P2P3P4`
- Confidence: `medium`
- Reason: Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.

### Prompt 2

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

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-23-retry-version-short-header.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-23-retry-version-short-header.reconciliation.json
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

### Prompt 4

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

## 9000-24-frame-encodings-part-1

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S18, S18P1, S18P2`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield transport-parameter, PADDING, PING, and ACK frame work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-24-frame-encodings-part-1.reconciliation.json
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

### Prompt 4

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

## 9000-25-frame-encodings-part-2

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S19P1, S19P2, S19P3, S19P3P1, S19P3P2, S19P4, S19P5`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.

### Prompt 2

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

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-25-frame-encodings-part-2.reconciliation.json
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

### Prompt 4

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

## 9000-26-frame-encodings-part-3

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S19P6, S19P7, S19P8, S19P9, S19P10, S19P11`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.

### Prompt 2

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

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-26-frame-encodings-part-3.reconciliation.json
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

### Prompt 4

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

## 9000-27-frame-encodings-part-4

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S19P12, S19P13, S19P14, S19P15, S19P16, S19P17, S19P18`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield frame-encoding work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

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
- if present: ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.reconciliation.md
- if present: ./specs/generated/quic/chunks/9000-27-frame-encodings-part-4.reconciliation.json
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

### Prompt 4

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

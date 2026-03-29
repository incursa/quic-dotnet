param(
    [string]$OutputDir = ".\quic-phase-prompts",
    [string[]]$CodeRoots = @("./src"),
    [string[]]$TestRoots = @("./tests"),
    [string[]]$PhaseIds = @(),
    [switch]$IncludeManualReview = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Chunk {
    param(
        [string]$ChunkId,
        [string]$Rfc,
        [string]$SpecFile,
        [string[]]$SectionTokens,
        [ValidateSet('P2P3P4','P3P4','REVIEW','SKIP')]
        [string]$Mode,
        [string]$Reason = '',
        [string]$Confidence = 'high'
    )

    [pscustomobject]@{
        ChunkId       = $ChunkId
        Rfc           = $Rfc
        SpecFile      = $SpecFile
        SectionTokens = $SectionTokens
        Mode          = $Mode
        Reason        = $Reason
        Confidence    = $Confidence
    }
}

function New-Phase {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Summary,
        [object[]]$Chunks
    )

    [pscustomobject]@{
        Id      = $Id
        Title   = $Title
        Summary = $Summary
        Chunks  = $Chunks
    }
}

function Format-Bullets {
    param(
        [string[]]$Items,
        [string]$Indent = ''
    )

    if (-not $Items -or $Items.Count -eq 0) {
        return "$Indent- none"
    }

    return (($Items | ForEach-Object { "$Indent- $_" }) -join [Environment]::NewLine)
}

function Format-ListInline {
    param([string[]]$Items)
    if (-not $Items -or $Items.Count -eq 0) { return '' }
    return ($Items -join ', ')
}

function Render-Header {
    param($Phase)

@"
# $($Phase.Id) — $($Phase.Title)

$($Phase.Summary)

Code roots used in generated prompts:
$(Format-Bullets -Items $CodeRoots)

Test roots used in generated prompts:
$(Format-Bullets -Items $TestRoots)

"@
}

$Prompt2Template = @'
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: {{CHUNK_ID}}
- rfc: {{RFC_ID}}
- section_tokens:
{{SECTION_TOKENS}}
- spec_file: {{SPEC_FILE}}
- code_roots:
{{CODE_ROOTS}}
- test_roots:
{{TEST_ROOTS}}

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
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.reconciliation.md
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.reconciliation.json

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
'@

$Prompt3Template = @'
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: {{CHUNK_ID}}
- rfc: {{RFC_ID}}
- section_tokens:
{{SECTION_TOKENS}}
- spec_file: {{SPEC_FILE}}
- code_roots:
{{CODE_ROOTS}}
- test_roots:
{{TEST_ROOTS}}

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- if present: ./specs/generated/quic/chunks/{{CHUNK_ID}}.reconciliation.md
- if present: ./specs/generated/quic/chunks/{{CHUNK_ID}}.reconciliation.json
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
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.implementation-summary.md
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.implementation-summary.json

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
'@

$Prompt4Template = @'
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: {{CHUNK_ID}}
- rfc: {{RFC_ID}}
- section_tokens:
{{SECTION_TOKENS}}
- spec_file: {{SPEC_FILE}}

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.reconciliation.json
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.implementation-summary.json

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
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.closeout.md
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
'@

$ReviewTemplate = @'
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Perform a focused human-review-style analysis for a selected QUIC appendix chunk before automation.

Scope:
- chunk_id: {{CHUNK_ID}}
- rfc: {{RFC_ID}}
- section_tokens:
{{SECTION_TOKENS}}
- spec_file: {{SPEC_FILE}}
- code_roots:
{{CODE_ROOTS}}
- test_roots:
{{TEST_ROOTS}}

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
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.review.md
- ./specs/generated/quic/chunks/{{CHUNK_ID}}.review.json

Success criteria:
- The appendix chunk is either cleared for implementation, explicitly deferred, or split into a safer subset.
- No accidental duplicate implementation work is queued.
'@

function Render-Prompt {
    param(
        [string]$Template,
        $Chunk
    )

    $sectionBullets = Format-Bullets -Items $Chunk.SectionTokens -Indent '  '
    $codeBullets    = Format-Bullets -Items $CodeRoots -Indent '  '
    $testBullets    = Format-Bullets -Items $TestRoots -Indent '  '

    return $Template.
        Replace('{{CHUNK_ID}}', $Chunk.ChunkId).
        Replace('{{RFC_ID}}', $Chunk.Rfc).
        Replace('{{SPEC_FILE}}', $Chunk.SpecFile).
        Replace('{{SECTION_TOKENS}}', $sectionBullets).
        Replace('{{CODE_ROOTS}}', $codeBullets).
        Replace('{{TEST_ROOTS}}', $testBullets)
}

$Phases = @(
    (New-Phase -Id 'Phase 01' -Title 'Foundation — Wire Format and Packet/Frame Substrate' -Summary 'Start here. RFC 8999 invariants are already complete, so this phase begins with the remaining transport substrate and frame/header work that other phases depend on.' -Chunks @(
        (New-Chunk -ChunkId '8999-01-invariants' -Rfc '8999' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC8999.md' -SectionTokens @('S5P1') -Mode 'SKIP' -Reason 'Already implemented, tested, fuzzed, benchmarked, and closed out.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-21-long-header-general-and-initial' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S17','S17P1','S17P2') -Mode 'P2P3P4' -Reason 'Packet-header wire format and varint-related work already exists and carries stale VINT IDs.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-22-long-header-handshake-and-0rtt' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S17P2P1','S17P2P2','S17P2P3') -Mode 'P2P3P4' -Reason 'Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-23-retry-version-short-header' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S17P2P4','S17P2P5','S17P2P5P1','S17P2P5P2','S17P2P5P3','S17P3','S17P3P1','S17P4') -Mode 'P2P3P4' -Reason 'Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.' -Confidence 'medium'),
        (New-Chunk -ChunkId '9000-24-frame-encodings-part-1' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S18','S18P1','S18P2') -Mode 'P3P4' -Reason 'Greenfield transport-parameter, PADDING, PING, and ACK frame work.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-25-frame-encodings-part-2' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S19P1','S19P2','S19P3','S19P3P1','S19P3P2','S19P4','S19P5') -Mode 'P2P3P4' -Reason 'This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-26-frame-encodings-part-3' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S19P6','S19P7','S19P8','S19P9','S19P10','S19P11') -Mode 'P2P3P4' -Reason 'This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-27-frame-encodings-part-4' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S19P12','S19P13','S19P14','S19P15','S19P16','S19P17','S19P18') -Mode 'P3P4' -Reason 'Greenfield frame-encoding work.' -Confidence 'high')
    )),
    (New-Phase -Id 'Phase 02' -Title 'Connection Establishment and Crypto Bootstrap' -Summary 'After the wire substrate is in place, build connection establishment, CID policy, version negotiation behavior, TLS carriage, transport parameters, and address/path validation.' -Chunks @(
        (New-Chunk -ChunkId '9000-04-connection-ids-basics' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S5','S5P1','S5P1P1') -Mode 'P2P3P4' -Reason 'Existing packet-classification and Version Negotiation parser/tests already exist, so CID basics should reconcile first.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-05-connection-id-management' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S5P1P2','S5P2','S5P2P1','S5P2P2','S5P2P3') -Mode 'P2P3P4' -Reason 'Connection-ID management builds on existing packet parsing and CID-related logic.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-06-version-negotiation' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S6','S6P1','S6P2','S6P3') -Mode 'P3P4' -Reason 'Greenfield Version Negotiation behavior layered on top of existing header parsing.' -Confidence 'high'),
        (New-Chunk -ChunkId '9001-01-tls-core' -Rfc '9001' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9001.md' -SectionTokens @('S2','S3','S4','S5') -Mode 'P3P4' -Reason 'Greenfield QUIC TLS and packet-protection core.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-07-handshake-properties' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S7','S7P2','S7P3') -Mode 'P3P4' -Reason 'Greenfield cryptographic handshake and connection-ID authentication semantics.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-08-transport-params-and-crypto-buffers' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S7P4','S7P4P1','S7P4P2','S7P5') -Mode 'P3P4' -Reason 'Greenfield transport-parameter and CRYPTO buffering behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-09-address-validation-and-tokens' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S8','S8P1','S8P1P1','S8P1P2','S8P1P3','S8P1P4') -Mode 'P3P4' -Reason 'Greenfield address-validation token and amplification-limit behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-10-path-validation' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S8P2','S8P2P1','S8P2P2','S8P2P3','S8P2P4') -Mode 'P3P4' -Reason 'Greenfield path-challenge/response behavior.' -Confidence 'high')
    )),
    (New-Phase -Id 'Phase 03' -Title 'ACK and Recovery Fundamentals' -Summary 'Once the handshake path exists, add acknowledgment generation, retransmission rules, RTT estimation, and loss detection so the connection can make forward progress reliably.' -Chunks @(
        (New-Chunk -ChunkId '9000-18-ack-generation' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S13','S13P1','S13P2','S13P2P1','S13P2P2','S13P2P3','S13P2P4','S13P2P5','S13P2P6','S13P2P7') -Mode 'P3P4' -Reason 'Greenfield ACK-generation behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-19-retransmission-and-frame-reliability' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S13P3') -Mode 'P3P4' -Reason 'Greenfield retransmission/frame-reliability work.' -Confidence 'high'),
        (New-Chunk -ChunkId '9002-01-transport-basics' -Rfc '9002' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9002.md' -SectionTokens @('S2','S3') -Mode 'P3P4' -Reason 'Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.' -Confidence 'high'),
        (New-Chunk -ChunkId '9002-02-rtt-estimation' -Rfc '9002' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9002.md' -SectionTokens @('S5','S5P1','S5P2','S5P3') -Mode 'P3P4' -Reason 'Greenfield RTT-estimation behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9002-03-loss-detection' -Rfc '9002' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9002.md' -SectionTokens @('S6','S6P1','S6P1P1','S6P1P2','S6P2','S6P2P1','S6P2P2','S6P2P2P1','S6P2P3','S6P2P4','S6P3','S6P4') -Mode 'P3P4' -Reason 'Greenfield loss detection and PTO behavior.' -Confidence 'high')
    )),
    (New-Phase -Id 'Phase 04' -Title 'Streams and Flow Control' -Summary 'With basic recovery in place, implement stream abstractions, stream state machines, and flow control.' -Chunks @(
        (New-Chunk -ChunkId '9000-01-streams-core' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S2','S2P1','S2P2','S2P3','S2P4') -Mode 'P2P3P4' -Reason 'Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-02-stream-state' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S3','S3P1','S3P2','S3P3','S3P4','S3P5') -Mode 'P3P4' -Reason 'Greenfield stream state-machine work.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-03-flow-control' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S4','S4P1','S4P2','S4P4','S4P5','S4P6') -Mode 'P3P4' -Reason 'Greenfield stream and connection flow-control work.' -Confidence 'high')
    )),
    (New-Phase -Id 'Phase 05' -Title 'Migration and Path Management' -Summary 'Once streams, ACK, and validation exist, implement migration and path-management behavior.' -Chunks @(
        (New-Chunk -ChunkId '9000-11-migration-core' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S9','S9P1','S9P2','S9P3','S9P3P1','S9P3P2','S9P3P3') -Mode 'P3P4' -Reason 'Greenfield migration-core behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-12-migration-followup' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S9P4','S9P5','S9P6','S9P6P1','S9P6P2','S9P6P3','S9P7') -Mode 'P3P4' -Reason 'Greenfield migration follow-up and preferred-address behavior.' -Confidence 'high')
    )),
    (New-Phase -Id 'Phase 06' -Title 'Lifecycle, Close, and Error Handling' -Summary 'Add idle timeout, connection close, stateless reset, and error signaling after the main path is alive.' -Chunks @(
        (New-Chunk -ChunkId '9000-13-idle-and-close' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S10','S10P1','S10P1P1','S10P1P2','S10P2','S10P2P1','S10P2P2','S10P2P3') -Mode 'P3P4' -Reason 'Greenfield idle-timeout and connection-close behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-14-stateless-reset' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S10P3','S10P3P1','S10P3P2','S10P3P3') -Mode 'P3P4' -Reason 'Greenfield stateless-reset behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-15-error-handling' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S11','S11P1','S11P2') -Mode 'P3P4' -Reason 'Greenfield transport/application error-handling behavior.' -Confidence 'high')
    )),
    (New-Phase -Id 'Phase 07' -Title 'Congestion Control and Recovery State' -Summary 'After loss detection exists, add congestion control and then review appendix-driven recovery-state implementation work.' -Chunks @(
        (New-Chunk -ChunkId '9002-04-congestion-control' -Rfc '9002' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9002.md' -SectionTokens @('S7','S7P1','S7P2','S7P3P1','S7P3P2','S7P3P3','S7P4','S7P5','S7P6','S7P6P1','S7P6P2','S7P7','S7P8') -Mode 'P3P4' -Reason 'Greenfield congestion-control, ECN, and persistent-congestion behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9002-05-appendix-a-recovery-state' -Rfc '9002' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9002.md' -SectionTokens @('SAP1','SAP1P1','SAP2','SAP4','SAP5','SAP6','SAP7','SAP8','SAP9','SAP10','SAP11') -Mode 'REVIEW' -Reason 'Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.' -Confidence 'medium')
    )),
    (New-Phase -Id 'Phase 08' -Title 'Late, Policy-Heavy, and Appendix Work' -Summary 'Finish the smaller late-policy slices and then review the remaining appendix B material.' -Chunks @(
        (New-Chunk -ChunkId '9001-02-security-and-registry' -Rfc '9001' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9001.md' -SectionTokens @('S6','S7','S8','S9','S10') -Mode 'P3P4' -Reason 'Greenfield key-update, security-consideration, and registry behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9001-03-appendix-b-aead-limits' -Rfc '9001' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9001.md' -SectionTokens @('SB','SBP1P1','SBP1P2','SBP2') -Mode 'P3P4' -Reason 'Greenfield appendix B AEAD limit behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-20-datagram-and-mtu' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S13P4','S13P4P1','S13P4P2','S13P4P2P1','S13P4P2P2','S14','S14P1','S14P2','S14P2P1','S14P3','S14P4') -Mode 'P3P4' -Reason 'Greenfield datagram-size and PMTU behavior.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-28-errors-registry-and-security' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S19P19','S19P20','S19P21','S20P1','S20P2','S21P1P1P1','S21P2','S21P3','S21P4','S21P5','S21P5P3','S21P5P6','S21P6','S21P7','S21P9','S21P10','S21P11','S21P12') -Mode 'P3P4' -Reason 'Greenfield error-code, security, and late-policy material.' -Confidence 'high'),
        (New-Chunk -ChunkId '9000-29-iana-and-late-sections' -Rfc '9000' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9000.md' -SectionTokens @('S22P1P1','S22P1P2','S22P1P3','S22P1P4','S22P2','S22P3','S22P4','S22P5') -Mode 'P3P4' -Reason 'Greenfield IANA and late-section work.' -Confidence 'high'),
        (New-Chunk -ChunkId '9002-06-appendix-b-constants-and-examples' -Rfc '9002' -SpecFile './specs/requirements/quic/SPEC-QUIC-RFC9002.md' -SectionTokens @('SBP1','SBP2','SBP3','SBP4','SBP5','SBP6','SBP7','SBP8','SBP9') -Mode 'REVIEW' -Reason 'Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.' -Confidence 'medium')
    ))
)

if ($PhaseIds -and $PhaseIds.Count -gt 0) {
    $Phases = $Phases | Where-Object { $PhaseIds -contains $_.Id }
}

if (-not $IncludeManualReview) {
    foreach ($phase in $Phases) {
        $phase.Chunks = @($phase.Chunks | Where-Object { $_.Mode -ne 'REVIEW' })
    }
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$indexPath = Join-Path $OutputDir 'README.md'
$indexLines = New-Object System.Collections.Generic.List[string]
$indexLines.Add('# QUIC Phased Prompt Queue')
$indexLines.Add('')
$indexLines.Add('This directory contains one markdown file per implementation phase. The phases follow dependency order and use the repository inventory to decide whether a chunk needs reconciliation (`Prompt 2`), implementation (`Prompt 3`), closeout (`Prompt 4`), or manual review.')
$indexLines.Add('')
$indexLines.Add('Generated with `generate-quic-phase-prompts.ps1`.')
$indexLines.Add('')

foreach ($phase in $Phases) {
    $safeName = ($phase.Id -replace '\s+', '-') + '-' + (($phase.Title -replace '[^A-Za-z0-9]+','-').Trim('-'))
    $phaseFile = Join-Path $OutputDir ($safeName + '.md')

    $content = New-Object System.Collections.Generic.List[string]
    $content.Add((Render-Header -Phase $phase).TrimEnd())
    $content.Add('')
    $content.Add('## Chunk Order')
    $content.Add('')
    foreach ($chunk in $phase.Chunks) {
        $content.Add("- `$($chunk.ChunkId)` — mode `$($chunk.Mode)` — $($chunk.Reason)")
    }
    $content.Add('')

    foreach ($chunk in $phase.Chunks) {
        $content.Add("## $($chunk.ChunkId)")
        $content.Add('')
        $content.Add("- RFC: ``$($chunk.Rfc)``")
        $content.Add("- Spec file: ``$($chunk.SpecFile)``")
        $content.Add("- Section tokens: ``" + (Format-ListInline -Items $chunk.SectionTokens) + "``")
        $content.Add("- Mode: ``$($chunk.Mode)``")
        $content.Add("- Confidence: ``$($chunk.Confidence)``")
        $content.Add("- Reason: $($chunk.Reason)")
        $content.Add('')

        switch ($chunk.Mode) {
            'SKIP' {
                $content.Add('This chunk is already complete and is included here only to preserve phase order.')
                $content.Add('')
            }
            'P2P3P4' {
                $content.Add('### Prompt 2')
                $content.Add('')
                $content.Add('```text')
                $content.Add((Render-Prompt -Template $Prompt2Template -Chunk $chunk).TrimEnd())
                $content.Add('```')
                $content.Add('')
                $content.Add('### Prompt 3')
                $content.Add('')
                $content.Add('```text')
                $content.Add((Render-Prompt -Template $Prompt3Template -Chunk $chunk).TrimEnd())
                $content.Add('```')
                $content.Add('')
                $content.Add('### Prompt 4')
                $content.Add('')
                $content.Add('```text')
                $content.Add((Render-Prompt -Template $Prompt4Template -Chunk $chunk).TrimEnd())
                $content.Add('```')
                $content.Add('')
            }
            'P3P4' {
                $content.Add('Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.')
                $content.Add('')
                $content.Add('### Prompt 3')
                $content.Add('')
                $content.Add('```text')
                $content.Add((Render-Prompt -Template $Prompt3Template -Chunk $chunk).TrimEnd())
                $content.Add('```')
                $content.Add('')
                $content.Add('### Prompt 4')
                $content.Add('')
                $content.Add('```text')
                $content.Add((Render-Prompt -Template $Prompt4Template -Chunk $chunk).TrimEnd())
                $content.Add('```')
                $content.Add('')
            }
            'REVIEW' {
                $content.Add('This chunk was marked `human_review_first` by the inventory, so it gets a manual-review prompt instead of automatic Prompt 2/3/4 generation.')
                $content.Add('')
                $content.Add('### Review Prompt')
                $content.Add('')
                $content.Add('```text')
                $content.Add((Render-Prompt -Template $ReviewTemplate -Chunk $chunk).TrimEnd())
                $content.Add('```')
                $content.Add('')
            }
        }
    }

    $contentText = ($content -join [Environment]::NewLine)
    Set-Content -Path $phaseFile -Value $contentText -Encoding UTF8

    $indexLines.Add("- [$($phase.Id) — $($phase.Title)]($(Split-Path -Leaf $phaseFile))")
}

Set-Content -Path $indexPath -Value ($indexLines -join [Environment]::NewLine) -Encoding UTF8

Write-Host "Generated $($Phases.Count) phase file(s) under $OutputDir"

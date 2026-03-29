param(
    [string]$OutputPath = "./generated-quic-codex-prompts.md",
    [string[]]$CodeRoots = @("./src"),
    [string[]]$TestRoots = @("./tests"),
    [string[]]$ChunkIds,
    [switch]$EmitSeparateFiles,
    [string]$SeparateOutputDir = "./generated-quic-codex-prompts"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-ToBulletBlock {
    param([string[]]$Items)
    if (-not $Items -or $Items.Count -eq 0) {
        return "  - <none>"
    }
    return ($Items | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
}

function Expand-Template {
    param(
        [string]$Template,
        [pscustomobject]$Chunk,
        [string[]]$CodeRoots,
        [string[]]$TestRoots
    )

    $result = $Template
    $result = $result.Replace("{{chunk_id}}", $Chunk.chunk_id)
    $result = $result.Replace("{{rfc}}", $Chunk.rfc)
    $result = $result.Replace("{{spec_file}}", $Chunk.spec_file)
    $result = $result.Replace("{{section_tokens_block}}", (Convert-ToBulletBlock -Items $Chunk.section_tokens))
    $result = $result.Replace("{{code_roots_block}}", (Convert-ToBulletBlock -Items $CodeRoots))
    $result = $result.Replace("{{test_roots_block}}", (Convert-ToBulletBlock -Items $TestRoots))
    return $result
}

$chunks = @'
[
  {
    "chunk_id": "8999-01-invariants",
    "rfc": "8999",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC8999.md",
    "approx_requirements": 8,
    "section_tokens": [
      "S5P1"
    ]
  },
  {
    "chunk_id": "9001-01-tls-core",
    "rfc": "9001",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9001.md",
    "approx_requirements": 44,
    "section_tokens": [
      "S2",
      "S3",
      "S4",
      "S5",
      "S6"
    ]
  },
  {
    "chunk_id": "9001-02-security-and-registry",
    "rfc": "9001",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9001.md",
    "approx_requirements": 8,
    "section_tokens": [
      "S7",
      "S8",
      "S9",
      "S10"
    ]
  },
  {
    "chunk_id": "9001-03-appendix-b-aead-limits",
    "rfc": "9001",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9001.md",
    "approx_requirements": 9,
    "section_tokens": [
      "SB",
      "SBP1P1",
      "SBP1P2",
      "SBP2"
    ]
  },
  {
    "chunk_id": "9002-01-transport-basics",
    "rfc": "9002",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9002.md",
    "approx_requirements": 21,
    "section_tokens": [
      "S2",
      "S3"
    ]
  },
  {
    "chunk_id": "9002-02-rtt-estimation",
    "rfc": "9002",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9002.md",
    "approx_requirements": 25,
    "section_tokens": [
      "S5",
      "S5P1",
      "S5P2",
      "S5P3"
    ]
  },
  {
    "chunk_id": "9002-03-loss-detection",
    "rfc": "9002",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9002.md",
    "approx_requirements": 55,
    "section_tokens": [
      "S6",
      "S6P1",
      "S6P1P1",
      "S6P1P2",
      "S6P2",
      "S6P2P1",
      "S6P2P2",
      "S6P2P2P1",
      "S6P2P3",
      "S6P2P4",
      "S6P3",
      "S6P4"
    ]
  },
  {
    "chunk_id": "9002-04-congestion-control",
    "rfc": "9002",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9002.md",
    "approx_requirements": 46,
    "section_tokens": [
      "S7",
      "S7P1",
      "S7P2",
      "S7P3P1",
      "S7P3P2",
      "S7P3P3",
      "S7P4",
      "S7P5",
      "S7P6",
      "S7P6P1",
      "S7P6P2",
      "S7P7",
      "S7P8"
    ]
  },
  {
    "chunk_id": "9002-05-appendix-a-recovery-state",
    "rfc": "9002",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9002.md",
    "approx_requirements": 49,
    "section_tokens": [
      "SAP1",
      "SAP1P1",
      "SAP2",
      "SAP4",
      "SAP5",
      "SAP6",
      "SAP7",
      "SAP8",
      "SAP9",
      "SAP10",
      "SAP11"
    ]
  },
  {
    "chunk_id": "9002-06-appendix-b-constants-and-examples",
    "rfc": "9002",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9002.md",
    "approx_requirements": 28,
    "section_tokens": [
      "SBP1",
      "SBP2",
      "SBP3",
      "SBP4",
      "SBP5",
      "SBP6",
      "SBP7",
      "SBP8",
      "SBP9"
    ]
  },
  {
    "chunk_id": "9000-01-streams-core",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 44,
    "section_tokens": [
      "S2",
      "S2P1",
      "S2P2",
      "S2P3",
      "S2P4"
    ]
  },
  {
    "chunk_id": "9000-02-stream-state",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 66,
    "section_tokens": [
      "S3",
      "S3P1",
      "S3P2",
      "S3P3",
      "S3P4",
      "S3P5"
    ]
  },
  {
    "chunk_id": "9000-03-flow-control",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 50,
    "section_tokens": [
      "S4",
      "S4P1",
      "S4P2",
      "S4P4",
      "S4P5",
      "S4P6"
    ]
  },
  {
    "chunk_id": "9000-04-connection-ids-basics",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 44,
    "section_tokens": [
      "S5",
      "S5P1",
      "S5P1P1"
    ]
  },
  {
    "chunk_id": "9000-05-connection-id-management",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 61,
    "section_tokens": [
      "S5P1P2",
      "S5P2",
      "S5P2P1",
      "S5P2P2",
      "S5P2P3",
      "S5P3"
    ]
  },
  {
    "chunk_id": "9000-06-version-negotiation",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 11,
    "section_tokens": [
      "S6",
      "S6P1",
      "S6P2",
      "S6P3"
    ]
  },
  {
    "chunk_id": "9000-07-handshake-properties",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 34,
    "section_tokens": [
      "S7",
      "S7P2",
      "S7P3"
    ]
  },
  {
    "chunk_id": "9000-08-transport-params-and-crypto-buffers",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 22,
    "section_tokens": [
      "S7P4",
      "S7P4P1",
      "S7P4P2",
      "S7P5"
    ]
  },
  {
    "chunk_id": "9000-09-address-validation-and-tokens",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 42,
    "section_tokens": [
      "S8",
      "S8P1",
      "S8P1P1",
      "S8P1P2",
      "S8P1P3",
      "S8P1P4"
    ]
  },
  {
    "chunk_id": "9000-10-path-validation",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 21,
    "section_tokens": [
      "S8P2",
      "S8P2P1",
      "S8P2P2",
      "S8P2P3",
      "S8P2P4"
    ]
  },
  {
    "chunk_id": "9000-11-migration-core",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 40,
    "section_tokens": [
      "S9",
      "S9P1",
      "S9P2",
      "S9P3",
      "S9P3P1",
      "S9P3P2",
      "S9P3P3"
    ]
  },
  {
    "chunk_id": "9000-12-migration-followup",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 61,
    "section_tokens": [
      "S9P4",
      "S9P5",
      "S9P6",
      "S9P6P1",
      "S9P6P2",
      "S9P6P3",
      "S9P7"
    ]
  },
  {
    "chunk_id": "9000-13-idle-and-close",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 52,
    "section_tokens": [
      "S10",
      "S10P1",
      "S10P1P1",
      "S10P1P2",
      "S10P2",
      "S10P2P1",
      "S10P2P2",
      "S10P2P3"
    ]
  },
  {
    "chunk_id": "9000-14-stateless-reset",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 55,
    "section_tokens": [
      "S10P3",
      "S10P3P1",
      "S10P3P2",
      "S10P3P3"
    ]
  },
  {
    "chunk_id": "9000-15-error-handling",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 18,
    "section_tokens": [
      "S11",
      "S11P1",
      "S11P2"
    ]
  },
  {
    "chunk_id": "9000-16-packet-protection-and-coalescing",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 32,
    "section_tokens": [
      "S12P1",
      "S12P2",
      "S12P3"
    ]
  },
  {
    "chunk_id": "9000-17-frame-and-space-rules",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 28,
    "section_tokens": [
      "S12P4",
      "S12P5"
    ]
  },
  {
    "chunk_id": "9000-18-ack-generation",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 54,
    "section_tokens": [
      "S13",
      "S13P1",
      "S13P2",
      "S13P2P1",
      "S13P2P2",
      "S13P2P3",
      "S13P2P4",
      "S13P2P5",
      "S13P2P6",
      "S13P2P7"
    ]
  },
  {
    "chunk_id": "9000-19-retransmission-and-frame-reliability",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 39,
    "section_tokens": [
      "S13P3"
    ]
  },
  {
    "chunk_id": "9000-20-datagram-and-mtu",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 85,
    "section_tokens": [
      "S13P4",
      "S13P4P1",
      "S13P4P2",
      "S13P4P2P1",
      "S13P4P2P2",
      "S14",
      "S14P1",
      "S14P2",
      "S14P2P1",
      "S14P3",
      "S14P4",
      "S15",
      "S16"
    ]
  },
  {
    "chunk_id": "9000-21-long-header-general-and-initial",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 58,
    "section_tokens": [
      "S17",
      "S17P1",
      "S17P2",
      "S17P2P1"
    ]
  },
  {
    "chunk_id": "9000-22-long-header-handshake-and-0rtt",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 49,
    "section_tokens": [
      "S17P2P2",
      "S17P2P3"
    ]
  },
  {
    "chunk_id": "9000-23-retry-version-short-header",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 96,
    "section_tokens": [
      "S17P2P4",
      "S17P2P5",
      "S17P2P5P1",
      "S17P2P5P2",
      "S17P2P5P3",
      "S17P3",
      "S17P3P1",
      "S17P4"
    ]
  },
  {
    "chunk_id": "9000-24-frame-encodings-part-1",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 47,
    "section_tokens": [
      "S18",
      "S18P1",
      "S18P2"
    ]
  },
  {
    "chunk_id": "9000-25-frame-encodings-part-2",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 68,
    "section_tokens": [
      "S19P1",
      "S19P2",
      "S19P3",
      "S19P3P1",
      "S19P3P2",
      "S19P4",
      "S19P5"
    ]
  },
  {
    "chunk_id": "9000-26-frame-encodings-part-3",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 78,
    "section_tokens": [
      "S19P6",
      "S19P7",
      "S19P8",
      "S19P9",
      "S19P10",
      "S19P11"
    ]
  },
  {
    "chunk_id": "9000-27-frame-encodings-part-4",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 66,
    "section_tokens": [
      "S19P12",
      "S19P13",
      "S19P14",
      "S19P15",
      "S19P16",
      "S19P17",
      "S19P18"
    ]
  },
  {
    "chunk_id": "9000-28-errors-registry-and-security",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 70,
    "section_tokens": [
      "S19P19",
      "S19P20",
      "S19P21",
      "S20P1",
      "S20P2",
      "S21P1P1P1",
      "S21P2",
      "S21P3",
      "S21P4",
      "S21P5",
      "S21P5P3",
      "S21P5P6",
      "S21P6",
      "S21P7",
      "S21P9",
      "S21P10",
      "S21P11",
      "S21P12"
    ]
  },
  {
    "chunk_id": "9000-29-iana-and-late-sections",
    "rfc": "9000",
    "spec_file": "./specs/requirements/quic/SPEC-QUIC-RFC9000.md",
    "approx_requirements": 52,
    "section_tokens": [
      "S22P1P1",
      "S22P1P2",
      "S22P1P3",
      "S22P1P4",
      "S22P2",
      "S22P3",
      "S22P4",
      "S22P5"
    ]
  }
]
'@ | ConvertFrom-Json

if ($ChunkIds -and $ChunkIds.Count -gt 0) {
    $chunks = $chunks | Where-Object { $ChunkIds -contains $_.chunk_id }
}

if (-not $chunks -or $chunks.Count -eq 0) {
    throw "No chunks selected. Check -ChunkIds or the embedded manifest."
}

$template2 = @'
You are working in a repository that contains imported QUIC Spec Trace requirements and some existing code/tests.

Goal:
Reconcile the existing implementation and tests for a selected QUIC chunk to the new requirement IDs, identify coverage gaps, and fix straightforward traceability or small implementation gaps.

Scope:
- chunk_id: {{chunk_id}}
- rfc: {{rfc}}
- section_tokens:
{{section_tokens_block}}
- spec_file: {{spec_file}}
- code_roots:
{{code_roots_block}}
- test_roots:
{{test_roots_block}}

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
- ./specs/generated/quic/chunks/{{chunk_id}}.reconciliation.md
- ./specs/generated/quic/chunks/{{chunk_id}}.reconciliation.json

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

$template3 = @'
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Implement the remaining missing or partial requirements for a selected QUIC chunk, add or update tests, and leave the chunk in a clean state for later traceability/audit reporting.

Scope:
- chunk_id: {{chunk_id}}
- rfc: {{rfc}}
- section_tokens:
{{section_tokens_block}}
- spec_file: {{spec_file}}
- code_roots:
{{code_roots_block}}
- test_roots:
{{test_roots_block}}

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file under ./specs/requirements/quic/
- ./specs/generated/quic/chunks/{{chunk_id}}.reconciliation.md
- ./specs/generated/quic/chunks/{{chunk_id}}.reconciliation.json
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
- ./specs/generated/quic/chunks/{{chunk_id}}.implementation-summary.md
- ./specs/generated/quic/chunks/{{chunk_id}}.implementation-summary.json

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

$template4 = @'
You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Audit one completed implementation chunk and confirm that code, tests, and direct requirement references are internally consistent.

Scope:
- chunk_id: {{chunk_id}}
- rfc: {{rfc}}
- section_tokens:
{{section_tokens_block}}
- spec_file: {{spec_file}}

Selection rule:
- Include only requirements whose IDs match the selected RFC and whose section token is exactly one of the section_tokens listed above.

Read first:
- the relevant QUIC spec file
- ./specs/generated/quic/chunks/{{chunk_id}}.reconciliation.json
- ./specs/generated/quic/chunks/{{chunk_id}}.implementation-summary.json

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
- ./specs/generated/quic/chunks/{{chunk_id}}.closeout.md
- ./specs/generated/quic/chunks/{{chunk_id}}.closeout.json

Success criteria:
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- The chunk is ready to be merged or queued for final repo-wide trace/audit tooling.
'@

$builder = [System.Text.StringBuilder]::new()
[void]$builder.AppendLine("# QUIC Codex Prompt Queue")
[void]$builder.AppendLine()
[void]$builder.AppendLine("Generated: $(Get-Date -Format s)")
[void]$builder.AppendLine()
[void]$builder.AppendLine("Code roots:")
[void]$builder.AppendLine((Convert-ToBulletBlock -Items $CodeRoots))
[void]$builder.AppendLine()
[void]$builder.AppendLine("Test roots:")
[void]$builder.AppendLine((Convert-ToBulletBlock -Items $TestRoots))
[void]$builder.AppendLine()

if ($EmitSeparateFiles) {
    New-Item -ItemType Directory -Force -Path $SeparateOutputDir | Out-Null
}

foreach ($chunk in $chunks) {
    $p2 = Expand-Template -Template $template2 -Chunk $chunk -CodeRoots $CodeRoots -TestRoots $TestRoots
    $p3 = Expand-Template -Template $template3 -Chunk $chunk -CodeRoots $CodeRoots -TestRoots $TestRoots
    $p4 = Expand-Template -Template $template4 -Chunk $chunk -CodeRoots $CodeRoots -TestRoots $TestRoots

    [void]$builder.AppendLine("## $($chunk.chunk_id) (RFC $($chunk.rfc); ~$($chunk.approx_requirements) requirements)")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine("Section tokens: $($chunk.section_tokens -join ', ')")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('### Prompt 2 - Reconciliation')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('```text')
    [void]$builder.AppendLine($p2.TrimEnd())
    [void]$builder.AppendLine('```')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('### Prompt 3 - Implementation')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('```text')
    [void]$builder.AppendLine($p3.TrimEnd())
    [void]$builder.AppendLine('```')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('### Prompt 4 - Closeout')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('```text')
    [void]$builder.AppendLine($p4.TrimEnd())
    [void]$builder.AppendLine('```')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('---')
    [void]$builder.AppendLine()

    if ($EmitSeparateFiles) {
        $baseName = $chunk.chunk_id
        Set-Content -Path (Join-Path $SeparateOutputDir "$baseName.prompt2.txt") -Value $p2 -Encoding UTF8
        Set-Content -Path (Join-Path $SeparateOutputDir "$baseName.prompt3.txt") -Value $p3 -Encoding UTF8
        Set-Content -Path (Join-Path $SeparateOutputDir "$baseName.prompt4.txt") -Value $p4 -Encoding UTF8
    }
}

$targetDir = Split-Path -Parent $OutputPath
if ($targetDir) {
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
}

Set-Content -Path $OutputPath -Value $builder.ToString() -Encoding UTF8
Write-Host "Wrote $OutputPath"

if ($EmitSeparateFiles) {
    Write-Host "Wrote separate prompt files to $SeparateOutputDir"
}

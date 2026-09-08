[CmdletBinding()]
param(
    [string]$SchemaPath = (Join-Path $PSScriptRoot '..\..\model\model.schema.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schema = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
$idSchema = @{
    '$schema' = $schema['$schema']
    '$ref' = '#/$defs/requirementId'
    '$defs' = $schema['$defs']
} | ConvertTo-Json -Depth 100 -Compress
$statementSchema = @{
    '$schema' = $schema['$schema']
    '$ref' = '#/$defs/requirementStatement'
    '$defs' = $schema['$defs']
} | ConvertTo-Json -Depth 100 -Compress

# Source candidates may have nested numeric paragraph components, as emitted
# by the RFC importer and recognized by the coverage-triage reader. They are
# migration compatibility identifiers, not evidence of Manager reconciliation.
$validIds = @(
    'REQ-QUIC-RFC9000-0001',
    'REQ-RFC9298-S3-N3-P2-N2-R-0001',
    'RFC9000-S4-6-P3-R01',
    'RFC9000-S19-4-P3-S1-R01',
    'RFC9000-S2-R01',
    'RFC9297-S2-1-P3-4-S2-R01',
    'RFC9298-S2-P4-2-R02',
    'RFC9464-S4-P3-2-S1-R01',
    'RFC9484-S4-7-2-P6-4-S1-R02',
    'RFC9484-S4-7-3-P6-6-S1-R01',
    'RFC9484-S4-P3-2-1-S1-R01'
)
$invalidIds = @(
    '',
    'RFC9298-S2-P4--2-R01',
    'RFC9298-S2-P4-two-R01',
    'RFC9298-S2-P-2-R01',
    'RFC9298-S2-P4-2--R01',
    'RFC9298-S2-P4-2-S-R01',
    'RFC9298-S2-P4-2-R1',
    'RFC9298-S2-P4-2-R01-extra',
    'prefix-RFC9298-S2-P4-2-R01',
    'RFC9298-S2-P4-2-R01 ',
    'rfc9298-S2-P4-2-R01',
    'RFC929-S2-P4-2-R01',
    'REQ-RFC9298-S3-N3-P2-N2-R-0001-extra'
)

$failures = [System.Collections.Generic.List[string]]::new()
foreach ($id in $validIds) {
    $valid = Test-Json -Json (ConvertTo-Json -InputObject $id -Compress) -Schema $idSchema -ErrorAction SilentlyContinue
    if (-not $valid) { $failures.Add("Valid identifier rejected: '$id'.") }
}
foreach ($id in $invalidIds) {
    $valid = Test-Json -Json (ConvertTo-Json -InputObject $id -Compress) -Schema $idSchema -ErrorAction SilentlyContinue
    if ($valid) { $failures.Add("Malformed identifier accepted: '$id'.") }
}

$statements = @(
    @{ Text = 'An endpoint MUST reject the frame.'; Valid = $true },
    @{ Text = 'An endpoint MUST NOT send the frame.'; Valid = $true },
    @{ Text = 'An endpoint rejects the frame.'; Valid = $false },
    @{ Text = 'An endpoint MUST reject the frame and MUST close the connection.'; Valid = $false }
)
foreach ($statement in $statements) {
    $valid = Test-Json -Json (ConvertTo-Json -InputObject $statement.Text -Compress) -Schema $statementSchema -ErrorAction SilentlyContinue
    if ($valid -ne $statement.Valid) { $failures.Add("Unexpected statement validation: '$($statement.Text)'.") }
}

if ($failures.Count -gt 0) {
    throw ($failures -join [Environment]::NewLine)
}
Write-Output "Passed $($validIds.Count + $invalidIds.Count + $statements.Count) local schema compatibility checks."

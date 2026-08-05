# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $PilotPath = (Join-Path $PSScriptRoot `
        'experiment-control\adaptive-runtime-send-admission-performance-pilot-v1.json'),
    [string] $OutputRoot = (Join-Path 'C:\shared\temp\quic-dotnet' (
        'admission-performance-pairwise-request-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $ProtocolLabRoot = '../protocol-lab',
    [string] $ControllerUri,
    [string] $ExistingPackageManifestPath,
    [switch] $PublishPackages,
    [switch] $Preview,
    [switch] $Import,
    [switch] $Start,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

function Assert-Request([bool] $Condition, [string] $Code) {
    if (-not $Condition) {
        throw $Code
    }
}

function Read-Repo([string] $RelativePath) {
    Read-AdaptiveRuntimeJsonDocument (Join-Path $RepositoryRoot $RelativePath)
}

function Write-JsonFile([string] $Path, [object] $Value) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 100),
        [System.Text.UTF8Encoding]::new($false))
}

function Resolve-AbsolutePath {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Invoke-ControllerJson {
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][string] $Method,
        [object] $Body
    )

    $parameters = @{
        Uri = $Uri
        Method = $Method
        TimeoutSec = 30
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = ($Body | ConvertTo-Json -Depth 100)
    }

    Invoke-RestMethod @parameters
}

function ConvertTo-LabPackageReference {
    param([Parameter(Mandatory = $true)][object] $Package)

    [pscustomobject][ordered]@{
        packageId = [string]$Package.packageId
        packageVersion = [string]$Package.packageVersion
        sha256 = [string]$Package.sha256
    }
}

function Publish-PairwisePackage {
    param(
        [Parameter(Mandatory = $true)][string] $ControllerUri,
        [Parameter(Mandatory = $true)][string] $Path
    )

    $uploadUri = $ControllerUri.TrimEnd('/') + '/api/lab/packages/upload'
    $form = @{
        package = Get-Item -LiteralPath $Path
    }
    Invoke-RestMethod -Uri $uploadUri -Method Post -Form $form -TimeoutSec 120 -ErrorAction Stop
}

Assert-Request (-not $Start -or $Import) 'pairwise_request_start_requires_import'
Assert-Request (-not ($Start -and $PublishPackages)) 'pairwise_request_start_conflicts_publish_packages'

function Join-Values([object[]] $Values) {
    [string]::Join('|', @($Values | ForEach-Object { [string]$_ }))
}

function Get-ReviewedCellAxisValue([object] $Cell, [string] $AxisId) {
    $axisValue = @($Cell.axis_values | Where-Object axis_id -ceq $AxisId)[0]
    Assert-Request ($null -ne $axisValue) "pairwise_request_axis_missing:$AxisId"
    [string]$axisValue.policy_value
}

function Get-CellControlRecord([object] $Cell) {
    $batch = Get-ReviewedCellAxisValue $Cell 'application_send_batch_formation'
    $buffer = Get-ReviewedCellAxisValue $Cell 'buffer_copy_coalescing'
    $profile = switch ("$batch|$buffer") {
        'legacy_current|legacy_current' { 'legacy_current_path' }
        'legacy_current|memory_conservative' { 'legacy_current_memory_conservative' }
        'single_eligible|legacy_current' { 'single_eligible_legacy_copy' }
        'single_eligible|memory_conservative' { 'single_eligible_memory_conservative' }
        default { throw "pairwise_request_selected_profile_invalid:$([string]$Cell.cell_id)" }
    }

    [pscustomobject][ordered]@{
        cell_id = ([string]$Cell.cell_id).Split('.')[-1]
        oversized_write_admission_quantum = Get-ReviewedCellAxisValue $Cell 'oversized_write_admission_quantum'
        application_send_batch_formation = $batch
        buffer_copy_coalescing = $buffer
        send_composition_profile = $profile
    }
}

function ConvertTo-TraceReferenceList([object] $TraceReferences) {
    $references = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $TraceReferences) {
        return @()
    }

    foreach ($mapping in @(
        @{ Name = 'architecture_ids'; Prefix = 'architecture' },
        @{ Name = 'requirement_ids'; Prefix = 'requirement' },
        @{ Name = 'verification_ids'; Prefix = 'verification' },
        @{ Name = 'work_item_ids'; Prefix = 'work-item' }
    )) {
        foreach ($value in @($TraceReferences.$($mapping.Name))) {
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                [void]$references.Add("$($mapping.Prefix):$([string]$value)")
            }
        }
    }

    return @($references)
}

function Get-ExpectedPackageManifestCell {
    param(
        [Parameter(Mandatory = $true)][hashtable] $CellsById,
        [Parameter(Mandatory = $true)][string] $CellId
    )

    Assert-Request ($CellsById.ContainsKey($CellId)) "pairwise_request_package_cell_missing:$CellId"
    $cell = $CellsById[$CellId]
    Assert-Request (
        $null -ne $cell.package_ref -and
        -not [string]::IsNullOrWhiteSpace([string]$cell.package_ref.packageId) -and
        -not [string]::IsNullOrWhiteSpace([string]$cell.package_ref.packageVersion) -and
        [string]$cell.package_ref.sha256 -match '^[0-9a-f]{64}$'
    ) "pairwise_request_package_ref_invalid:$CellId"
    return $cell
}

function New-RunPlan {
    param(
        [Parameter(Mandatory = $true)][object] $Pilot,
        [Parameter(Mandatory = $true)][object] $Cell,
        [Parameter(Mandatory = $true)][object] $ImplementationPackageRef,
        [Parameter(Mandatory = $true)][string[]] $TraceReferences,
        [Parameter(Mandatory = $true)][string] $RunPlanVersion
    )

    $cellId = [string]$Cell.cell_id
    $cellLabels = @(
        'adaptive-runtime',
        'send-admission',
        'performance',
        'pilot',
        "cell:$cellId"
    )

    [pscustomobject][ordered]@{
        schemaVersion = 'protocol-lab-run-plan-v1'
        runPlanId = "adaptive-runtime-send-admission-performance-$cellId"
        runPlanVersion = $RunPlanVersion
        displayName = "Adaptive runtime send admission performance $cellId"
        packages = @(
            $ImplementationPackageRef
        ) + @($Pilot.package_selection.component_package_references | ForEach-Object {
            [pscustomobject][ordered]@{
                packageId = [string]$_.package_id
                packageVersion = [string]$_.package_version
                sha256 = [string]$_.sha256
            }
        })
        implementationIds = @([string]$Pilot.package_selection.implementation_id)
        testExecutorIds = @([string]$Pilot.package_selection.test_executor_id)
        suiteIds = @([string]$Pilot.package_selection.suite_id)
        scenarioIds = @([string]$Pilot.package_selection.scenario_id)
        protocols = @([string]$Pilot.package_selection.protocol)
        loadProfileId = [string]$Pilot.package_selection.load_profile_id
        targetMode = 'implementation-resolved'
        targetNetworkMode = 'published-endpoint'
        requiredCapabilities = @(
            [pscustomobject][ordered]@{
                name = 'evidenceTier'
                value = 'offline-ml-two-host-vm'
            }
        )
        repetitions = [int]$Pilot.package_selection.repetitions_per_cell
        cellOrder = 'round-robin'
        comparisonGroups = @()
        publicationIntent = 'local-only'
        labels = @($cellLabels)
        traceReferences = @($TraceReferences)
        notes = (
            "Exact reviewed adaptive-runtime admission pilot arm $cellId; no run-plan synthesis; " +
            'factor values are pinned to reviewed controls and package-backed execution stays bounded.'
        )
    }
}

$pilot = Read-AdaptiveRuntimeJsonDocument $PilotPath
Assert-Request (Test-AdaptiveRuntimeDocumentHash $pilot) 'pairwise_request_pilot_hash_invalid'
Assert-Request (
    Test-AdaptiveRuntimeJsonSchema $pilot (Join-Path $RepositoryRoot `
        'schemas\adaptive-runtime-send-admission-performance-pilot-v1.schema.json')
) 'pairwise_request_pilot_schema_invalid'
Assert-Request (
    (Join-Values @($pilot.selected_cells | Sort-Object)) -ceq
        (Join-Values @('a0', 'a3', 'a4', 'a7'))
) 'pairwise_request_selected_cells_invalid'
Assert-Request (
    (Join-Values @($pilot.execution_sequence)) -ceq
        (Join-Values @('a0', 'a4', 'a3', 'a7'))
) 'pairwise_request_execution_sequence_invalid'
Assert-Request (
    [string]$pilot.host_selection.placement_policy -ceq 'isolated-pair' -and
    [string]$pilot.host_selection.worker_selection_owner -ceq 'controller-owned' -and
    [string]$pilot.package_selection.package_target -ceq 'RawQuic' -and
    [string]$pilot.package_selection.implementation_id -ceq 'quic-dotnet-raw-dev' -and
    [string]$pilot.package_selection.suite_id -ceq 'quic-transport-v1-comparison' -and
    [string]$pilot.package_selection.scenario_id -ceq 'quic.transport.multiplex.100x64kb' -and
    [string]$pilot.package_selection.protocol -ceq 'quic' -and
    [string]$pilot.package_selection.test_executor_id -ceq 'quic-go-raw-load' -and
    [string]$pilot.package_selection.load_profile_id -ceq 'raw-quic-peer-confidence' -and
    [int]$pilot.package_selection.repetitions_per_cell -eq 2 -and
    $pilot.package_selection.package_backed_execution -eq $true -and
    $pilot.covering_array_generator_implemented -eq $false -and
    [int]$pilot.covering_array_trigger_effective_cell_count -eq 65
) 'pairwise_request_pilot_controls_invalid'

if ([string]::IsNullOrWhiteSpace($ControllerUri)) {
    $ControllerUri = [string]$pilot.controller_uri
}
$controllerAddress = $null
Assert-Request (
    [System.Uri]::TryCreate($ControllerUri, [System.UriKind]::Absolute, [ref]$controllerAddress) -and
    $controllerAddress.Scheme -in @('http', 'https')
) 'pairwise_request_controller_uri_invalid'
$ControllerUri = $ControllerUri.TrimEnd('/')

$factor = Read-Repo 'eng\adaptive-runtime\experiment-control\adaptive-runtime-factor-cell-space-v3.json'
Assert-Request (Test-AdaptiveRuntimeDocumentHash $factor) 'pairwise_request_factor_hash_invalid'
$admissionSpace = @($factor.family_spaces | Where-Object family_id -ceq 'send_admission_composition')
Assert-Request ($admissionSpace.Count -eq 1) 'pairwise_request_factor_space_missing'
$reviewed = @($admissionSpace[0].planned_cells |
    Where-Object classification -ceq 'reviewed_exact_exhaustive' |
    Sort-Object cell_order)
Assert-Request ($reviewed.Count -eq 8) 'pairwise_request_reviewed_cell_count_invalid'

$reviewedCells = @($reviewed | ForEach-Object { Get-CellControlRecord $_ })
Assert-Request (
    (Join-Values @($reviewedCells.cell_id)) -ceq
        (Join-Values @('a0','a1','a2','a3','a4','a5','a6','a7'))
) 'pairwise_request_reviewed_cell_identity_invalid'
$pilotCandidateCells = @($reviewedCells | Where-Object cell_id -in @($pilot.selected_cells) | Sort-Object cell_id)
Assert-Request (
    (Join-Values @($pilotCandidateCells.cell_id)) -ceq
        (Join-Values @('a0','a3','a4','a7'))
) 'pairwise_request_pilot_candidate_identity_invalid'
Assert-Request (
    (Join-Values @($pilotCandidateCells.send_composition_profile | Sort-Object -Unique)) -ceq
        (Join-Values @('legacy_current_path','single_eligible_memory_conservative'))
) 'pairwise_request_pilot_profile_invalid'

$sourceCommit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
Assert-Request (
    $LASTEXITCODE -eq 0 -and
    $sourceCommit -match '^[0-9a-f]{40}$'
) 'pairwise_request_source_commit_unresolved'
$sourceCommitShort = $sourceCommit.Substring(0, 8)
$pilotHashShort = ([string]$pilot.content_sha256).Substring(0, 8)
$experimentVersion = "2026.08.03-$pilotHashShort-$sourceCommitShort"
$packageVersionPrefix = "adaptive-runtime-admission-stage-e1-$pilotHashShort-$sourceCommitShort"
$traceReferences = ConvertTo-TraceReferenceList $pilot.trace_references

$outputRootFull = [System.IO.Path]::GetFullPath($OutputRoot)
[void](New-Item -ItemType Directory -Force -Path $outputRootFull)
$packagesPath = Join-Path $outputRootFull 'package-identities.json'
$requestPath = Join-Path $outputRootFull 'pairwise-generation-request.json'
$previewPath = Join-Path $outputRootFull 'pairwise-generation-preview.json'
$importRequestPath = Join-Path $outputRootFull 'pairwise-generation-import-request.json'
$importResponsePath = Join-Path $outputRootFull 'pairwise-generation-import-response.json'
$startRequestPath = Join-Path $outputRootFull 'pairwise-generation-start-request.json'
$startResponsePath = Join-Path $outputRootFull 'pairwise-generation-start-response.json'

$cellsById = @{}

if (-not [string]::IsNullOrWhiteSpace($ExistingPackageManifestPath)) {
    $packageManifest = Read-AdaptiveRuntimeJsonDocument $ExistingPackageManifestPath
    foreach ($cell in @($packageManifest.implementation_packages)) {
        $cellsById[[string]$cell.cell_id] = $cell
    }
}
else {
    $protocolLabRootFull = Resolve-AbsolutePath -Path $ProtocolLabRoot -BasePath $RepositoryRoot
    foreach ($cell in $pilotCandidateCells) {
        $packageVersion = "$packageVersionPrefix-$([string]$cell.cell_id)"
        $packageResult = & (Join-Path $PSScriptRoot '..\protocol-lab\New-QuicDotNetProtocolLabPackage.ps1') `
            -PackageTarget RawQuic `
            -ProtocolLabRoot $protocolLabRootFull `
            -Project 'eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic/Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj' `
            -Configuration Release `
            -RuntimeIdentifier @('linux-x64') `
            -PackageVersion $packageVersion `
            -AdaptiveRuntimeOversizedWriteAdmissionPolicy ([string]$cell.oversized_write_admission_quantum) `
            -AdaptiveRuntimeApplicationSendBatchPolicy ([string]$cell.application_send_batch_formation) `
            -AdaptiveRuntimeBufferCopyPolicy ([string]$cell.buffer_copy_coalescing) `
            -Force `
            -AllowDirtySource:$false | ConvertFrom-Json

        Assert-Request (
            $null -ne $packageResult -and
            -not [string]::IsNullOrWhiteSpace([string]$packageResult.path) -and
            -not [string]::IsNullOrWhiteSpace([string]$packageResult.packageId) -and
            -not [string]::IsNullOrWhiteSpace([string]$packageResult.packageVersion) -and
            [string]$packageResult.sha256 -match '^[0-9a-f]{64}$'
        ) "pairwise_request_package_build_failed:$($cell.cell_id)"

        $packageRef = ConvertTo-LabPackageReference $packageResult
        if ($PublishPackages) {
            $uploadedPackage = Publish-PairwisePackage `
                -ControllerUri $ControllerUri `
                -Path ([string]$packageResult.path)
            Assert-Request (
                [string]$uploadedPackage.packageId -ceq [string]$packageRef.packageId -and
                [string]$uploadedPackage.packageVersion -ceq [string]$packageRef.packageVersion -and
                [string]$uploadedPackage.sha256 -ceq [string]$packageRef.sha256
            ) "pairwise_request_uploaded_package_identity_mismatch:$($cell.cell_id)"
        }

        $cellsById[[string]$cell.cell_id] = [pscustomobject][ordered]@{
            cell_id = [string]$cell.cell_id
            package_ref = $packageRef
            package_path = [string]$packageResult.path
            package_attestation_path = [string]$packageResult.buildAttestationPath
            published_to_controller = [bool]$PublishPackages
        }
    }
}

$coverage = [pscustomobject][ordered]@{
    interactionStrength = 2
    factors = @(
        [pscustomobject][ordered]@{
            factorId = 'oversized_write_admission_quantum'
            levels = @('legacy_current', 'single_fragment')
        },
        [pscustomobject][ordered]@{
            factorId = 'send_composition_profile'
            levels = @('legacy_current_path', 'single_eligible_memory_conservative')
        }
    )
    excludedPairs = @()
}

$candidateArms = @($pilotCandidateCells | ForEach-Object {
    $cell = $_
    $packageCell = Get-ExpectedPackageManifestCell -CellsById $cellsById -CellId ([string]$cell.cell_id)
    $runPlan = New-RunPlan `
        -Pilot $pilot `
        -Cell $cell `
        -ImplementationPackageRef $packageCell.package_ref `
        -TraceReferences $traceReferences `
        -RunPlanVersion $experimentVersion

    [pscustomobject][ordered]@{
        armId = [string]$cell.cell_id
        role = if ([string]$cell.cell_id -ceq 'a0') { 'baseline' } else { 'candidate' }
        placementPolicy = 'isolated-pair'
        machineRoles = @(
            foreach ($roleId in @('sut', 'load')) {
                [pscustomobject][ordered]@{
                    roleId = $roleId
                    required = $true
                    resourceRequirements = [pscustomobject][ordered]@{
                        capabilities = @(
                            [pscustomobject][ordered]@{ name = 'role'; value = $roleId },
                            [pscustomobject][ordered]@{
                                name = 'evidenceTier'
                                value = 'offline-ml-two-host-vm'
                            }
                        )
                    }
                }
            }
        )
        factorValues = [ordered]@{
            oversized_write_admission_quantum = [string]$cell.oversized_write_admission_quantum
            send_composition_profile = [string]$cell.send_composition_profile
        }
        runPlan = $runPlan
    }
})

$request = [pscustomobject][ordered]@{
    schemaVersion = 'protocol-lab-internal-experiment-pairwise-generation-request-v1'
    strategyId = 'pairwise-greedy-v1'
    experimentId = 'adaptive-runtime-send-admission-performance-pairwise'
    experimentVersion = $experimentVersion
    displayName = 'Adaptive runtime send admission performance pilot'
    hypothesis = 'Exact reviewed adaptive-runtime pilot arms can satisfy the bounded Stage E1 pairwise design without synthesizing new run plans, while keeping batch and buffer intentionally coupled in this pilot.'
    coverage = $coverage
    candidateArms = @($candidateArms)
    pinnedArmIds = @($pilot.execution_sequence)
    executionSequenceArmIds = @($pilot.execution_sequence)
    labels = @(
        'adaptive-runtime',
        'send-admission',
        'performance',
        'pilot',
        'pairwise-stage-e1'
    )
    traceReferences = @($traceReferences)
    notes = (
        'Reviewed A0, A3, A4, and A7 exact candidate export for the bounded adaptive-runtime admission pilot. ' +
        'Pinned execution order remains A0, A4, A3, A7. Batch formation and buffer coalescing stay ' +
        'intentionally coupled as send_composition_profile in this pilot, so the request remains honest ' +
        'about what the four-cell design can and cannot attribute.'
    )
}

$packageManifestValue = [pscustomobject][ordered]@{
    schemaVersion = 'adaptive-runtime-admission-performance-pairwise-package-manifest-v1'
    controllerUri = $ControllerUri
    experimentId = [string]$request.experimentId
    experimentVersion = [string]$request.experimentVersion
    sourceCommit = $sourceCommit
    packageVersionPrefix = $packageVersionPrefix
    implementation_packages = @($pilotCandidateCells | ForEach-Object {
        $packageCell = Get-ExpectedPackageManifestCell -CellsById $cellsById -CellId ([string]$_.cell_id)
        [pscustomobject][ordered]@{
            cell_id = [string]$packageCell.cell_id
            package_ref = $packageCell.package_ref
            package_path = if ($packageCell.PSObject.Properties.Name -contains 'package_path') {
                [string]$packageCell.package_path
            } else { $null }
            package_attestation_path = if ($packageCell.PSObject.Properties.Name -contains 'package_attestation_path') {
                [string]$packageCell.package_attestation_path
            } else { $null }
            published_to_controller = if ($packageCell.PSObject.Properties.Name -contains 'published_to_controller') {
                [bool]$packageCell.published_to_controller
            } else { $false }
        }
    })
    component_packages = @($pilot.package_selection.component_package_references)
}

Write-JsonFile -Path $packagesPath -Value $packageManifestValue
Write-JsonFile -Path $requestPath -Value $request

$previewResponse = $null
$importRequest = $null
$importResponse = $null
$startRequest = $null
$startResponse = $null
if ($Preview -or $Import) {
    $previewResponse = Invoke-ControllerJson `
        -Uri ($ControllerUri + '/api/lab/experiments/pairwise-generation/preview') `
        -Method Post `
        -Body $request
    Write-JsonFile -Path $previewPath -Value $previewResponse
}

if ($Import) {
    Assert-Request ($null -ne $previewResponse) 'pairwise_request_preview_missing'
    Assert-Request ($previewResponse.canImport -eq $true) 'pairwise_request_preview_not_importable'
    $importRequest = [pscustomobject][ordered]@{
        schemaVersion = 'protocol-lab-internal-experiment-pairwise-generation-import-v1'
        request = $request
        expectedRequestContentHash = [string]$previewResponse.requestContentHash
        expectedManifestContentHash = [string]$previewResponse.generatedManifestContentHash
        expectedCompilationContentHash = [string]$previewResponse.preview.compilationContentHash
    }
    Write-JsonFile -Path $importRequestPath -Value $importRequest
    $importResponse = Invoke-ControllerJson `
        -Uri ($ControllerUri + '/api/lab/experiments/pairwise-generation/import') `
        -Method Post `
        -Body $importRequest
    Write-JsonFile -Path $importResponsePath -Value $importResponse
}

$startExecutionId = $null
if ($Start) {
    Assert-Request ($null -ne $previewResponse) 'pairwise_request_start_preview_missing'
    Assert-Request ($null -ne $importResponse) 'pairwise_request_start_import_missing'
    $selectedArmSet = Join-Values @($previewResponse.selectedArmIds | ForEach-Object { [string]$_ } | Sort-Object)
    $executionSequenceSet = Join-Values @($request.executionSequenceArmIds | ForEach-Object { [string]$_ } | Sort-Object)
    Assert-Request ($selectedArmSet -ceq $executionSequenceSet) 'pairwise_request_start_sequence_mismatch'
    $startRequest = [pscustomobject][ordered]@{
        schemaVersion = 'admission-performance-pairwise-start-request-v1'
        executionId = $null
        expectedManifestContentHash = [string]$previewResponse.generatedManifestContentHash
        expectedCompilationContentHash = [string]$previewResponse.preview.compilationContentHash
    }
    Write-JsonFile -Path $startRequestPath -Value $startRequest
    $startResponse = Invoke-ControllerJson `
        -Uri ($ControllerUri + '/api/lab/experiments/' + $request.experimentId + '/versions/' + $request.experimentVersion + '/executions') `
        -Method Post `
        -Body $startRequest
    $startExecutionId = [string]$startResponse.executionId
    $startResponseCompact = [pscustomobject][ordered]@{
        schemaVersion = 'admission-performance-pairwise-start-response-v1'
        experiment_id = [string]$startResponse.experimentId
        experiment_version = [string]$startResponse.experimentVersion
        execution_id = [string]$startResponse.executionId
        status = [string]$startResponse.status
        created_at = [string]$startResponse.createdAt
        updated_at = [string]$startResponse.updatedAt
        manifest_content_hash = [string]$startResponse.manifestContentHash
        compilation_content_hash = [string]$startResponse.compilationContentHash
    }
    Write-JsonFile -Path $startResponsePath -Value $startResponseCompact
}

$result = [pscustomobject][ordered]@{
    output_root = $outputRootFull
    package_manifest_path = $packagesPath
    request_path = $requestPath
    preview_path = if ($null -ne $previewResponse) { $previewPath } else { $null }
    import_request_path = if ($null -ne $importRequest) { $importRequestPath } else { $null }
    import_response_path = if ($null -ne $importResponse) { $importResponsePath } else { $null }
    start_request_path = if ($null -ne $startRequest) { $startRequestPath } else { $null }
    start_response_path = if ($null -ne $startResponse) { $startResponsePath } else { $null }
    controller_uri = $ControllerUri
    experiment_id = [string]$request.experimentId
    experiment_version = [string]$request.experimentVersion
    candidate_arm_count = @($request.candidateArms).Count
    pinned_arm_ids = @($request.pinnedArmIds)
    execution_sequence_arm_ids = @($request.executionSequenceArmIds)
    package_version_prefix = $packageVersionPrefix
    preview_status = if ($null -ne $previewResponse) { [string]$previewResponse.status } else { $null }
    preview_can_import = if ($null -ne $previewResponse) { [bool]$previewResponse.canImport } else { $null }
    selected_arm_ids = if ($null -ne $previewResponse) { @($previewResponse.selectedArmIds) } else { @() }
    import_completed = ($null -ne $importResponse)
    start_completed = ($null -ne $startResponse)
    start_execution_id = if ($null -ne $startResponse) { $startExecutionId } else { $null }
    start_status = if ($null -ne $startResponse) { [string]$startResponse.status } else { $null }
}

if ($PassThru) {
    $result
}
else {
    $result | ConvertTo-Json -Depth 32
}

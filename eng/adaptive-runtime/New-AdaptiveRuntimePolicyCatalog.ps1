# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [string] $CatalogId = 'adaptive-runtime-receive-credit-catalog',

    [string] $CatalogVersion = '2026-07-22-v1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdaptiveRuntimePipeline.Common.ps1')

$repositoryRoot = Get-AdaptiveRuntimeRepositoryRoot
$schemaPath = Join-Path $repositoryRoot 'schemas\adaptive-runtime-policy-catalog-v1.schema.json'

$document = [ordered]@{
    schemaVersion = 'adaptive-runtime-policy-catalog-v1'
    catalogId = $CatalogId
    catalogVersion = $CatalogVersion
    generatedUtc = [DateTime]::UtcNow.ToString('O')
    measurementOnly = $true
    seamLocal = $true
    activationAuthorized = $false
    scope = [ordered]@{
        requirementIds = @(
            'REQ-QUIC-CRT-0170',
            'REQ-QUIC-CRT-0171',
            'REQ-QUIC-CRT-0172'
        )
        axisIds = @(
            'receive_credit_publication',
            'oversized_write_admission',
            'application_send_turn_planning',
            'application_datagram_batching',
            'application_send_batch_formation',
            'queued_send_burst_budget',
            'application_send_pressure_classification',
            'ready_stream_fairness',
            'actor_work_quantum',
            'packet_flush_cadence',
            'backpressure_bounds',
            'runtime_pressure_advisor'
        )
        blockedCapabilities = @(
            'active_internal',
            'online_learning',
            'production_activation',
            'axis_widening',
            'runtime_mode_reclassification'
        )
    }
    entries = @(
        [ordered]@{
            entryId = 'receive-credit-publication.experimental'
            axisId = 'receive_credit_publication'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'executable_measurement'
            runtimeAuthority = 'legacy_current'
            measurementModes = @('shadow', 'forced')
            policyValues = @(
                'legacy_current',
                'immediate',
                'read_dominant_batch'
            )
            candidatePolicies = @('read_dominant_batch')
            forceableForCampaigns = $true
            shadowSupported = $true
            activationAuthorized = $false
            sourceRequirements = @(
                'REQ-QUIC-CRT-0170',
                'REQ-QUIC-CRT-0171',
                'REQ-QUIC-CRT-0172'
            )
            retainedNegativeEvidenceClasses = @(
                'universal_batching',
                'half_window_duplex_reactivation',
                'quarter_window_duplex_reactivation',
                'non_sticky_duplex_fallback',
                'lock_based_selector'
            )
            notes = @(
                'Catalog entries remain review metadata only and cannot authorize runtime activation.',
                'The bounded first slice stays on receive-credit publication and does not widen to other axes.'
            )
        }
        [ordered]@{
            entryId = 'oversized-write-admission.inventory'
            axisId = 'oversized_write_admission'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'inventory_only'
            runtimeAuthority = 'static_current'
            measurementModes = @()
            policyValues = @('static_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170')
            retainedNegativeEvidenceClasses = @()
            notes = @('Existing seam inventory only; no end-to-end forced campaign mode exists in this tranche.')
        }
        [ordered]@{
            entryId = 'application-send-turn-planning.inventory'
            axisId = 'application_send_turn_planning'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'forceable_test_seam'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current', 'candidate')
            candidatePolicies = @('candidate')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170')
            retainedNegativeEvidenceClasses = @('scheduler_quantum')
            notes = @('Planner injection exists in tests and benchmarks, but no executable local campaign mode is authorized here.')
        }
        [ordered]@{
            entryId = 'application-datagram-batching.inventory'
            axisId = 'application_datagram_batching'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'forceable_test_seam'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current', 'candidate')
            candidatePolicies = @('candidate')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170')
            retainedNegativeEvidenceClasses = @()
            notes = @('Adaptive precedent exists, but this catalog entry remains metadata only for compatibility review.')
        }
        [ordered]@{
            entryId = 'application-send-batch-formation.observation'
            axisId = 'application_send_batch_formation'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'inventory_only'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170')
            retainedNegativeEvidenceClasses = @()
            notes = @('Candidate seam only after a stable forced-mode contract exists.')
        }
        [ordered]@{
            entryId = 'queued-send-burst-budget.observation'
            axisId = 'queued_send_burst_budget'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'inventory_only'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170')
            retainedNegativeEvidenceClasses = @()
            notes = @('Safety budgets remain authoritative; metadata only until a reviewed lower-only policy exists.')
        }
        [ordered]@{
            entryId = 'application-send-pressure-classification.observation'
            axisId = 'application_send_pressure_classification'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'observation_only'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170', 'REQ-QUIC-CRT-0172')
            retainedNegativeEvidenceClasses = @()
            notes = @('Observation source only; it does not select runtime work in this tranche.')
        }
        [ordered]@{
            entryId = 'ready-stream-fairness.observation'
            axisId = 'ready_stream_fairness'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'inventory_only'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170')
            retainedNegativeEvidenceClasses = @()
            notes = @('Ordering invariants remain fixed and are not configurable through this measurement substrate.')
        }
        [ordered]@{
            entryId = 'actor-work-quantum.observation'
            axisId = 'actor_work_quantum'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'observation_only'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170')
            retainedNegativeEvidenceClasses = @('scheduler_quantum')
            notes = @('Observe first; no safe adaptive seam is approved for actor work quantum.')
        }
        [ordered]@{
            entryId = 'packet-flush-cadence.observation'
            axisId = 'packet_flush_cadence'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'observation_only'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170')
            retainedNegativeEvidenceClasses = @()
            notes = @('Correctness-critical packet progress remains authoritative; metadata only.')
        }
        [ordered]@{
            entryId = 'backpressure-bounds.observation'
            axisId = 'backpressure_bounds'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'observation_only'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170', 'REQ-QUIC-CRT-0172')
            retainedNegativeEvidenceClasses = @()
            notes = @('Hard bounds remain authoritative; future adaptation may only become more conservative before a bound.')
        }
        [ordered]@{
            entryId = 'runtime-pressure-advisor.observation'
            axisId = 'runtime_pressure_advisor'
            catalogStatus = 'experimental_measurement_only'
            readiness = 'observation_only'
            runtimeAuthority = 'legacy_current'
            measurementModes = @()
            policyValues = @('legacy_current')
            candidatePolicies = @('not_applicable')
            forceableForCampaigns = $false
            shadowSupported = $false
            activationAuthorized = $false
            sourceRequirements = @('REQ-QUIC-CRT-0170', 'REQ-QUIC-CRT-0172')
            retainedNegativeEvidenceClasses = @()
            notes = @('Advisor snapshots remain optional and immutable; absence must map to conservative behavior.')
        }
    )
    notes = @(
        'This catalog is measurement-only metadata for seam-local offline review.',
        'Presence in the catalog does not authorize active_internal, production activation, or online learning.',
        'Only receive-credit publication is executable in this v1 substrate; all other entries remain inventory or observation metadata.'
    )
}

$written = Write-ValidatedJsonDocument -Document $document -SchemaPath $schemaPath -OutputPath $OutputPath
[pscustomobject]@{
    schemaVersion = 'adaptive-runtime-policy-catalog-write-v1'
    catalogId = $document.catalogId
    catalogVersion = $document.catalogVersion
    outputPath = $written.Path
    sha256 = $written.Sha256
} | ConvertTo-Json -Depth 20

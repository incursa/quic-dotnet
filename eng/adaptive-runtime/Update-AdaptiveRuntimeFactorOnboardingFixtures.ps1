# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $RepositoryRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot `
    'AdaptiveRuntimeExperimentControl.Common.psm1') -Force

$schemaRoot = Join-Path $RepositoryRoot 'schemas'
$catalogRoot = Join-Path $RepositoryRoot `
    'eng\adaptive-runtime\experiment-control'
$fixtureRoot = Join-Path $RepositoryRoot `
    'tests\fixtures\adaptive-runtime-factor-onboarding'

$trace = [pscustomobject][ordered]@{
    requirement_ids = @(
        'REQ-QUIC-CRT-0235',
        'REQ-QUIC-CRT-0236',
        'REQ-QUIC-CRT-0237',
        'REQ-QUIC-CRT-0238',
        'REQ-QUIC-CRT-0239',
        'REQ-QUIC-CRT-0240'
    )
    architecture_ids = @('ARC-QUIC-CRT-0113')
    work_item_ids = @('WI-QUIC-CRT-0114')
    verification_ids = @('VER-QUIC-CRT-0115')
}
$planTrace = [pscustomobject][ordered]@{
    requirement_ids = @(
        'REQ-QUIC-CRT-0202',
        'REQ-QUIC-CRT-0203',
        'REQ-QUIC-CRT-0204',
        'REQ-QUIC-CRT-0205')
    architecture_ids = @('ARC-QUIC-CRT-0092')
    work_item_ids = @('WI-QUIC-CRT-0093')
    verification_ids = @('VER-QUIC-CRT-0094')
}

function Write-Utf8NoBom {
    param([string] $Path, [string] $Text)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        [void](New-Item -ItemType Directory -Path $parent)
    }
    [IO.File]::WriteAllText(
        $Path,
        $Text.TrimEnd() + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

function Copy-SchemaVariant {
    param(
        [string] $Source,
        [string] $Destination,
        [hashtable] $Replacements
    )
    $text = Get-Content -LiteralPath (Join-Path $schemaRoot $Source) -Raw
    foreach ($entry in $Replacements.GetEnumerator()) {
        $text = $text.Replace([string]$entry.Key, [string]$entry.Value)
    }
    Write-Utf8NoBom (Join-Path $schemaRoot $Destination) $text
}

function New-DocumentRef {
    param([object] $Document)
    [pscustomobject][ordered]@{
        document_id = [string]$Document.document_id
        schema_version = [string]$Document.schema_version
        document_version = [int]$Document.document_version
        content_sha256 = [string]$Document.content_sha256
    }
}

function Write-Document {
    param([object] $Document, [string] $RelativePath)
    Write-AdaptiveRuntimeCanonicalDocument $Document (
        Join-Path $RepositoryRoot $RelativePath)
}

# Additive schema line. Retained schemas are read but never modified.
Copy-SchemaVariant `
    'adaptive-runtime-policy-axis-contract-v1.schema.json' `
    'adaptive-runtime-policy-axis-contract-v2.schema.json' @{
        'adaptive-runtime-policy-axis-contract-v1' =
            'adaptive-runtime-policy-axis-contract-v2'
        'Policy Axis Contract v1' = 'Policy Axis Contract v2'
        '"document_version": { "type": "integer", "const": 1 }' =
            '"document_version": { "type": "integer", "const": 2 }'
        '"REQ-QUIC-CRT-0198","REQ-QUIC-CRT-0199","REQ-QUIC-CRT-0200","REQ-QUIC-CRT-0201"' =
            '"REQ-QUIC-CRT-0235","REQ-QUIC-CRT-0236","REQ-QUIC-CRT-0237","REQ-QUIC-CRT-0238","REQ-QUIC-CRT-0239","REQ-QUIC-CRT-0240"'
        '"REQ-QUIC-CRT-0198",' = '"REQ-QUIC-CRT-0235",'
        '"REQ-QUIC-CRT-0199",' = '"REQ-QUIC-CRT-0236",'
        '"REQ-QUIC-CRT-0200",' = '"REQ-QUIC-CRT-0237",'
        '"REQ-QUIC-CRT-0201"' =
            '"REQ-QUIC-CRT-0238", "REQ-QUIC-CRT-0239", "REQ-QUIC-CRT-0240"'
        '"minItems": 4,' = '"minItems": 6,'
        '"maxItems": 4,' = '"maxItems": 6,'
        '"ARC-QUIC-CRT-0089"' = '"ARC-QUIC-CRT-0113"'
        '"WI-QUIC-CRT-0090"' = '"WI-QUIC-CRT-0114"'
        '"VER-QUIC-CRT-0091"' = '"VER-QUIC-CRT-0115"'
    }

Copy-SchemaVariant `
    'adaptive-runtime-effective-behavior-catalog-v2.schema.json' `
    'adaptive-runtime-effective-behavior-catalog-v3.schema.json' @{
        'adaptive-runtime-effective-behavior-catalog-v2' =
            'adaptive-runtime-effective-behavior-catalog-v3'
        'Effective Behavior Catalog v2' = 'Effective Behavior Catalog v3'
        '"document_version": { "const": 2 }' =
            '"document_version": { "const": 3 }'
        '"reviewed_version": { "const": 2 }' =
            '"reviewed_version": { "const": 3 }'
        '"behavior_catalog_version": 2' = '"behavior_catalog_version": 3'
        '"application_send_turn_planning"' =
            '"application_send_turn_planning", "oversized_write_admission_quantum", "queued_send_burst_budget"'
        '"conservative"' =
            '"conservative", "single_fragment", "bounded_multi_fragment", "single_datagram"'
        '"send_turn"]' = '"send_turn", "logical_write"]'
        '"minItems": 5' = '"minItems": 9'
        '"minItems": 6' = '"minItems": 11'
    }

Copy-SchemaVariant `
    'adaptive-runtime-policy-relationship-graph-v2.schema.json' `
    'adaptive-runtime-policy-relationship-graph-v3.schema.json' @{
        'adaptive-runtime-policy-relationship-graph-v2' =
            'adaptive-runtime-policy-relationship-graph-v3'
        'Relationship Graph v2' = 'Relationship Graph v3'
        '"document_version": { "const": 2 }' =
            '"document_version": { "const": 3 }'
        '"reviewed_version": { "const": 2 }' =
            '"reviewed_version": { "const": 3 }'
        '"application_send_turn_planning"]' =
            '"application_send_turn_planning", "oversized_write_admission_quantum", "queued_send_burst_budget"]'
    }

Copy-SchemaVariant `
    'adaptive-runtime-combination-constraint-catalog-v1.schema.json' `
    'adaptive-runtime-combination-constraint-catalog-v2.schema.json' @{
        'adaptive-runtime-combination-constraint-catalog-v1' =
            'adaptive-runtime-combination-constraint-catalog-v2'
        'Constraint Catalog v1' = 'Constraint Catalog v2'
        '"document_version": { "type": "integer", "const": 1 }' =
            '"document_version": { "type": "integer", "const": 2 }'
        '"REQ-QUIC-CRT-0198",' = '"REQ-QUIC-CRT-0235",'
        '"REQ-QUIC-CRT-0199",' = '"REQ-QUIC-CRT-0236",'
        '"REQ-QUIC-CRT-0200",' = '"REQ-QUIC-CRT-0237",'
        '"REQ-QUIC-CRT-0201"' =
            '"REQ-QUIC-CRT-0238", "REQ-QUIC-CRT-0239", "REQ-QUIC-CRT-0240"'
        '"minItems": 4,' = '"minItems": 6,'
        '"maxItems": 4,' = '"maxItems": 6,'
        '"ARC-QUIC-CRT-0089"' = '"ARC-QUIC-CRT-0113"'
        '"WI-QUIC-CRT-0090"' = '"WI-QUIC-CRT-0114"'
        '"VER-QUIC-CRT-0091"' = '"VER-QUIC-CRT-0115"'
        '"application_send_turn_planning"' =
            '"application_send_turn_planning", "oversized_write_admission_quantum", "queued_send_burst_budget"'
    }

Copy-SchemaVariant `
    'adaptive-runtime-experiment-family-catalog-v2.schema.json' `
    'adaptive-runtime-experiment-family-catalog-v3.schema.json' @{
        'adaptive-runtime-experiment-family-catalog-v2' =
            'adaptive-runtime-experiment-family-catalog-v3'
        'Family Catalog v2' = 'Family Catalog v3'
        '"document_version": { "const": 2 }' =
            '"document_version": { "const": 3 }'
        '"application_send_turn_planning"]' =
            '"application_send_turn_planning", "oversized_write_admission_quantum", "queued_send_burst_budget"]'
        '"conservative"' =
            '"conservative", "single_fragment", "bounded_multi_fragment", "single_datagram"'
        '"relationship_refs": { "type": "array", "minItems": 1,' =
            '"relationship_refs": { "type": "array", "minItems": 0,'
    }

Copy-SchemaVariant `
    'adaptive-runtime-actuation-mechanism-capture-v1.schema.json' `
    'adaptive-runtime-actuation-mechanism-capture-v2.schema.json' @{
        'adaptive-runtime-actuation-mechanism-capture-v1' =
            'adaptive-runtime-actuation-mechanism-capture-v2'
        'mechanism capture v1' = 'mechanism capture v2'
        '"document_version": { "const": 1 }' =
            '"document_version": { "const": 2 }'
        '"application_send_batch_formation",' =
            '"application_send_batch_formation", "oversized_write_admission_quantum", "queued_send_burst_budget",'
        '"single_eligible", "memory_conservative"' =
            '"single_eligible", "memory_conservative", "single_fragment", "bounded_multi_fragment", "single_datagram"'
        '"packet_plan", "combined_send"' =
            '"packet_plan", "combined_send", "logical_write", "send_turn"'
    }

Copy-SchemaVariant `
    'adaptive-runtime-actuation-proof-evidence-v1.schema.json' `
    'adaptive-runtime-actuation-proof-evidence-v2.schema.json' @{
        'adaptive-runtime-actuation-proof-evidence-v1' =
            'adaptive-runtime-actuation-proof-evidence-v2'
        'proof evidence v1' = 'proof evidence v2'
        '"document_version": { "const": 1 }' =
            '"document_version": { "const": 2 }'
        '"application_send_batch_formation",' =
            '"application_send_batch_formation", "oversized_write_admission_quantum", "queued_send_burst_budget",'
        '"single_eligible", "memory_conservative"' =
            '"single_eligible", "memory_conservative", "single_fragment", "bounded_multi_fragment", "single_datagram"'
    }

Copy-SchemaVariant `
    'adaptive-runtime-operation-evidence-v3.schema.json' `
    'adaptive-runtime-operation-evidence-v4.schema.json' @{
        'adaptive-runtime-operation-evidence-v3' =
            'adaptive-runtime-operation-evidence-v4'
        'Operation Evidence v3' = 'Operation Evidence v4'
        '"document_version": { "const": 3 }' =
            '"document_version": { "const": 4 }'
        '"packet_plan", "combined_send"' =
            '"packet_plan", "combined_send", "logical_write", "send_turn"'
    }

Copy-SchemaVariant `
    'adaptive-runtime-compiled-execution-manifest-v1.schema.json' `
    'adaptive-runtime-compiled-execution-manifest-v2.schema.json' @{
        'adaptive-runtime-compiled-execution-manifest-v1' =
            'adaptive-runtime-compiled-execution-manifest-v2'
        'Compiled Execution Manifest v1' =
            'Compiled Execution Manifest v2'
        '"document_version": { "type": "integer", "const": 1 }' =
            '"document_version": { "type": "integer", "const": 2 }'
        '"application_send_turn_planning"' =
            '"application_send_turn_planning", "oversized_write_admission_quantum", "queued_send_burst_budget"'
    }

Copy-SchemaVariant `
    'adaptive-runtime-experiment-plan-validation-v2.schema.json' `
    'adaptive-runtime-experiment-plan-validation-v3.schema.json' @{
        'adaptive-runtime-experiment-plan-validation-v2' =
            'adaptive-runtime-experiment-plan-validation-v3'
        'Plan Validation v2' = 'Plan Validation v3'
        '"document_version": { "type": "integer", "const": 2 }' =
            '"document_version": { "type": "integer", "const": 3 }'
    }

$axisV1 = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-policy-axis-contracts-v1.json')
$axisContracts = @($axisV1.axis_contracts | ForEach-Object {
    $copy = $_ | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
    $copy.trace_references = $trace
    $copy
})
$axisContracts += [pscustomobject][ordered]@{
    axis_id = 'oversized_write_admission_quantum'
    status = 'implemented'
    executable = $true
    policy_values = @(
        'legacy_current',
        'single_fragment',
        'bounded_multi_fragment'
    )
    authority = [pscustomobject][ordered]@{
        owner = 'connection_actor'
        scope = 'logical_write'
        boundary = 'after_oversized_write_classification_before_fragment_dispatch'
        latch = 'logical_write_terminal_latch'
    }
    scope = 'logical_write'
    boundary = 'after_oversized_write_classification_before_fragment_dispatch'
    latch = 'logical_write_terminal_latch'
    selected_value_compatibility = @(
        'legacy_current','single_fragment','bounded_multi_fragment' |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    selected_value = $_
                    candidate_value = $_
                    compatible = $true
                    comparison_mode = 'applied'
                    reason = 'The seam selected value is the generic pre-safety candidate.'
                }
            })
    canonical_predicates = @(
        [pscustomobject][ordered]@{
            predicate_id = 'predicate.oversized_write.activation'
            description = 'The logical write exceeds the retained maximum stream write chunk.'
        },
        [pscustomobject][ordered]@{
            predicate_id = 'predicate.oversized_write.single_fragment_distinct'
            description = 'Two fragments are legal and the retained selector would choose two.'
        },
        [pscustomobject][ordered]@{
            predicate_id = 'predicate.oversized_write.bounded_multi_fragment_distinct'
            description = 'Two fragments are legal and the retained selector would choose one.'
        }
    )
    safety_clamps = @(
        [pscustomobject][ordered]@{
            clamp_id = 'clamp.oversized_write.legal_quantum'
            description = 'The applied quantum cannot exceed the legal fragment quantum.'
        },
        [pscustomobject][ordered]@{
            clamp_id = 'clamp.oversized_write.lifecycle'
            description = 'Cancellation, disposal, terminal, ownership, and resource guards remain authoritative.'
        }
    )
    readiness = [pscustomobject][ordered]@{
        forceable = $true
        rollback_proof_status = 'represented'
        actuation_validation_status = 'pending'
        behavior_distinctness_status = 'proven'
        activation_predicate_refs = @('predicate.oversized_write.activation')
        behavior_distinctness_predicate_refs = @(
            'predicate.oversized_write.single_fragment_distinct',
            'predicate.oversized_write.bounded_multi_fragment_distinct')
        required_capability_ids = @(
            'adaptive_runtime_internal_forced_mode',
            'single_behavior_distinct_axis_only')
    }
    notes = @(
        'Candidate proofs are external-review pending.',
        'This contract does not authorize multi-axis execution.'
    )
    trace_references = $trace
}
$axisContracts += [pscustomobject][ordered]@{
    axis_id = 'queued_send_burst_budget'
    status = 'implemented'
    executable = $true
    policy_values = @('legacy_current','single_datagram')
    authority = [pscustomobject][ordered]@{
        owner = 'connection_actor'
        scope = 'send_turn'
        boundary = 'after_authoritative_queued_send_budget_before_actor_turn_emission'
        latch = 'actor_turn_latch'
    }
    scope = 'send_turn'
    boundary = 'after_authoritative_queued_send_budget_before_actor_turn_emission'
    latch = 'actor_turn_latch'
    selected_value_compatibility = @(
        'legacy_current','single_datagram' | ForEach-Object {
            [pscustomobject][ordered]@{
                selected_value = $_
                candidate_value = $_
                compatible = $true
                comparison_mode = 'applied'
                reason = 'The seam selected value is the generic pre-safety candidate.'
            }
        })
    canonical_predicates = @(
        [pscustomobject][ordered]@{
            predicate_id = 'predicate.queued_send.legal_budget_gt_one'
            description = 'The legal datagram budget exceeds one and follow-on queued work exists.'
        },
        [pscustomobject][ordered]@{
            predicate_id = 'predicate.queued_send.lower_only'
            description = 'single_datagram may only lower an authoritative legal datagram budget.'
        }
    )
    safety_clamps = @(
        [pscustomobject][ordered]@{
            clamp_id = 'clamp.queued_send.transport_authority'
            description = 'Congestion, pacing, recovery, anti-amplification, endpoint, handshake, flow-control, and lifecycle guards remain authoritative.'
        },
        [pscustomobject][ordered]@{
            clamp_id = 'clamp.queued_send.one_datagram'
            description = 'single_datagram cannot emit more than one datagram in the latched actor turn.'
        }
    )
    readiness = [pscustomobject][ordered]@{
        forceable = $true
        rollback_proof_status = 'represented'
        actuation_validation_status = 'pending'
        behavior_distinctness_status = 'proven'
        activation_predicate_refs = @(
            'predicate.queued_send.legal_budget_gt_one')
        behavior_distinctness_predicate_refs = @(
            'predicate.queued_send.legal_budget_gt_one')
        required_capability_ids = @(
            'adaptive_runtime_internal_forced_mode',
            'single_behavior_distinct_axis_only')
    }
    notes = @(
        'Candidate proof is external-review pending.',
        'This contract does not authorize multi-axis execution.'
    )
    trace_references = $trace
}
$axisCatalog = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-policy-axis-contract-v2'
    document_id = 'adaptive_runtime_policy_axis_contracts_v2'
    document_version = 2
    content_sha256 = '0' * 64
    trace_references = $trace
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    axis_contracts = @($axisContracts | Sort-Object axis_id)
}
[void](Set-AdaptiveRuntimeDocumentHash $axisCatalog)
Write-Document $axisCatalog `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-axis-contracts-v2.json'

$behaviorV2 = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-effective-behavior-catalog-v2.json')
$behaviors = @($behaviorV2.effective_behaviors | ForEach-Object {
    $copy = $_ | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100
    $copy.reviewed_version = 3
    $copy
})
$behaviors += @(
    [pscustomobject][ordered]@{
        effective_behavior_id =
            'behavior.oversized_write_admission_quantum.one_fragment_per_turn'
        axis_id = 'oversized_write_admission_quantum'
        derivation_mode = 'mutually_exclusive'
        reviewed_version = 3
        operation_scope = [pscustomobject][ordered]@{
            operation_kind = 'logical_write'
            boundary = 'logical_write_admission'
            scope_version = 1
        }
        mechanism_event_ids = @(
            'mechanism_event.oversized_write.one_fragment_per_turn')
    },
    [pscustomobject][ordered]@{
        effective_behavior_id =
            'behavior.oversized_write_admission_quantum.bounded_two_fragments_per_turn'
        axis_id = 'oversized_write_admission_quantum'
        derivation_mode = 'mutually_exclusive'
        reviewed_version = 3
        operation_scope = [pscustomobject][ordered]@{
            operation_kind = 'logical_write'
            boundary = 'logical_write_admission'
            scope_version = 1
        }
        mechanism_event_ids = @(
            'mechanism_event.oversized_write.bounded_two_fragments_per_turn')
    },
    [pscustomobject][ordered]@{
        effective_behavior_id =
            'behavior.queued_send_burst_budget.legal_actor_turn_budget'
        axis_id = 'queued_send_burst_budget'
        derivation_mode = 'mutually_exclusive'
        reviewed_version = 3
        operation_scope = [pscustomobject][ordered]@{
            operation_kind = 'send_turn'
            boundary = 'queued_send_actor_turn'
            scope_version = 1
        }
        mechanism_event_ids = @(
            'mechanism_event.queued_send.legal_actor_turn_budget')
    },
    [pscustomobject][ordered]@{
        effective_behavior_id =
            'behavior.queued_send_burst_budget.single_datagram_cap'
        axis_id = 'queued_send_burst_budget'
        derivation_mode = 'mutually_exclusive'
        reviewed_version = 3
        operation_scope = [pscustomobject][ordered]@{
            operation_kind = 'send_turn'
            boundary = 'queued_send_actor_turn'
            scope_version = 1
        }
        mechanism_event_ids = @(
            'mechanism_event.queued_send.single_datagram_cap')
    }
)
$valueSets = @($behaviorV2.value_behavior_sets)
$commonOutcomes = @(
    'outcome.inactive','outcome.fallback','outcome.clamped',
    'outcome.invalid','outcome.error','outcome.unclassifiable')
$valueSets += @(
    [pscustomobject][ordered]@{
        axis_id = 'oversized_write_admission_quantum'
        policy_value = 'legacy_current'
        primary_expected_behavior_ids = @(
            'behavior.oversized_write_admission_quantum.one_fragment_per_turn',
            'behavior.oversized_write_admission_quantum.bounded_two_fragments_per_turn')
        possible_effective_behavior_ids = @(
            'behavior.oversized_write_admission_quantum.one_fragment_per_turn',
            'behavior.oversized_write_admission_quantum.bounded_two_fragments_per_turn')
        non_behavior_outcome_ids = $commonOutcomes
        activation_signature_id =
            'activation.oversized_write.retained_selector_context'
        multiple_primary_permitted = $false
    },
    [pscustomobject][ordered]@{
        axis_id = 'oversized_write_admission_quantum'
        policy_value = 'single_fragment'
        primary_expected_behavior_ids = @(
            'behavior.oversized_write_admission_quantum.one_fragment_per_turn')
        possible_effective_behavior_ids = @(
            'behavior.oversized_write_admission_quantum.one_fragment_per_turn')
        non_behavior_outcome_ids = $commonOutcomes
        activation_signature_id =
            'activation.oversized_write.legacy_would_select_two'
        multiple_primary_permitted = $false
    },
    [pscustomobject][ordered]@{
        axis_id = 'oversized_write_admission_quantum'
        policy_value = 'bounded_multi_fragment'
        primary_expected_behavior_ids = @(
            'behavior.oversized_write_admission_quantum.bounded_two_fragments_per_turn')
        possible_effective_behavior_ids = @(
            'behavior.oversized_write_admission_quantum.bounded_two_fragments_per_turn',
            'behavior.oversized_write_admission_quantum.one_fragment_per_turn')
        non_behavior_outcome_ids = $commonOutcomes
        activation_signature_id =
            'activation.oversized_write.legacy_would_select_one_two_legal'
        multiple_primary_permitted = $false
    },
    [pscustomobject][ordered]@{
        axis_id = 'queued_send_burst_budget'
        policy_value = 'legacy_current'
        primary_expected_behavior_ids = @(
            'behavior.queued_send_burst_budget.legal_actor_turn_budget')
        possible_effective_behavior_ids = @(
            'behavior.queued_send_burst_budget.legal_actor_turn_budget')
        non_behavior_outcome_ids = $commonOutcomes
        activation_signature_id =
            'activation.queued_send.actor_turn_with_legal_send'
        multiple_primary_permitted = $false
    },
    [pscustomobject][ordered]@{
        axis_id = 'queued_send_burst_budget'
        policy_value = 'single_datagram'
        primary_expected_behavior_ids = @(
            'behavior.queued_send_burst_budget.single_datagram_cap')
        possible_effective_behavior_ids = @(
            'behavior.queued_send_burst_budget.single_datagram_cap',
            'behavior.queued_send_burst_budget.legal_actor_turn_budget')
        non_behavior_outcome_ids = $commonOutcomes
        activation_signature_id =
            'activation.queued_send.legal_budget_gt_one'
        multiple_primary_permitted = $false
    }
)
$behaviorCatalog = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-effective-behavior-catalog-v3'
    document_id = 'adaptive_runtime_effective_behavior_catalog_v3'
    document_version = 3
    content_sha256 = '0' * 64
    trace_references = $trace
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    effective_behaviors = @($behaviors | Sort-Object effective_behavior_id)
    value_behavior_sets = @($valueSets |
        Sort-Object axis_id, policy_value)
    outcome_definitions = @($behaviorV2.outcome_definitions |
        Sort-Object outcome_id)
}
[void](Set-AdaptiveRuntimeDocumentHash $behaviorCatalog)
Write-Document $behaviorCatalog `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-effective-behavior-catalog-v3.json'

$relationshipV2 = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-policy-relationship-graph-v2.json')
$edges = @($relationshipV2.directed_edges | ForEach-Object {
    [pscustomobject][ordered]@{
        edge_id = ([string]$_.edge_id).Replace('.v2','.v3')
        source_axis_id = $_.source_axis_id
        target_axis_id = $_.target_axis_id
        relationship_type = $_.relationship_type
        mechanism = $_.mechanism
        confidence = $_.confidence
        evidence_level = $_.evidence_level
        evidence_references = $_.evidence_references
        experiment_requirement = $_.experiment_requirement
        reviewed_version = 3
        behavior_condition_ids = $_.behavior_condition_ids
    }
})
$edges += [pscustomobject][ordered]@{
    edge_id = 'edge.oversized_to_batch.supplies_work.v3'
    source_axis_id = 'oversized_write_admission_quantum'
    target_axis_id = 'application_send_batch_formation'
    relationship_type = 'supplies_work'
    mechanism = 'Admitted logical-write fragments enter the application-send queue consumed by batch formation.'
    confidence = 'proven'
    evidence_level = 'mechanism_test'
    evidence_references = @(
        'src/Incursa.Quic/QuicConnectionRuntime.Streams.cs',
        'tests/Incursa.Quic.Tests/RequirementHomes/CRT/REQ-QUIC-CRT-0180.cs')
    experiment_requirement = 'varied'
    reviewed_version = 3
    behavior_condition_ids = @(
        'condition.oversized_fragment_enters_batch_queue')
}
$relationship = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-policy-relationship-graph-v3'
    document_id = 'adaptive_runtime_policy_relationship_graph_v3'
    document_version = 3
    content_sha256 = '0' * 64
    trace_references = $trace
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    directed_edges = @($edges | Sort-Object edge_id)
    nominated_hyperedges = @()
}
[void](Set-AdaptiveRuntimeDocumentHash $relationship)
Write-Document $relationship `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-relationship-graph-v3.json'

$constraintsV1 = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-combination-constraint-catalog-v1.json')
$constraints = @($constraintsV1.combination_constraints)
$constraints += @(
    [pscustomobject][ordered]@{
        constraint_id =
            'constraint.send_admission_composition.multi_axis_capability'
        family_id = 'send_admission_composition'
        experiment_types = @('interaction_screen')
        fixed_axis_ids = @(
            'application_send_turn_planning',
            'queued_send_burst_budget')
        varied_axis_ids = @(
            'oversized_write_admission_quantum',
            'application_send_batch_formation',
            'buffer_copy_coalescing')
        predicate_refs = @(
            'predicate.oversized_write.activation',
            'predicate.batch.distinct_only_when_multiple_eligible',
            'predicate.buffer.lower_only')
        guard_refs = @(
            'guard.single_behavior_distinct_axis_only',
            'guard.active_behavior_false',
            'guard.measurement_false')
        legality = 'legal'
        capability_state = 'blocked'
        equivalence_state = 'not_equivalent'
        measurement_authorized = $false
        promotion_deferred = $true
        notes = @(
            'Configured cells are planning-only until value-specific proofs are reviewed and an exact capability is authorized.',
            'Raw oversized fragments structurally prevent same-operation batch and buffer distinctness.')
    },
    [pscustomobject][ordered]@{
        constraint_id = 'constraint.queued_send_burst.single_axis'
        family_id = 'queued_send_burst_correctness'
        experiment_types = @(
            'actuation_validation',
            'isolated_counterfactual')
        fixed_axis_ids = @(
            'application_send_turn_planning',
            'application_send_batch_formation',
            'buffer_copy_coalescing',
            'oversized_write_admission_quantum')
        varied_axis_ids = @('queued_send_burst_budget')
        predicate_refs = @(
            'predicate.queued_send.legal_budget_gt_one')
        guard_refs = @(
            'guard.single_behavior_distinct_axis_only',
            'guard.active_behavior_false',
            'guard.measurement_false')
        legality = 'legal'
        capability_state = 'eligible'
        equivalence_state = 'not_equivalent'
        measurement_authorized = $false
        promotion_deferred = $true
        notes = @(
            'Only independent correctness-only plans are executable.',
            'All adjacent axes remain legacy_current.')
    }
)
$constraintCatalog = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-combination-constraint-catalog-v2'
    document_id = 'adaptive_runtime_combination_constraint_catalog_v2'
    document_version = 2
    content_sha256 = '0' * 64
    trace_references = $trace
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    combination_constraints = @($constraints | Sort-Object constraint_id)
}
[void](Set-AdaptiveRuntimeDocumentHash $constraintCatalog)
Write-Document $constraintCatalog `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-combination-constraint-catalog-v2.json'

$familyV2 = Read-AdaptiveRuntimeJsonDocument (
    Join-Path $catalogRoot 'adaptive-runtime-experiment-family-catalog-v2.json')
$families = @($familyV2.experiment_families)
$families += @(
    [pscustomobject][ordered]@{
        family_id = 'send_admission_composition'
        included_axis_ids = @(
            'oversized_write_admission_quantum',
            'application_send_batch_formation',
            'buffer_copy_coalescing')
        fixed_axis_requirements = @(
            [pscustomobject][ordered]@{
                axis_id = 'application_send_turn_planning'
                configured_value = 'legacy_current'
            },
            [pscustomobject][ordered]@{
                axis_id = 'queued_send_burst_budget'
                configured_value = 'legacy_current'
            })
        outer_context_ids = @(
            'context.send_admission.legacy_selector_band',
            'context.send_admission.legal_prefix_shape')
        workload_archetype_ids = @(
            'workload.send_admission.correctness_fixture')
        primary_metric_ids = @('metric.correctness.mechanism_attribution')
        guardrail_metric_ids = @(
            'metric.correctness.safety_fallback',
            'metric.correctness.logical_write_completion')
        predicate_refs = @(
            'predicate.oversized_write.activation',
            'predicate.batch.distinct_only_when_multiple_eligible',
            'predicate.buffer.lower_only')
        relationship_refs = @(
            'edge.oversized_to_batch.supplies_work.v3',
            'edge.batch_to_buffer.supplies_work.v3')
        constraint_refs = @(
            'constraint.send_admission_composition.multi_axis_capability')
        history_reset_requirements = @(
            'history.send_admission.reset_each_correctness_cell')
        actuation_proof_refs = @(
            $familyV2.reviewed_actuation_proofs.proof_id)
        supported_experiment_types = @(
            'actuation_validation',
            'isolated_counterfactual',
            'interaction_screen')
        blocked_experiment_types = @('feedback_loop','profile_validation')
        measurement_authorized = $false
        promotion_status = 'deferred'
    },
    [pscustomobject][ordered]@{
        family_id = 'queued_send_burst_correctness'
        included_axis_ids = @('queued_send_burst_budget')
        fixed_axis_requirements = @(
            [pscustomobject][ordered]@{
                axis_id = 'application_send_turn_planning'
                configured_value = 'legacy_current'
            },
            [pscustomobject][ordered]@{
                axis_id = 'application_send_batch_formation'
                configured_value = 'legacy_current'
            },
            [pscustomobject][ordered]@{
                axis_id = 'buffer_copy_coalescing'
                configured_value = 'legacy_current'
            },
            [pscustomobject][ordered]@{
                axis_id = 'oversized_write_admission_quantum'
                configured_value = 'legacy_current'
            })
        outer_context_ids = @('context.queued_send.legal_budget')
        workload_archetype_ids = @(
            'workload.queued_send.correctness_fixture')
        primary_metric_ids = @('metric.correctness.mechanism_attribution')
        guardrail_metric_ids = @(
            'metric.correctness.transport_authority')
        predicate_refs = @(
            'predicate.queued_send.legal_budget_gt_one')
        relationship_refs = @()
        constraint_refs = @(
            'constraint.queued_send_burst.single_axis')
        history_reset_requirements = @(
            'history.queued_send.reset_each_correctness_cell')
        actuation_proof_refs = @()
        supported_experiment_types = @(
            'actuation_validation',
            'isolated_counterfactual')
        blocked_experiment_types = @(
            'interaction_screen','feedback_loop','profile_validation')
        measurement_authorized = $false
        promotion_status = 'deferred'
    }
)
$familyCatalog = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-experiment-family-catalog-v3'
    document_id = 'adaptive_runtime_experiment_family_catalog_v3'
    document_version = 3
    content_sha256 = '0' * 64
    trace_references = $trace
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    reviewed_actuation_proofs = @($familyV2.reviewed_actuation_proofs)
    experiment_families = @($families | Sort-Object family_id)
}
[void](Set-AdaptiveRuntimeDocumentHash $familyCatalog)
Write-Document $familyCatalog `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-experiment-family-catalog-v3.json'

$admissionCells = [Collections.Generic.List[object]]::new()
$order = 0
foreach ($oversized in @(
    'legacy_current','single_fragment','bounded_multi_fragment')) {
    foreach ($batch in @('legacy_current','single_eligible')) {
        foreach ($buffer in @('legacy_current','memory_conservative')) {
            $nonLegacy = @($oversized,$batch,$buffer |
                Where-Object { $_ -ne 'legacy_current' }).Count
            $state = if ($nonLegacy -le 1) {
                'correctness_single_axis_candidate'
            }
            else {
                'capability_pending'
            }
            $reasons = [Collections.Generic.List[string]]::new()
            if ($nonLegacy -gt 1) {
                $reasons.Add('multi_axis_execution_not_authorized')
            }
            if ($oversized -ne 'legacy_current' -and
                ($batch -ne 'legacy_current' -or
                 $buffer -ne 'legacy_current')) {
                $reasons.Add(
                    'oversized_fragment_same_operation_structural_inactivity')
            }
            $admissionCells.Add([pscustomobject][ordered]@{
                cell_id = ('cell.send_admission.{0:d2}' -f $order)
                cell_order = $order
                axis_values = @(
                    [pscustomobject][ordered]@{
                        axis_id = 'oversized_write_admission_quantum'
                        policy_value = $oversized
                    },
                    [pscustomobject][ordered]@{
                        axis_id = 'application_send_batch_formation'
                        policy_value = $batch
                    },
                    [pscustomobject][ordered]@{
                        axis_id = 'buffer_copy_coalescing'
                        policy_value = $buffer
                    })
                classification = $state
                reason_codes = @($reasons | Sort-Object)
                measurement_authorized = $false
                active_behavior_authorization = $false
            })
            $order++
        }
    }
}
$queuedCells = @(
    [pscustomobject][ordered]@{
        cell_id = 'cell.queued_send.00'
        cell_order = 0
        axis_values = @([pscustomobject][ordered]@{
            axis_id = 'queued_send_burst_budget'
            policy_value = 'legacy_current'
        })
        classification = 'correctness_single_axis_candidate'
        reason_codes = @()
        measurement_authorized = $false
        active_behavior_authorization = $false
    },
    [pscustomobject][ordered]@{
        cell_id = 'cell.queued_send.01'
        cell_order = 1
        axis_values = @([pscustomobject][ordered]@{
            axis_id = 'queued_send_burst_budget'
            policy_value = 'single_datagram'
        })
        classification = 'correctness_single_axis_candidate'
        reason_codes = @()
        measurement_authorized = $false
        active_behavior_authorization = $false
    })

$cellSpace = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-factor-cell-space-v1'
    document_id = 'adaptive_runtime_factor_cell_space_v1'
    document_version = 1
    content_sha256 = '0' * 64
    catalog_refs = @(
        New-DocumentRef $axisCatalog
        New-DocumentRef $behaviorCatalog
        New-DocumentRef $relationship
        New-DocumentRef $constraintCatalog
        New-DocumentRef $familyCatalog
    )
    generation_mode = 'exhaustive_explicit'
    covering_array_generator_implemented = $false
    covering_array_trigger_effective_cell_count = 65
    family_spaces = @(
        [pscustomobject][ordered]@{
            family_id = 'send_admission_composition'
            raw_configured_cell_count = 12
            after_illegal_removal_count = 12
            after_capability_filter_count = 5
            structurally_inactive_cell_count = 6
            safety_clamped_cell_count = 0
            expected_equivalence_group_count = 0
            behavior_distinct_effective_cell_count = 4
            verification_only_cell_count = 8
            measurement_blocked_cell_count = 12
            correctness_executable_cell_count = 5
            planned_cells = @($admissionCells)
        },
        [pscustomobject][ordered]@{
            family_id = 'queued_send_burst_correctness'
            raw_configured_cell_count = 2
            after_illegal_removal_count = 2
            after_capability_filter_count = 2
            structurally_inactive_cell_count = 0
            safety_clamped_cell_count = 0
            expected_equivalence_group_count = 0
            behavior_distinct_effective_cell_count = 2
            verification_only_cell_count = 0
            measurement_blocked_cell_count = 2
            correctness_executable_cell_count = 2
            planned_cells = $queuedCells
        })
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $trace
}
[void](Set-AdaptiveRuntimeDocumentHash $cellSpace)
Write-Document $cellSpace `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-factor-cell-space-v1.json'

$admissionCellsV2 = @($admissionCells | ForEach-Object {
    $isBaseline = @($_.axis_values |
        Where-Object policy_value -ne 'legacy_current').Count -eq 0
    $hasOperationLocalNoncoactivation =
        $_.reason_codes -contains
            'oversized_fragment_same_operation_structural_inactivity'
    $annotations = [Collections.Generic.List[string]]::new()
    $annotations.Add('measurement_blocked')
    if ($isBaseline) {
        $annotations.Add('verification_only')
    }
    if ($hasOperationLocalNoncoactivation) {
        $annotations.Add('operation_local_noncoactivation')
    }
    $reasonCodes = @($_.reason_codes | ForEach-Object {
        if ($_ -eq
            'oversized_fragment_same_operation_structural_inactivity') {
            'operation_local_noncoactivation'
        }
        else {
            $_
        }
    } | Sort-Object -Unique)
    [pscustomobject][ordered]@{
        cell_id = $_.cell_id
        cell_order = $_.cell_order
        axis_values = @($_.axis_values)
        classification = $_.classification
        annotations = @($annotations | Sort-Object)
        reason_codes = $reasonCodes
        measurement_authorized = $false
        active_behavior_authorization = $false
    }
})
$queuedCellsV2 = @($queuedCells | ForEach-Object {
    $isBaseline = @($_.axis_values |
        Where-Object policy_value -ne 'legacy_current').Count -eq 0
    $annotations = [Collections.Generic.List[string]]::new()
    $annotations.Add('measurement_blocked')
    if ($isBaseline) {
        $annotations.Add('verification_only')
    }
    [pscustomobject][ordered]@{
        cell_id = $_.cell_id
        cell_order = $_.cell_order
        axis_values = @($_.axis_values)
        classification = $_.classification
        annotations = @($annotations | Sort-Object)
        reason_codes = @($_.reason_codes)
        measurement_authorized = $false
        active_behavior_authorization = $false
    }
})
$cellSpaceV2 = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-factor-cell-space-v2'
    document_id = 'adaptive_runtime_factor_cell_space_v2'
    document_version = 2
    content_sha256 = '0' * 64
    catalog_refs = @(
        New-DocumentRef $axisCatalog
        New-DocumentRef $behaviorCatalog
        New-DocumentRef $relationship
        New-DocumentRef $constraintCatalog
        New-DocumentRef $familyCatalog
    )
    generation_mode = 'exhaustive_explicit'
    covering_array_generator_implemented = $false
    covering_array_trigger_effective_cell_count = 65
    family_spaces = @(
        [pscustomobject][ordered]@{
            family_id = 'send_admission_composition'
            raw_configured_cell_count = 12
            after_illegal_removal_count = 12
            after_capability_filter_count = 5
            expected_equivalence_group_count = 0
            distinct_effective_cell_count_including_baseline = 5
            nonlegacy_behavior_distinct_treatment_value_count = 4
            partition_counts = [pscustomobject][ordered]@{
                correctness_executable = 5
                capability_pending = 7
                cell_structurally_inactive = 0
                rejected = 0
            }
            annotation_counts = [pscustomobject][ordered]@{
                measurement_blocked = 12
                verification_only = 1
                operation_local_noncoactivation = 6
                safety_clamped = 0
            }
            annotation_counts_overlap_partitions = $true
            planned_cells = $admissionCellsV2
        },
        [pscustomobject][ordered]@{
            family_id = 'queued_send_burst_correctness'
            raw_configured_cell_count = 2
            after_illegal_removal_count = 2
            after_capability_filter_count = 2
            expected_equivalence_group_count = 0
            distinct_effective_cell_count_including_baseline = 2
            nonlegacy_behavior_distinct_treatment_value_count = 1
            partition_counts = [pscustomobject][ordered]@{
                correctness_executable = 2
                capability_pending = 0
                cell_structurally_inactive = 0
                rejected = 0
            }
            annotation_counts = [pscustomobject][ordered]@{
                measurement_blocked = 2
                verification_only = 1
                operation_local_noncoactivation = 0
                safety_clamped = 0
            }
            annotation_counts_overlap_partitions = $true
            planned_cells = $queuedCellsV2
        })
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    trace_references = $trace
}
[void](Set-AdaptiveRuntimeDocumentHash $cellSpaceV2)
Write-Document $cellSpaceV2 `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-factor-cell-space-v2.json'

$sourceRefs = @(
    New-DocumentRef $axisCatalog
    New-DocumentRef $behaviorCatalog
    New-DocumentRef $relationship
    New-DocumentRef $constraintCatalog
    New-DocumentRef $familyCatalog
)
$admissionTreatments = @()
$treatmentOrder = @()
$treatmentIndex = 0
foreach ($pair in @(
    @('oversized_write_admission_quantum','legacy_current'),
    @('oversized_write_admission_quantum','single_fragment'),
    @('oversized_write_admission_quantum','bounded_multi_fragment'),
    @('application_send_batch_formation','legacy_current'),
    @('application_send_batch_formation','single_eligible'),
    @('buffer_copy_coalescing','legacy_current'),
    @('buffer_copy_coalescing','memory_conservative')
)) {
    $treatmentId = "treatment.$($pair[0]).$($pair[1])"
    $treatment = [ordered]@{
        treatment_id = $treatmentId
        order_index = $treatmentIndex
        axis_id = $pair[0]
        configured_value = $pair[1]
        candidate_value = $pair[1]
    }
    if ($pair[1] -ne 'legacy_current') {
        $treatment.forced_value = $pair[1]
    }
    $admissionTreatments += [pscustomobject]$treatment
    $treatmentOrder += $treatmentId
    $treatmentIndex++
}
$admissionPlannedCells = @($admissionCells | ForEach-Object {
    $axisValues = @($_.axis_values)
    [pscustomobject][ordered]@{
        cell_id = $_.cell_id
        cell_order = $_.cell_order
        treatment_ids = @($axisValues | ForEach-Object {
            "treatment.$($_.axis_id).$($_.policy_value)"
        })
        axis_ids = @($axisValues.axis_id)
        expected_equivalence_group_id = "declared.$($_.cell_id)"
        execution_state = 'blocked'
        performance_comparable = $false
        activation_expectation = 'reachable'
    }
})
$admissionPlan = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-experiment-plan-v1'
    document_id = 'adaptive_runtime_send_admission_explicit_plan_v1'
    document_version = 1
    content_sha256 = '0' * 64
    trace_references = $planTrace
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    experiment_plan_id = 'experiment_plan.send_admission.explicit.v1'
    experiment_type = 'interaction_screen'
    family_id = 'send_admission_composition'
    source_document_refs = $sourceRefs
    fixed_axis_ids = @(
        'application_send_turn_planning',
        'queued_send_burst_budget')
    varied_axis_ids = @(
        'oversized_write_admission_quantum',
        'application_send_batch_formation',
        'buffer_copy_coalescing')
    fixed_axis_values = @(
        [pscustomobject][ordered]@{
            axis_id = 'application_send_turn_planning'
            configured_value = 'legacy_current'
        },
        [pscustomobject][ordered]@{
            axis_id = 'queued_send_burst_budget'
            configured_value = 'legacy_current'
        })
    expected_capabilities = @(
        [pscustomobject][ordered]@{
            capability_id = 'adaptive_runtime_internal_forced_mode'
            expectation = 'required'
            resolution = 'deferred_to_manifest'
        },
        [pscustomobject][ordered]@{
            capability_id = 'single_behavior_distinct_axis_only'
            expectation = 'required'
            resolution = 'deferred_to_manifest'
        },
        [pscustomobject][ordered]@{
            capability_id = 'reviewed_send_admission_multi_axis_capability'
            expectation = 'required'
            resolution = 'pending'
        })
    required_predicate_refs = @(
        'predicate.oversized_write.activation',
        'predicate.oversized_write.single_fragment_distinct',
        'predicate.oversized_write.bounded_multi_fragment_distinct',
        'predicate.batch.distinct_only_when_multiple_eligible',
        'predicate.buffer.lower_only')
    treatments = $admissionTreatments
    treatment_order = $treatmentOrder
    planned_cells = $admissionPlannedCells
    execution_order_policy = 'deterministic'
    execution_status = 'blocked_by_capability'
    preserve_equivalent_cells_for_verification = $true
    notes = @(
        'Explicit dry-run planning only.',
        'New multi-axis execution, measurement, and active behavior are unauthorized.')
}
[void](Set-AdaptiveRuntimeDocumentHash $admissionPlan)
Write-Document $admissionPlan `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-send-admission-explicit-plan-v1.json'

$queuedTreatments = @(
    [pscustomobject][ordered]@{
        treatment_id = 'treatment.queued_send_burst_budget.legacy_current'
        order_index = 0
        axis_id = 'queued_send_burst_budget'
        configured_value = 'legacy_current'
        candidate_value = 'legacy_current'
    },
    [pscustomobject][ordered]@{
        treatment_id = 'treatment.queued_send_burst_budget.single_datagram'
        order_index = 1
        axis_id = 'queued_send_burst_budget'
        configured_value = 'single_datagram'
        forced_value = 'single_datagram'
        candidate_value = 'single_datagram'
    })
$queuedPlan = [pscustomobject][ordered]@{
    schema_version = 'adaptive-runtime-experiment-plan-v1'
    document_id = 'adaptive_runtime_queued_send_actuation_plan_v1'
    document_version = 1
    content_sha256 = '0' * 64
    trace_references = $planTrace
    active_behavior_authorization = $false
    performance_acceptance_authorization = $false
    experiment_plan_id = 'experiment_plan.queued_send.actuation.v1'
    experiment_type = 'actuation_validation'
    family_id = 'queued_send_burst_correctness'
    source_document_refs = $sourceRefs
    fixed_axis_ids = @(
        'application_send_turn_planning',
        'application_send_batch_formation',
        'buffer_copy_coalescing',
        'oversized_write_admission_quantum')
    varied_axis_ids = @('queued_send_burst_budget')
    fixed_axis_values = @(
        'application_send_turn_planning',
        'application_send_batch_formation',
        'buffer_copy_coalescing',
        'oversized_write_admission_quantum' | ForEach-Object {
            [pscustomobject][ordered]@{
                axis_id = $_
                configured_value = 'legacy_current'
            }
        })
    expected_capabilities = @(
        [pscustomobject][ordered]@{
            capability_id = 'adaptive_runtime_internal_forced_mode'
            expectation = 'required'
            resolution = 'deferred_to_manifest'
        },
        [pscustomobject][ordered]@{
            capability_id = 'single_behavior_distinct_axis_only'
            expectation = 'required'
            resolution = 'deferred_to_manifest'
        })
    required_predicate_refs = @(
        'predicate.queued_send.legal_budget_gt_one')
    treatments = $queuedTreatments
    treatment_order = @($queuedTreatments.treatment_id)
    planned_cells = @(
        [pscustomobject][ordered]@{
            cell_id = 'cell.queued_send.00'
            cell_order = 0
            treatment_ids = @(
                'treatment.queued_send_burst_budget.legacy_current')
            axis_ids = @('queued_send_burst_budget')
            expected_equivalence_group_id =
                'declared.cell.queued_send.00'
            execution_state = 'ready'
            performance_comparable = $false
            activation_expectation = 'reachable'
        },
        [pscustomobject][ordered]@{
            cell_id = 'cell.queued_send.01'
            cell_order = 1
            treatment_ids = @(
                'treatment.queued_send_burst_budget.single_datagram')
            axis_ids = @('queued_send_burst_budget')
            expected_equivalence_group_id =
                'declared.cell.queued_send.01'
            execution_state = 'ready'
            performance_comparable = $false
            activation_expectation = 'reachable'
        })
    execution_order_policy = 'deterministic'
    execution_status = 'ready'
    preserve_equivalent_cells_for_verification = $true
    notes = @(
        'Independent correctness-only actuation plan.',
        'Measurement and active behavior remain unauthorized.')
}
[void](Set-AdaptiveRuntimeDocumentHash $queuedPlan)
Write-Document $queuedPlan `
    'eng/adaptive-runtime/experiment-control/adaptive-runtime-queued-send-actuation-plan-v1.json'

foreach ($oversizedValue in @(
    'single_fragment','bounded_multi_fragment')) {
    $distinctPredicate = if ($oversizedValue -eq 'single_fragment') {
        'predicate.oversized_write.single_fragment_distinct'
    }
    else {
        'predicate.oversized_write.bounded_multi_fragment_distinct'
    }
    $oversizedPlan = [pscustomobject][ordered]@{
        schema_version = 'adaptive-runtime-experiment-plan-v1'
        document_id =
            "adaptive_runtime_oversized_write_$($oversizedValue)_actuation_plan_v1"
        document_version = 1
        content_sha256 = '0' * 64
        trace_references = $planTrace
        active_behavior_authorization = $false
        performance_acceptance_authorization = $false
        experiment_plan_id =
            "experiment_plan.oversized_write.$oversizedValue.actuation.v1"
        experiment_type = 'actuation_validation'
        family_id = 'send_admission_composition'
        source_document_refs = $sourceRefs
        fixed_axis_ids = @(
            'application_send_turn_planning',
            'queued_send_burst_budget')
        varied_axis_ids = @('oversized_write_admission_quantum')
        fixed_axis_values = @(
            [pscustomobject][ordered]@{
                axis_id = 'application_send_turn_planning'
                configured_value = 'legacy_current'
            },
            [pscustomobject][ordered]@{
                axis_id = 'queued_send_burst_budget'
                configured_value = 'legacy_current'
            })
        expected_capabilities = @(
            [pscustomobject][ordered]@{
                capability_id = 'adaptive_runtime_internal_forced_mode'
                expectation = 'required'
                resolution = 'deferred_to_manifest'
            },
            [pscustomobject][ordered]@{
                capability_id = 'single_behavior_distinct_axis_only'
                expectation = 'required'
                resolution = 'deferred_to_manifest'
            })
        required_predicate_refs = @(
            'predicate.oversized_write.activation',
            'predicate.oversized_write.single_fragment_distinct',
            'predicate.oversized_write.bounded_multi_fragment_distinct')
        treatments = @(
            [pscustomobject][ordered]@{
                treatment_id =
                    'treatment.oversized_write_admission_quantum.legacy_current'
                order_index = 0
                axis_id = 'oversized_write_admission_quantum'
                configured_value = 'legacy_current'
                candidate_value = 'legacy_current'
            },
            [pscustomobject][ordered]@{
                treatment_id =
                    "treatment.oversized_write_admission_quantum.$oversizedValue"
                order_index = 1
                axis_id = 'oversized_write_admission_quantum'
                configured_value = $oversizedValue
                forced_value = $oversizedValue
                candidate_value = $oversizedValue
            })
        treatment_order = @(
            'treatment.oversized_write_admission_quantum.legacy_current',
            "treatment.oversized_write_admission_quantum.$oversizedValue")
        planned_cells = @(
            [pscustomobject][ordered]@{
                cell_id = "cell.oversized_write.$oversizedValue.00"
                cell_order = 0
                treatment_ids = @(
                    'treatment.oversized_write_admission_quantum.legacy_current')
                axis_ids = @('oversized_write_admission_quantum')
                expected_equivalence_group_id =
                    "declared.oversized_write.$oversizedValue.00"
                execution_state = 'ready'
                performance_comparable = $false
                activation_expectation = 'reachable'
            },
            [pscustomobject][ordered]@{
                cell_id = "cell.oversized_write.$oversizedValue.01"
                cell_order = 1
                treatment_ids = @(
                    "treatment.oversized_write_admission_quantum.$oversizedValue")
                axis_ids = @('oversized_write_admission_quantum')
                expected_equivalence_group_id =
                    "declared.oversized_write.$oversizedValue.01"
                execution_state = 'ready'
                performance_comparable = $false
                activation_expectation = 'reachable'
            })
        execution_order_policy = 'deterministic'
        execution_status = 'ready'
        preserve_equivalent_cells_for_verification = $true
        notes = @(
            'Independent correctness-only actuation plan.',
            'All adjacent axes remain legacy_current.',
            'Measurement and active behavior remain unauthorized.')
    }
    [void](Set-AdaptiveRuntimeDocumentHash $oversizedPlan)
    Write-Document $oversizedPlan (
        "eng/adaptive-runtime/experiment-control/" +
        "adaptive-runtime-oversized-write-$oversizedValue-actuation-plan-v1.json")
}

$cellSpaceSchema = @'
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://incursa.dev/schemas/adaptive-runtime-factor-cell-space-v1.schema.json",
  "title": "Adaptive Runtime Factor Cell Space v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version","document_id","document_version","content_sha256","catalog_refs","generation_mode","covering_array_generator_implemented","covering_array_trigger_effective_cell_count","family_spaces","active_behavior_authorization","performance_acceptance_authorization","trace_references"],
  "properties": {
    "schema_version": {"const":"adaptive-runtime-factor-cell-space-v1"},
    "document_id":{"$ref":"#/$defs/id"},
    "document_version":{"const":1},
    "content_sha256":{"$ref":"#/$defs/hash"},
    "catalog_refs":{"type":"array","minItems":5,"maxItems":5,"items":{"$ref":"#/$defs/ref"}},
    "generation_mode":{"const":"exhaustive_explicit"},
    "covering_array_generator_implemented":{"const":false},
    "covering_array_trigger_effective_cell_count":{"const":65},
    "family_spaces":{"type":"array","minItems":2,"items":{"$ref":"#/$defs/space"}},
    "active_behavior_authorization":{"const":false},
    "performance_acceptance_authorization":{"const":false},
    "trace_references":{"$ref":"#/$defs/trace"}
  },
  "$defs": {
    "id":{"type":"string","pattern":"^[a-z0-9][a-z0-9._-]*$"},
    "hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},
    "ref":{"type":"object","additionalProperties":false,"required":["document_id","schema_version","document_version","content_sha256"],"properties":{"document_id":{"$ref":"#/$defs/id"},"schema_version":{"$ref":"#/$defs/id"},"document_version":{"type":"integer","minimum":1},"content_sha256":{"$ref":"#/$defs/hash"}}},
    "axisValue":{"type":"object","additionalProperties":false,"required":["axis_id","policy_value"],"properties":{"axis_id":{"$ref":"#/$defs/id"},"policy_value":{"$ref":"#/$defs/id"}}},
    "cell":{"type":"object","additionalProperties":false,"required":["cell_id","cell_order","axis_values","classification","reason_codes","measurement_authorized","active_behavior_authorization"],"properties":{"cell_id":{"$ref":"#/$defs/id"},"cell_order":{"type":"integer","minimum":0},"axis_values":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/axisValue"}},"classification":{"enum":["correctness_single_axis_candidate","capability_pending","structurally_inactive","verification_only"]},"reason_codes":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"measurement_authorized":{"const":false},"active_behavior_authorization":{"const":false}}},
    "space":{"type":"object","additionalProperties":false,"required":["family_id","raw_configured_cell_count","after_illegal_removal_count","after_capability_filter_count","structurally_inactive_cell_count","safety_clamped_cell_count","expected_equivalence_group_count","behavior_distinct_effective_cell_count","verification_only_cell_count","measurement_blocked_cell_count","correctness_executable_cell_count","planned_cells"],"properties":{"family_id":{"$ref":"#/$defs/id"},"raw_configured_cell_count":{"type":"integer","minimum":1},"after_illegal_removal_count":{"type":"integer","minimum":0},"after_capability_filter_count":{"type":"integer","minimum":0},"structurally_inactive_cell_count":{"type":"integer","minimum":0},"safety_clamped_cell_count":{"type":"integer","minimum":0},"expected_equivalence_group_count":{"type":"integer","minimum":0},"behavior_distinct_effective_cell_count":{"type":"integer","minimum":0},"verification_only_cell_count":{"type":"integer","minimum":0},"measurement_blocked_cell_count":{"type":"integer","minimum":0},"correctness_executable_cell_count":{"type":"integer","minimum":0},"planned_cells":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/cell"}}}},
    "trace":{"type":"object","additionalProperties":false,"required":["requirement_ids","architecture_ids","work_item_ids","verification_ids"],"properties":{"requirement_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string"}},"architecture_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string"}},"work_item_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string"}},"verification_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string"}}}}
  }
}
'@
Write-Utf8NoBom (
    Join-Path $schemaRoot 'adaptive-runtime-factor-cell-space-v1.schema.json') `
    $cellSpaceSchema

Write-Host 'Updated additive factor-onboarding schemas and canonical catalogs.'

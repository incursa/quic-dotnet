// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0225")]
public sealed class REQ_QUIC_CRT_0225
{
    private const string Hash =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string CapturePathVariable =
        "INCURSA_ADAPTIVE_RUNTIME_INTERACTION_CAPTURE_PATH";
    private const string ManifestHashVariable =
        "INCURSA_ADAPTIVE_RUNTIME_INTERACTION_MANIFEST_HASH";
    private const string BatchProofHashVariable =
        "INCURSA_ADAPTIVE_RUNTIME_INTERACTION_BATCH_PROOF_HASH";
    private const string BufferProofHashVariable =
        "INCURSA_ADAPTIVE_RUNTIME_INTERACTION_BUFFER_PROOF_HASH";

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExactReviewedCorrectnessCellMayConfigureBothAxes()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();

        runtime.ConfigureAdaptiveRuntimePolicy(CreateOptions(
            QuicAdaptiveRuntimeCorrectnessInteractionAuthorization
                .CreateForReviewedManifest(
                    Hash,
                    "cell.send_composition.correctness.000",
                    Hash,
                    Hash)));

        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            runtime.ApplicationSendBatchPolicyMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TwoAxesRemainDeniedWithoutExactManifestAuthorization()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();

        InvalidOperationException exception =
            Assert.Throws<InvalidOperationException>(() =>
                runtime.ConfigureAdaptiveRuntimePolicy(CreateOptions(null)));

        Assert.Contains(
            "requires the legacy_current application-send batch policy",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AuthorizationCannotJoinAThirdBehaviorDistinctAxis()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicClientConnectionOptions options = CreateOptions(
            QuicAdaptiveRuntimeCorrectnessInteractionAuthorization
                .CreateForReviewedManifest(
                    Hash,
                    "cell.send_composition.correctness.000",
                    Hash,
                    Hash));
        options.ForcedQueuedSendBurstPolicyMode =
            QuicQueuedSendBurstPolicyMode.SingleDatagram;

        Assert.Throws<InvalidOperationException>(() =>
            runtime.ConfigureAdaptiveRuntimePolicy(options));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AuthorizationRejectsAStaleOrMalformedIdentity()
    {
        Assert.Throws<ArgumentException>(() =>
            QuicAdaptiveRuntimeCorrectnessInteractionAuthorization
                .CreateForReviewedManifest(
                    "stale",
                    "cell.send_composition.correctness.000",
                    Hash,
                    Hash));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProductionSeamsEmitTheReviewedInteractionCaseMatrix()
    {
        string manifestHash = GetHash(ManifestHashVariable);
        string batchProofHash = GetHash(BatchProofHashVariable);
        string bufferProofHash = GetHash(BufferProofHashVariable);
        QuicAdaptiveRuntimeCorrectnessInteractionAuthorization authorization =
            QuicAdaptiveRuntimeCorrectnessInteractionAuthorization
                .CreateForReviewedManifest(
                    manifestHash,
                    "cell.send_composition.correctness.000",
                    batchProofHash,
                    bufferProofHash);

        object batchDistinct = REQ_QUIC_CRT_0219.CaptureBatchOperation(
            "connection.interaction.both-distinct.batch",
            "positive_actuation",
            201,
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            true,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            [100, 100, 100, 100],
            "applied",
            null);
        (object Operation, object Release) bufferDistinct =
            REQ_QUIC_CRT_0219.CaptureBufferRuntimeOperation(
                "connection.interaction.both-distinct.buffer",
                "positive_actuation",
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                4,
                400,
                200,
                interactionAuthorization: authorization);
        object batchOnly = REQ_QUIC_CRT_0219.CaptureBatchOperation(
            "connection.interaction.batch-distinct",
            "positive_actuation",
            202,
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            true,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            [100, 100, 100],
            "applied",
            null);
        (object Operation, object Release) bufferInactive =
            REQ_QUIC_CRT_0219.CaptureBufferRuntimeOperation(
                "connection.interaction.buffer-inactive",
                "structurally_inactive",
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                2,
                200,
                200,
                interactionAuthorization: authorization);
        object batchInactive = REQ_QUIC_CRT_0219.CaptureBatchOperation(
            "connection.interaction.batch-inactive",
            "structurally_inactive",
            203,
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            true,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            [100],
            "inactive",
            "eligible_count_one");
        (object Operation, object Release) bufferDistinctSecond =
            REQ_QUIC_CRT_0219.CaptureBufferRuntimeOperation(
                "connection.interaction.buffer-distinct",
                "positive_actuation",
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                4,
                400,
                200,
                interactionAuthorization: authorization);
        object batchBothInactive = REQ_QUIC_CRT_0219.CaptureBatchOperation(
            "connection.interaction.both-inactive.batch",
            "structurally_inactive",
            207,
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            true,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            [100],
            "inactive",
            "eligible_count_one");
        (object Operation, object Release) bufferBothInactive =
            REQ_QUIC_CRT_0219.CaptureBufferRuntimeOperation(
                "connection.interaction.both-inactive.buffer",
                "structurally_inactive",
                QuicBufferCopyObservationMode.ObserveOnly,
                QuicBufferCopyPolicyValue.MemoryConservative,
                2,
                200,
                200,
                interactionAuthorization: authorization);
        object batchFallback = REQ_QUIC_CRT_0219.CaptureBatchOperation(
            "connection.interaction.fallback",
            "safety_fallback",
            204,
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            true,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            [100, 100, 100],
            "clamped",
            "lifecycle_guard",
            forceLifecycleGuard: true);
        object batchShadow = REQ_QUIC_CRT_0219.CaptureBatchOperation(
            "connection.interaction.shadow",
            "shadow_neutrality",
            205,
            QuicApplicationSendBatchObservationMode.Shadow,
            false,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            [100, 100, 100],
            "applied",
            null,
            forceShadowRecommendation: true);
        object batchRollback = REQ_QUIC_CRT_0219.CaptureBatchOperation(
            "connection.interaction.rollback",
            "rollback",
            206,
            QuicApplicationSendBatchObservationMode.ObserveOnly,
            false,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            [100, 100, 100],
            "applied",
            null);

        object[] operations =
        [
            Wrap("both_distinct", "application_send_batch_formation", batchDistinct),
            Wrap("both_distinct", "buffer_copy_coalescing", bufferDistinct.Operation),
            Wrap("batch_distinct_buffer_inactive", "application_send_batch_formation", batchOnly),
            Wrap("batch_distinct_buffer_inactive", "buffer_copy_coalescing", bufferInactive.Operation),
            Wrap("batch_inactive_buffer_distinct", "application_send_batch_formation", batchInactive),
            Wrap("batch_inactive_buffer_distinct", "buffer_copy_coalescing", bufferDistinctSecond.Operation),
            Wrap("both_inactive", "application_send_batch_formation", batchBothInactive),
            Wrap("both_inactive", "buffer_copy_coalescing", bufferBothInactive.Operation),
            Wrap("safety_fallback", "application_send_batch_formation", batchFallback),
            Wrap("shadow_neutrality", "application_send_batch_formation", batchShadow),
            Wrap("rollback", "application_send_batch_formation", batchRollback),
        ];
        object[] releases =
        [
            Wrap("both_distinct", "buffer_copy_coalescing", bufferDistinct.Release),
            Wrap("batch_distinct_buffer_inactive", "buffer_copy_coalescing", bufferInactive.Release),
            Wrap("batch_inactive_buffer_distinct", "buffer_copy_coalescing", bufferDistinctSecond.Release),
            Wrap("both_inactive", "buffer_copy_coalescing", bufferBothInactive.Release),
        ];

        Assert.Equal(11, operations.Length);
        Assert.Equal(4, releases.Length);

        string? capturePath = Environment.GetEnvironmentVariable(
            CapturePathVariable);
        if (!string.IsNullOrWhiteSpace(capturePath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(capturePath)!);
            File.WriteAllText(
                capturePath,
                System.Text.Json.JsonSerializer.Serialize(new
                {
                    schema_version =
                        "adaptive-runtime-send-composition-mechanism-capture-v1",
                    document_id =
                        "mechanism_capture.send_composition.correctness",
                    document_version = 1,
                    content_sha256 = new string('0', 64),
                    run_id = "run.send_composition.correctness",
                    binary_cohort_id =
                        "binary.send_composition.correctness",
                    manifest_content_sha256 = manifestHash,
                    exact_cell_id =
                        "cell.send_composition.correctness.000",
                    forced_behavior_distinct_axis_count = 2,
                    operations,
                    releases,
                    active_behavior_authorization = false,
                    performance_acceptance_authorization = false,
                }));
        }
    }

    private static QuicClientConnectionOptions CreateOptions(
        QuicAdaptiveRuntimeCorrectnessInteractionAuthorization?
            authorization)
    {
        return new()
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.SingleEligible,
            ForcedBufferCopyPolicyValue =
                QuicBufferCopyPolicyValue.MemoryConservative,
            SendCompositionCorrectnessAuthorization = authorization,
        };
    }

    private static string GetHash(string variable)
    {
        string? value = Environment.GetEnvironmentVariable(variable);
        return string.IsNullOrWhiteSpace(value) ? Hash : value;
    }

    private static object Wrap(
        string interactionCase,
        string axisId,
        object evidence)
        => new
        {
            interaction_case = interactionCase,
            axis_id = axisId,
            evidence,
        };
}

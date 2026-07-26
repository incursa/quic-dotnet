// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0229")]
[Requirement("REQ-QUIC-CRT-0230")]
[Requirement("REQ-QUIC-CRT-0231")]
[Requirement("REQ-QUIC-CRT-0233")]
public sealed class REQ_QUIC_CRT_0229
{
    private const string Hash =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Theory]
    [InlineData(
        (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent,
        (int)QuicBufferCopyPolicyValue.LegacyCurrent)]
    [InlineData(
        (int)QuicApplicationSendBatchPolicyMode.SingleEligible,
        (int)QuicBufferCopyPolicyValue.LegacyCurrent)]
    [InlineData(
        (int)QuicApplicationSendBatchPolicyMode.LegacyCurrent,
        (int)QuicBufferCopyPolicyValue.MemoryConservative)]
    [InlineData(
        (int)QuicApplicationSendBatchPolicyMode.SingleEligible,
        (int)QuicBufferCopyPolicyValue.MemoryConservative)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExactOfflineCampaignCellsAreManifestBound(
        int batchValue,
        int bufferValue)
    {
        QuicApplicationSendBatchPolicyMode batch =
            (QuicApplicationSendBatchPolicyMode)batchValue;
        QuicBufferCopyPolicyValue buffer =
            (QuicBufferCopyPolicyValue)bufferValue;
        QuicAdaptiveRuntimePerformanceInteractionAuthorization authorization =
            QuicAdaptiveRuntimePerformanceInteractionAuthorization
                .CreateForReviewedManifest(
                    "campaign.send_composition.performance.v1",
                    Hash,
                    $"cell.{batchValue}.{bufferValue}",
                    Hash,
                    Hash,
                    batch,
                    buffer);

        Assert.True(authorization.Authorizes(batch, buffer));
        Assert.False(authorization.ActiveBehaviorAuthorization);
        Assert.False(authorization.PerformanceAcceptanceAuthorization);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MismatchedRuntimeCellIsDenied()
    {
        QuicAdaptiveRuntimePerformanceInteractionAuthorization authorization =
            QuicAdaptiveRuntimePerformanceInteractionAuthorization
                .CreateForReviewedManifest(
                    "campaign.send_composition.performance.v1",
                    Hash,
                    "cell.d",
                    Hash,
                    Hash,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.MemoryConservative);

        Assert.False(authorization.Authorizes(
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.MemoryConservative));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExactDCellMayConfigureOnlyWithOfflineAuthorization()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicAdaptiveRuntimePerformanceInteractionAuthorization authorization =
            QuicAdaptiveRuntimePerformanceInteractionAuthorization
                .CreateForReviewedManifest(
                    "campaign.send_composition.performance.v1",
                    Hash,
                    "cell.d",
                    Hash,
                    Hash,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.MemoryConservative);

        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode =
                QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendBatchPolicyMode =
                QuicApplicationSendBatchPolicyMode.SingleEligible,
            ForcedBufferCopyPolicyValue =
                QuicBufferCopyPolicyValue.MemoryConservative,
            SendCompositionPerformanceAuthorization = authorization,
        });

        Assert.Equal(
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            runtime.ApplicationSendBatchPolicyMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CorrectnessAndMeasurementTokensCannotBeCombined()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicAdaptiveRuntimePerformanceInteractionAuthorization measurement =
            QuicAdaptiveRuntimePerformanceInteractionAuthorization
                .CreateForReviewedManifest(
                    "campaign.send_composition.performance.v1",
                    Hash,
                    "cell.d",
                    Hash,
                    Hash,
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                    QuicBufferCopyPolicyValue.MemoryConservative);
        QuicAdaptiveRuntimeCorrectnessInteractionAuthorization correctness =
            QuicAdaptiveRuntimeCorrectnessInteractionAuthorization
                .CreateForReviewedManifest(
                    Hash,
                    "cell.send_composition.correctness.000",
                    Hash,
                    Hash);

        Assert.Throws<InvalidOperationException>(() =>
            runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
            {
                ForcedReceiveCreditPolicyMode =
                    QuicReceiveCreditPolicyMode.LegacyCurrent,
                ForcedApplicationSendBatchPolicyMode =
                    QuicApplicationSendBatchPolicyMode.SingleEligible,
                ForcedBufferCopyPolicyValue =
                    QuicBufferCopyPolicyValue.MemoryConservative,
                SendCompositionCorrectnessAuthorization = correctness,
                SendCompositionPerformanceAuthorization = measurement,
            }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SingleEligibleMakesCombinedBufferDistinctnessStructurallyUnreachable()
    {
        Assert.Equal(
            1,
            QuicApplicationSendBatchPolicy.SelectWriteCount(
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                legalEligibleWriteCount: 8));
        Assert.True(QuicBufferCopyPolicy.MinimumCombinedSourceSegments > 1);
    }
}

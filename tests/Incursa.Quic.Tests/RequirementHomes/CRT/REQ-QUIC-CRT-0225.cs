// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0225")]
public sealed class REQ_QUIC_CRT_0225
{
    private const string Hash =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
}

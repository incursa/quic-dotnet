// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0254")]
public sealed class REQ_QUIC_CRT_0254
{
    private const string CampaignId =
        "campaign.queued_send_burst_budget.performance.v1";
    private const string ManifestHash =
        "2ad809ecdb882f000c38d00c97f69604cbb3e004186535fd2348800e7c8a27ab";
    private const string Q0CellId =
        "cell.queued_send_burst_budget.performance.q0";
    private const string Q0CellHash =
        "b2911df4e1782b6f1636d37bf50f0dd5e59dbbb9164ec3154b667034c43fb3e9";
    private const string Q1CellId =
        "cell.queued_send_burst_budget.performance.q1";
    private const string Q1CellHash =
        "2f4a7a36c0d52aeae801a979e91335347693db5ec8665715497d068fb02cdc2a";

    [Theory]
    [InlineData(Q0CellId, Q0CellHash, (int)QuicQueuedSendBurstPolicyMode.LegacyCurrent)]
    [InlineData(Q1CellId, Q1CellHash, (int)QuicQueuedSendBurstPolicyMode.SingleDatagram)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExactQueuedSendPerformancePackagePathIsOfflineOnly(
        string cellId,
        string cellHash,
        int queuedBurstModeValue)
    {
        QuicQueuedSendBurstPolicyMode queuedBurstMode =
            (QuicQueuedSendBurstPolicyMode)queuedBurstModeValue;
        QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization authorization =
            CreateAuthorization(cellId, cellHash, queuedBurstMode);

        Assert.True(authorization.OfflineMeasurementOnly);
        Assert.False(authorization.ActiveBehaviorAuthorization);
        Assert.False(authorization.PerformanceAcceptanceAuthorization);
        Assert.False(authorization.AdaptiveRuleDerivationAuthorization);
        Assert.False(authorization.ProductionActivationAuthorization);
        Assert.Equal(CampaignId, authorization.CampaignId);
        Assert.Equal(ManifestHash, authorization.ManifestContentSha256);
        Assert.Equal(cellId, authorization.CellId);
        Assert.Equal(cellHash, authorization.CellContentSha256);
        Assert.Equal(queuedBurstMode, authorization.QueuedBurstMode);
        Assert.True(authorization.Authorizes(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            queuedBurstMode));
        Assert.False(authorization.Authorizes(
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            queuedBurstMode));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StaleManifestOrOutsideCellIsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            CreateAuthorization(
                Q0CellId,
                Q0CellHash,
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
                campaignId: "campaign.queued_send_burst_budget.performance.v0"));
        Assert.Throws<ArgumentException>(() =>
            CreateAuthorization(
                Q0CellId,
                Q0CellHash,
                QuicQueuedSendBurstPolicyMode.LegacyCurrent,
                manifestHash:
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        Assert.Throws<ArgumentException>(() =>
            CreateAuthorization(
                "cell.queued_send_burst_budget.performance.q2",
                Q0CellHash,
                QuicQueuedSendBurstPolicyMode.LegacyCurrent));
        Assert.Throws<ArgumentException>(() =>
            CreateAuthorization(
                Q1CellId,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                QuicQueuedSendBurstPolicyMode.SingleDatagram));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EveryAdjacentNonLegacyAxisIsRejected()
    {
        QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization authorization =
            CreateAuthorization(
                Q1CellId,
                Q1CellHash,
                QuicQueuedSendBurstPolicyMode.SingleDatagram);

        Assert.False(authorization.Authorizes(
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            QuicQueuedSendBurstPolicyMode.SingleDatagram));
        Assert.False(authorization.Authorizes(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            QuicQueuedSendBurstPolicyMode.SingleDatagram));
        Assert.False(authorization.Authorizes(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.MemoryConservative,
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            QuicQueuedSendBurstPolicyMode.SingleDatagram));
        Assert.False(authorization.Authorizes(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicReceiveCreditPolicyMode.Immediate,
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            QuicQueuedSendBurstPolicyMode.SingleDatagram));
        Assert.False(authorization.Authorizes(
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicReceiveCreditPolicyMode.LegacyCurrent,
            QuicApplicationSendTurnPolicyMode.Conservative,
            QuicQueuedSendBurstPolicyMode.SingleDatagram));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void QueuedSendPerformanceAuthorizationRejectsMixedPerformanceAuthorities()
    {
        QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization queuedAuthorization =
            CreateAuthorization(
                Q0CellId,
                Q0CellHash,
                QuicQueuedSendBurstPolicyMode.LegacyCurrent);
        QuicAdaptiveRuntimeAdmissionPerformanceAuthorization admissionAuthorization =
            REQ_QUIC_CRT_0248.CreateAuthorization(
                "cell.send_admission_composition.correctness.a0",
                "c9e070a0880872c9c9dce62f07e933a0de96c7590d343ce7f923f121278bba28",
                QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                QuicBufferCopyPolicyValue.LegacyCurrent);

        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport
                .CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.Throws<InvalidOperationException>(() =>
        {
            QuicClientConnectionOptions options = new()
            {
                ForcedReceiveCreditPolicyMode =
                    QuicReceiveCreditPolicyMode.LegacyCurrent,
                ForcedApplicationSendTurnPolicyMode =
                    QuicApplicationSendTurnPolicyMode.LegacyCurrent,
                ForcedQueuedSendBurstPolicyMode =
                    QuicQueuedSendBurstPolicyMode.LegacyCurrent,
                ForcedOversizedWriteAdmissionPolicyMode =
                    QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
                ForcedApplicationSendBatchPolicyMode =
                    QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                ForcedBufferCopyPolicyValue =
                    QuicBufferCopyPolicyValue.LegacyCurrent,
                SendAdmissionPerformanceAuthorization = admissionAuthorization,
                QueuedSendPerformanceAuthorization = queuedAuthorization,
            };

            runtime.ConfigureAdaptiveRuntimePolicy(options);
        });
    }

    internal static QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization
        CreateAuthorization(
            string cellId,
            string cellHash,
            QuicQueuedSendBurstPolicyMode queuedBurstMode,
            string? campaignId = null,
            string? manifestHash = null)
    {
        return QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization
            .CreateForReviewedPackagePath(
                campaignId ?? CampaignId,
                manifestHash ?? ManifestHash,
                cellId,
                cellHash,
                queuedBurstMode);
    }
}

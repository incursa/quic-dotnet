// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0257")]
public sealed class REQ_QUIC_CRT_0257
{
    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LegalBudgetGateTreatsValuesGreaterThanOneAsActivationPrecondition(
        int legalMaximumDatagrams,
        bool expected)
    {
        QuicQueuedSendBurstEvidence evidence = CreateEvidence(
            legalMaximumDatagrams);

        Assert.Equal(
            expected,
            QuicQueuedSendBurstEvidenceGate.HasLegalBudgetGreaterThanOne(
                in evidence));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QueuedSendPerformanceStage1SnapshotForcesTheQueuedAxis()
    {
        QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization authorization =
            QuicAdaptiveRuntimeQueuedSendPerformanceAuthorization
                .CreateForReviewedPackagePath(
                    "campaign.queued_send_burst_budget.performance.v1",
                    "9233dfdf43d14236a15a55907832582b1d82a692da3b9f400fdebd76f23abd5d",
                    "cell.queued_send_burst_budget.performance.q1",
                    "2f4a7a36c0d52aeae801a979e91335347693db5ec8665715497d068fb02cdc2a",
                    QuicQueuedSendBurstPolicyMode.SingleDatagram);

        QuicAdaptiveRuntimeStage1PolicySnapshot snapshot =
            QuicAdaptiveRuntimeStage1ConfiguredPolicy.CreateForQueuedSendPerformance(
                authorization,
                sendTurnForced: null,
                sendTurnObservation: QuicApplicationSendTurnObservationMode.Disabled,
                sendBatchForced: null,
                sendBatchObservation: QuicApplicationSendBatchObservationMode.Disabled,
                burstForced: QuicQueuedSendBurstPolicyMode.SingleDatagram,
                burstObservation: QuicQueuedSendBurstObservationMode.Disabled,
                oversizedForced: null,
                oversizedObservation: QuicOversizedWriteAdmissionObservationMode.Disabled,
                bufferCopyForced: null);

        Assert.True(snapshot.QueuedSendBurstBudget.HasForcedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            snapshot.QueuedSendBurstBudget.ForcedValue);
        Assert.False(snapshot.ApplicationSendTurnPlanning.HasForcedValue);
        Assert.False(snapshot.ApplicationSendBatchFormation.HasForcedValue);
        Assert.False(snapshot.OversizedWriteAdmissionQuantum.HasForcedValue);
    }

    private static QuicQueuedSendBurstEvidence CreateEvidence(
        int legalMaximumDatagrams)
        => new(
            default,
            default,
            default,
            legalMaximumDatagrams,
            legalMaximumDatagrams,
            0,
            0,
            0,
            0UL,
            0UL,
            false,
            null,
            0UL,
            default,
            default);
}

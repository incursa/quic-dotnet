// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicSendPolicyTests
{
    [Fact]
    public void ComputeQueuedApplicationSendBudget_BlocksWhenNoActivePathExists()
    {
        QuicQueuedApplicationSendBudget budget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
            CreateSnapshot(hasActivePath: false));

        Assert.False(budget.CanSendQueuedApplicationData);
        Assert.Equal(0, budget.MaxDatagrams);
        Assert.Equal(0, budget.MaxPayloadBytes);
        Assert.Equal(QuicSendPolicyBlockedReason.NoActivePath, budget.BlockedReason);
    }

    [Fact]
    public void ComputeQueuedApplicationSendBudget_BlocksWhenOrdinaryPacketsAreUnavailable()
    {
        QuicQueuedApplicationSendBudget budget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
            CreateSnapshot(canSendOrdinaryPackets: false));

        Assert.False(budget.CanSendQueuedApplicationData);
        Assert.Equal(QuicSendPolicyBlockedReason.OrdinaryPacketsUnavailable, budget.BlockedReason);
    }

    [Fact]
    public void ComputeQueuedApplicationSendBudget_BlocksAndPrioritizesApplicationDataRetransmission()
    {
        QuicQueuedApplicationSendBudget budget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
            CreateSnapshot(pendingRetransmissionCount: 2, hasApplicationDataRetransmission: true));

        Assert.False(budget.CanSendQueuedApplicationData);
        Assert.Equal(0, budget.MaxDatagrams);
        Assert.Equal(QuicSendPolicyBlockedReason.ApplicationDataRetransmissionPending, budget.BlockedReason);
        Assert.True(budget.ShouldPrioritizeRetransmission);
    }

    [Fact]
    public void ComputeQueuedApplicationSendBudget_ComputesPayloadBudgetFromCongestionAvailability()
    {
        QuicQueuedApplicationSendBudget budget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
            CreateSnapshot(
                maximumApplicationPayloadBytes: 8_000,
                congestionWindowBytes: 12_000,
                bytesInFlightBytes: 9_600));

        Assert.True(budget.CanSendQueuedApplicationData);
        Assert.Equal(QuicSendPolicy.MeasuredQueuedApplicationSendBurstDatagrams, budget.MaxDatagrams);
        Assert.Equal(2_400, budget.MaxPayloadBytes);
        Assert.Equal(QuicSendPolicyBlockedReason.None, budget.BlockedReason);
    }

    [Fact]
    public void ComputeQueuedApplicationSendBudget_PreservesMeasuredBurstLimit()
    {
        QuicQueuedApplicationSendBudget budget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
            CreateSnapshot(queuedApplicationSendCount: 32, congestionWindowBytes: 128_000));

        Assert.True(budget.CanSendQueuedApplicationData);
        Assert.Equal(QuicSendPolicy.MeasuredQueuedApplicationSendBurstDatagrams, budget.MaxDatagrams);
    }

    [Fact]
    public void ComputeQueuedApplicationSendBudget_TreatsSingleOversizedQueuedWriteAsBurstCandidate()
    {
        QuicQueuedApplicationSendBudget budget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
            CreateSnapshot(queuedApplicationSendCount: 1, congestionWindowBytes: 128_000));

        Assert.True(budget.CanSendQueuedApplicationData);
        Assert.Equal(QuicSendPolicy.MeasuredQueuedApplicationSendBurstDatagrams, budget.MaxDatagrams);
    }

    [Fact]
    public void ComputeQueuedApplicationSendBudget_LimitsDatagramsByLowCongestionAvailability()
    {
        QuicQueuedApplicationSendBudget budget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
            CreateSnapshot(queuedApplicationSendCount: 8, congestionWindowBytes: 2_400));

        Assert.True(budget.CanSendQueuedApplicationData);
        Assert.Equal(2, budget.MaxDatagrams);
    }

    [Fact]
    public void ComputeQueuedApplicationSendBudget_LimitsDatagramsByAntiAmplificationBudget()
    {
        QuicQueuedApplicationSendBudget budget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
            CreateSnapshot(
                queuedApplicationSendCount: 8,
                isAddressValidated: false,
                antiAmplificationAvailableBytes: 2_400,
                congestionWindowBytes: 128_000));

        Assert.True(budget.CanSendQueuedApplicationData);
        Assert.Equal(2, budget.MaxDatagrams);
        Assert.Equal(1_150, budget.MaxPayloadBytes);
    }

    private static QuicSendPolicySnapshot CreateSnapshot(
        bool hasActivePath = true,
        bool canSendOrdinaryPackets = true,
        ulong maximumDatagramSizeBytes = 1_200,
        int maximumApplicationPayloadBytes = 1_150,
        ulong congestionWindowBytes = 14_720,
        ulong bytesInFlightBytes = 0,
        int pendingRetransmissionCount = 0,
        bool hasApplicationDataRetransmission = false,
        ulong antiAmplificationAvailableBytes = 0,
        bool isAddressValidated = true,
        bool handshakeConfirmed = true,
        bool hasOneRttProtection = true,
        int queuedApplicationSendCount = 8)
        => new(
            hasActivePath,
            canSendOrdinaryPackets,
            maximumDatagramSizeBytes,
            maximumApplicationPayloadBytes,
            congestionWindowBytes,
            bytesInFlightBytes,
            pendingRetransmissionCount,
            hasApplicationDataRetransmission,
            antiAmplificationAvailableBytes,
            isAddressValidated,
            handshakeConfirmed,
            hasOneRttProtection,
            queuedApplicationSendCount);
}

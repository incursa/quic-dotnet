// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P6-0001">ACK frames MUST only be carried in a packet that has the same packet number space as the packet being acknowledged.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P6-0001")]
public sealed class REQ_QUIC_RFC9000_S13P2P6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_UsesOnlyTheRequestedPacketNumberSpace()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_010);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_020);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: true,
            receivedAtMicros: 1_030);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 1_100,
            out QuicAckFrame initialFrame));
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.Handshake,
            nowMicros: 1_100,
            out QuicAckFrame handshakeFrame));
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_100,
            out QuicAckFrame applicationFrame));

        Assert.Equal(2UL, initialFrame.LargestAcknowledged);
        Assert.Equal(1UL, initialFrame.FirstAckRange);
        Assert.Empty(initialFrame.AdditionalRanges);

        Assert.Equal(7UL, handshakeFrame.LargestAcknowledged);
        Assert.Equal(0UL, handshakeFrame.FirstAckRange);
        Assert.Empty(handshakeFrame.AdditionalRanges);

        Assert.Equal(4UL, applicationFrame.LargestAcknowledged);
        Assert.Equal(0UL, applicationFrame.FirstAckRange);
        Assert.Empty(applicationFrame.AdditionalRanges);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DoesNotUseReceiptsFromADifferentPacketNumberSpace()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.False(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 1_100,
            out _));
        Assert.False(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.Handshake,
            nowMicros: 1_100,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_KeepsSameNumericPacketNumberSeparateAcrossSpaces()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            ecnCounts: new QuicEcnCounts(1, 0, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_010,
            ecnCounts: new QuicEcnCounts(0, 0, 1));

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 1_100,
            out QuicAckFrame initialFrame));
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_100,
            out QuicAckFrame applicationFrame));

        Assert.Equal(5UL, initialFrame.LargestAcknowledged);
        Assert.Equal(1UL, initialFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(0UL, initialFrame.EcnCounts!.Value.EcnCeCount);

        Assert.Equal(5UL, applicationFrame.LargestAcknowledged);
        Assert.Equal(0UL, applicationFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(1UL, applicationFrame.EcnCounts!.Value.EcnCeCount);
    }
}

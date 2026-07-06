// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1203")]
public sealed class REQ_QUIC_RFC9000_1203
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1203")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_GapIdentifiesPacketsThatAreNotAcknowledged()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 8,
            last: 10);

        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 0,
            ackRangeLength: 0);

        Assert.True(sender.TryProcessAckFrame(QuicPacketNumberSpace.ApplicationData, frame, ackReceivedAtMicros: 11_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 12_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1203")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_DoesNotTreatGapPacketAsAcknowledged()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 8,
            last: 10);

        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 0,
            ackRangeLength: 0);

        Assert.True(sender.TryProcessAckFrame(QuicPacketNumberSpace.ApplicationData, frame, ackReceivedAtMicros: 11_000));
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 8, sentAtMicros: 12_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 12_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1203")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_LargerGapIdentifiesLargerUnacknowledgedRun()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 6,
            last: 10);

        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 2,
            ackRangeLength: 0);

        Assert.True(sender.TryProcessAckFrame(QuicPacketNumberSpace.ApplicationData, frame, ackReceivedAtMicros: 11_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 12_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 8, sentAtMicros: 12_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 7, sentAtMicros: 12_000));
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 6, sentAtMicros: 12_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1203")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckGapsPreserveUnacknowledgedPacketRuns()
    {
        for (ulong gap = 0; gap <= 5; gap++)
        {
            ulong largestAcknowledged = 32 + gap;
            ulong firstAckRange = 0;
            QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
                largestAcknowledged,
                firstAckRange,
                gap,
                ackRangeLength: 0);
            ulong acknowledgedAdditionalPacket = frame.AdditionalRanges[0].LargestAcknowledged;

            QuicSenderFlowController sender = new();
            QuicS19P3AckFrameTestSupport.RecordSentPackets(
                sender,
                QuicPacketNumberSpace.ApplicationData,
                first: acknowledgedAdditionalPacket,
                last: largestAcknowledged);

            Assert.True(sender.TryProcessAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                frame,
                ackReceivedAtMicros: 50_000 + gap));

            Assert.False(sender.TryRegisterLoss(
                QuicPacketNumberSpace.ApplicationData,
                acknowledgedAdditionalPacket,
                sentAtMicros: 60_000 + gap));
            Assert.False(sender.TryRegisterLoss(
                QuicPacketNumberSpace.ApplicationData,
                largestAcknowledged,
                sentAtMicros: 61_000 + gap));

            for (ulong packetNumber = acknowledgedAdditionalPacket + 1; packetNumber < largestAcknowledged; packetNumber++)
            {
                Assert.True(sender.TryRegisterLoss(
                    QuicPacketNumberSpace.ApplicationData,
                    packetNumber,
                    sentAtMicros: 62_000 + packetNumber));
            }
        }
    }
}

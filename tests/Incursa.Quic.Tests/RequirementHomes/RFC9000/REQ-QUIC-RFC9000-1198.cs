// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1198")]
public sealed class REQ_QUIC_RFC9000_1198
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1198")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_AckRangeLengthZeroMeansOnlyLargestInAdditionalRange()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
                    largestAcknowledged: 10,
                    firstAckRange: 0,
                    gap: 0,
                    ackRangeLength: 0)));

        Assert.Equal(8UL, parsed.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(parsed.AdditionalRanges[0].LargestAcknowledged, parsed.AdditionalRanges[0].SmallestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1198")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatAckFrame_RejectsZeroLengthRangeWhenSmallestDiffersFromLargest()
    {
        QuicAckFrame invalid = QuicS19P3AckFrameTestSupport.AckFrameFromRanges(
            largestAcknowledged: 10,
            firstAckRange: 0,
            new QuicAckRange(gap: 0, ackRangeLength: 0, smallestAcknowledged: 7, largestAcknowledged: 8));

        Span<byte> destination = stackalloc byte[64];

        Assert.False(QuicFrameCodec.TryFormatAckFrame(invalid, destination, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1198")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_FirstAckRangeZeroAcknowledgesOnlyLargestInFirstRange()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 9,
            last: 10);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(largestAcknowledged: 10, firstAckRange: 0),
            ackReceivedAtMicros: 11_000));

        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 12_000));
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 10, sentAtMicros: 12_000));
    }
}

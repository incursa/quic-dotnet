// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P3P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void AckRangeFuzz_RoundTripsGapAndRangeLengthVarintsAndComputedRanges()
    {
        Random random = new(0x5193_0001);
        Span<byte> destination = stackalloc byte[128];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            ulong largestAcknowledged = 1_000UL + (ulong)random.Next(0, 10_000);
            ulong firstAckRange = (ulong)random.Next(0, 32);
            ulong previousSmallestAcknowledged = largestAcknowledged - firstAckRange;
            ulong gap = SelectBoundaryOrRandom(random, iteration);
            ulong ackRangeLength = SelectBoundaryOrRandom(random, iteration + 3);

            if (previousSmallestAcknowledged <= gap + ackRangeLength + 1)
            {
                previousSmallestAcknowledged = gap + ackRangeLength + 2;
                largestAcknowledged = previousSmallestAcknowledged + firstAckRange;
            }

            QuicAckRange additionalRange = QuicFrameTestData.BuildAckRange(
                previousSmallestAcknowledged,
                gap,
                ackRangeLength);
            QuicAckFrame frame = QuicS19P3AckFrameTestSupport.AckFrameFromRanges(
                largestAcknowledged,
                firstAckRange,
                additionalRange);
            byte[] encoded = QuicS19P3AckFrameTestSupport.FormatAckFrame(frame);

            Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            QuicAckRange parsedRange = Assert.Single(parsed.AdditionalRanges);
            Assert.Equal(gap, parsedRange.Gap);
            Assert.Equal(ackRangeLength, parsedRange.AckRangeLength);
            Assert.Equal(previousSmallestAcknowledged - gap - 2, parsedRange.LargestAcknowledged);
            Assert.Equal(parsedRange.LargestAcknowledged - ackRangeLength, parsedRange.SmallestAcknowledged);

            Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void AckRangeUnderflowFuzz_RejectsNegativeComputedPacketNumbers()
    {
        for (ulong largestAcknowledged = 0; largestAcknowledged < 16; largestAcknowledged++)
        {
            for (ulong gap = largestAcknowledged; gap < largestAcknowledged + 4; gap++)
            {
                byte[] encoded = QuicS19P3AckFrameTestSupport.BuildPayload(
                    [0x02],
                    QuicS19P3AckFrameTestSupport.Varint(largestAcknowledged),
                    QuicS19P3AckFrameTestSupport.Varint(0),
                    QuicS19P3AckFrameTestSupport.Varint(1),
                    QuicS19P3AckFrameTestSupport.Varint(0),
                    QuicS19P3AckFrameTestSupport.Varint(gap),
                    QuicS19P3AckFrameTestSupport.Varint(0));

                Assert.False(QuicFrameCodec.TryParseAckFrame(encoded, out _, out _));
            }
        }
    }

    private static ulong SelectBoundaryOrRandom(Random random, int iteration)
        => (iteration % 6) switch
        {
            0 => 0UL,
            1 => 1UL,
            2 => 63UL,
            3 => 64UL,
            4 => 16_383UL,
            _ => (ulong)random.Next(0, 128),
        };
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_ContainsOneOrMoreAckRanges()
    {
        foreach (QuicAckFrame frame in AckFrameCases())
        {
            QuicAckFrame parsed = AssertAckFrameRoundTrip(frame);

            Assert.True(parsed.FirstAckRange <= parsed.LargestAcknowledged);
            Assert.True(parsed.AckRangeCount >= 0);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_PacketNumbersAreBoundToPacketNumberSpace()
    {
        foreach (ulong packetNumber in new[] { 0UL, 1UL, 7UL, 63UL })
        {
            QuicAckGenerationState state = new();
            state.RecordProcessedPacket(QuicPacketNumberSpace.Initial, packetNumber, ackEliciting: true, receivedAtMicros: 1_000);
            state.RecordProcessedPacket(QuicPacketNumberSpace.Handshake, packetNumber, ackEliciting: true, receivedAtMicros: 2_000);

            Assert.True(state.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 1_100, out QuicAckFrame initialAck));
            Assert.True(state.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 2_100, out QuicAckFrame handshakeAck));
            Assert.Equal(packetNumber, initialAck.LargestAcknowledged);
            Assert.Equal(packetNumber, handshakeAck.LargestAcknowledged);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_LargestAcknowledgedIsVariableLengthInteger()
    {
        foreach (ulong largestAcknowledged in VarintCases())
        {
            QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(largestAcknowledged, firstAckRange: 0);
            QuicAckFrame parsed = AssertAckFrameRoundTrip(frame);

            Assert.Equal(largestAcknowledged, parsed.LargestAcknowledged);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_AckDelayIsVariableLengthInteger()
    {
        foreach (ulong ackDelay in VarintCases())
        {
            QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(largestAcknowledged: 64, firstAckRange: 1);
            frame.AckDelay = ackDelay;

            QuicAckFrame parsed = AssertAckFrameRoundTrip(frame);

            Assert.Equal(ackDelay, parsed.AckDelay);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_AckRangeCountIsVariableLengthInteger()
    {
        foreach (QuicAckFrame frame in AckFrameCases())
        {
            QuicAckFrame parsed = AssertAckFrameRoundTrip(frame);

            Assert.Equal((ulong)parsed.AdditionalRangeCount, parsed.AckRangeCount);
            Assert.Equal(frame.AckRangeCount, parsed.AckRangeCount);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_FirstAckRangeIsVariableLengthInteger()
    {
        foreach ((ulong largestAcknowledged, ulong firstAckRange) in new[]
        {
            (0UL, 0UL),
            (1UL, 1UL),
            (63UL, 0UL),
            (64UL, 63UL),
            (16_384UL, 64UL),
        })
        {
            QuicAckFrame parsed = AssertAckFrameRoundTrip(
                QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(largestAcknowledged, firstAckRange));

            Assert.Equal(firstAckRange, parsed.FirstAckRange);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_LargestAcknowledgedReportsLargestPacketNumber()
    {
        foreach (QuicAckFrame frame in AckFrameCases())
        {
            QuicAckFrame parsed = AssertAckFrameRoundTrip(frame);

            Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
            Assert.True(parsed.LargestAcknowledged >= parsed.FirstAckRange);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_LargestAcknowledgedIsNotPacketNumberTruncated()
    {
        foreach (ulong largestAcknowledged in new[] { 0UL, 63UL, 64UL, 16_383UL, 16_384UL, QuicVariableLengthInteger.MaxValue })
        {
            byte[] encoded = QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(largestAcknowledged, firstAckRange: 0));

            Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.Equal(largestAcknowledged, parsed.LargestAcknowledged);

            if (encoded.Length > 2)
            {
                QuicS19P3AckFrameTestSupport.AssertRejects(encoded[..^1]);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_AckDelayEncodesMicrosecondDelay()
    {
        foreach ((ulong receivedAtMicros, ulong nowMicros, ulong expectedDelay) in new[]
        {
            (1_000UL, 1_000UL, 0UL),
            (1_000UL, 1_250UL, 250UL),
            (10_000UL, 16_400UL, 6_400UL),
        })
        {
            QuicAckGenerationState state = new();
            state.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, packetNumber: 4, ackEliciting: true, receivedAtMicros);

            Assert.True(state.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros, out QuicAckFrame frame));
            Assert.Equal(expectedDelay, frame.AckDelay);
            Assert.Equal(expectedDelay, AssertAckFrameRoundTrip(frame).AckDelay);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_AckRangeCountSpecifiesAdditionalRanges()
    {
        foreach (QuicAckFrame frame in AckFrameCases().Where(static frame => frame.AdditionalRangeCount > 0))
        {
            QuicAckFrame parsed = AssertAckFrameRoundTrip(frame);

            Assert.Equal(frame.AdditionalRangeCount, parsed.AdditionalRangeCount);
            Assert.Equal(frame.AckRangeCount, parsed.AckRangeCount);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFrame_FirstAckRangeAcknowledgesContiguousPacketsBeforeLargest()
    {
        foreach ((ulong largestAcknowledged, ulong firstAckRange) in new[]
        {
            (0UL, 0UL),
            (4UL, 0UL),
            (10UL, 3UL),
            (64UL, 63UL),
        })
        {
            QuicAckFrame parsed = AssertAckFrameRoundTrip(
                QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(largestAcknowledged, firstAckRange));

            ulong smallestAcknowledged = parsed.LargestAcknowledged - parsed.FirstAckRange;
            Assert.Equal(largestAcknowledged, parsed.LargestAcknowledged);
            Assert.Equal(firstAckRange, parsed.FirstAckRange);
            Assert.True(smallestAcknowledged <= parsed.LargestAcknowledged);
        }
    }

    private static QuicAckFrame AssertAckFrameRoundTrip(QuicAckFrame frame)
    {
        byte[] encoded = QuicS19P3AckFrameTestSupport.FormatAckFrame(frame);
        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Equal(frame.AdditionalRangeCount, parsed.AdditionalRangeCount);
        Assert.Equal(frame.EcnCounts.HasValue, parsed.EcnCounts.HasValue);

        for (int index = 0; index < frame.AdditionalRangeCount; index++)
        {
            QuicAckRange expected = frame.GetAdditionalRange(index);
            QuicAckRange actual = parsed.GetAdditionalRange(index);
            Assert.Equal(expected.Gap, actual.Gap);
            Assert.Equal(expected.AckRangeLength, actual.AckRangeLength);
            Assert.Equal(expected.SmallestAcknowledged, actual.SmallestAcknowledged);
            Assert.Equal(expected.LargestAcknowledged, actual.LargestAcknowledged);
        }

        if (frame.EcnCounts is QuicEcnCounts expectedEcnCounts)
        {
            Assert.Equal(expectedEcnCounts.Ect0Count, parsed.EcnCounts!.Value.Ect0Count);
            Assert.Equal(expectedEcnCounts.Ect1Count, parsed.EcnCounts!.Value.Ect1Count);
            Assert.Equal(expectedEcnCounts.EcnCeCount, parsed.EcnCounts!.Value.EcnCeCount);
        }

        byte[] destination = new byte[encoded.Length];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination));
        return parsed;
    }

    private static IEnumerable<QuicAckFrame> AckFrameCases()
    {
        yield return QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(0);
        yield return QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(10, firstAckRange: 3);

        ulong firstSmallestAcknowledged = 20 - 2;
        yield return QuicS19P3AckFrameTestSupport.AckFrameFromRanges(
            largestAcknowledged: 20,
            firstAckRange: 2,
            QuicFrameTestData.BuildAckRange(firstSmallestAcknowledged, gap: 1, ackRangeLength: 2));

        QuicAckRange firstAdditionalRange = QuicFrameTestData.BuildAckRange(
            previousSmallestAcknowledged: 64 - 3,
            gap: 1,
            ackRangeLength: 1);
        QuicAckRange secondAdditionalRange = QuicFrameTestData.BuildAckRange(
            firstAdditionalRange.SmallestAcknowledged,
            gap: 0,
            ackRangeLength: 0);
        yield return QuicS19P3AckFrameTestSupport.AckFrameFromRanges(
            largestAcknowledged: 64,
            firstAckRange: 3,
            firstAdditionalRange,
            secondAdditionalRange);

        QuicAckFrame ecnFrame = QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(63, firstAckRange: 1);
        ecnFrame.FrameType = 0x03;
        ecnFrame.EcnCounts = new QuicEcnCounts(1, 2, 3);
        yield return ecnFrame;
    }

    private static ulong[] VarintCases()
    {
        return [0, 1, 63, 64, 16_383, 16_384, QuicVariableLengthInteger.MaxValue];
    }
}

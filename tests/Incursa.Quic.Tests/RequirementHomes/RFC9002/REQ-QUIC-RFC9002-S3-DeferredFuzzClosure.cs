// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TransmissionsExposePacketLevelHeaders()
    {
        AssertPacketLevelHeadersCanBeParsedAcrossRepresentativeShortHeaderPackets();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S3-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketsPermitMultipleFrameTypes()
    {
        AssertPacketPayloadsCanContainMultipleFrameTypes();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S3-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoPacketsUseShortAcknowledgmentTimers()
    {
        AssertCryptoPacketSpacesUseImmediateAcknowledgmentTiming();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S3-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonAckPacketsCountTowardCongestionLimits()
    {
        AssertNonAckPacketsCountTowardCongestionLimits();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S3-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PaddingPacketsContributeTowardBytesInFlight()
    {
        AssertPaddingPacketsContributeTowardBytesInFlight();
    }

    private static void AssertPacketLevelHeadersCanBeParsedAcrossRepresentativeShortHeaderPackets()
    {
        foreach ((byte headerControlBits, byte[] remainder) in new[]
        {
            ((byte)0x00, new byte[] { 0x01 }),
            ((byte)0x01, new byte[] { 0xAA, 0xBB }),
            ((byte)0x02, new byte[] { 0x00, 0x01, 0x02 }),
            ((byte)0x03, new byte[] { 0xCC, 0xDD, 0xEE, 0xFF }),
            ((byte)0x24, new byte[] { 0x10, 0x20 }),
        })
        {
            byte[] packet = QuicHeaderTestData.BuildShortHeader(headerControlBits, remainder);

            Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
            Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
            Assert.Equal((byte)(0x40 | (headerControlBits & 0x3F)), header.HeaderControlBits);
            Assert.True(remainder.AsSpan().SequenceEqual(header.Remainder));
        }
    }

    private static void AssertPacketPayloadsCanContainMultipleFrameTypes()
    {
        byte[][] payloads =
        [
            [0x00, 0x01],
            [0x00, 0x00, 0x01],
            [0x01, 0x00],
            [0x00, 0x01, 0x00],
        ];

        foreach (byte[] payload in payloads)
        {
            HashSet<ulong> frameTypes = new();
            int offset = 0;
            while (offset < payload.Length)
            {
                ReadOnlySpan<byte> remaining = payload.AsSpan(offset);
                if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
                {
                    frameTypes.Add(0x00);
                    offset += paddingBytesConsumed;
                    continue;
                }

                if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
                {
                    frameTypes.Add(0x01);
                    offset += pingBytesConsumed;
                    continue;
                }

                Assert.True(QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame stream));
                frameTypes.Add(stream.FrameType);
                offset = payload.Length;
            }

            Assert.True(frameTypes.Count >= 2);
        }
    }

    private static void AssertCryptoPacketSpacesUseImmediateAcknowledgmentTiming()
    {
        foreach ((QuicPacketNumberSpace packetNumberSpace, ulong receivedAtMicros, ulong nowMicros, ulong maxAckDelayMicros) in new[]
        {
            (QuicPacketNumberSpace.Initial, 1_000UL, 1_001UL, 25_000UL),
            (QuicPacketNumberSpace.Initial, 2_500UL, 2_500UL, 1_000UL),
            (QuicPacketNumberSpace.Handshake, 10_000UL, 10_001UL, 25_000UL),
            (QuicPacketNumberSpace.Handshake, 50_000UL, 50_100UL, 1_000_000UL),
        })
        {
            Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x06));

            QuicAckGenerationState tracker = new();
            tracker.RecordProcessedPacket(
                packetNumberSpace,
                packetNumber: 1,
                ackEliciting: true,
                receivedAtMicros);

            Assert.True(tracker.ShouldSendAckImmediately(packetNumberSpace));
            Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
                packetNumberSpace,
                nowMicros,
                maxAckDelayMicros));
        }
    }

    private static void AssertNonAckPacketsCountTowardCongestionLimits()
    {
        foreach (ulong packetSizeBytes in new[] { 1UL, 64UL, 1_200UL, 12_000UL })
        {
            QuicCongestionControlState nonAckState = new();
            nonAckState.RegisterPacketSent(packetSizeBytes, isAckOnlyPacket: false);
            Assert.Equal(packetSizeBytes, nonAckState.BytesInFlightBytes);
            Assert.False(nonAckState.CanSend(nonAckState.CongestionWindowBytes, isProbePacket: false));

            QuicCongestionControlState ackOnlyState = new();
            ackOnlyState.RegisterPacketSent(packetSizeBytes, isAckOnlyPacket: true);
            Assert.Equal(0UL, ackOnlyState.BytesInFlightBytes);
            Assert.True(ackOnlyState.CanSend(ackOnlyState.CongestionWindowBytes, isProbePacket: false));
        }
    }

    private static void AssertPaddingPacketsContributeTowardBytesInFlight()
    {
        Span<byte> paddingFrame = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(paddingFrame, out int paddingFrameBytesWritten));
        Assert.Equal((byte)0x00, paddingFrame[0]);
        Assert.False(QuicFrameCodec.IsAckElicitingFrameType(paddingFrame[0]));

        foreach (ulong paddingPacketSizeBytes in new[] { (ulong)paddingFrameBytesWritten, 16UL, 1_200UL, 2_400UL })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(paddingPacketSizeBytes, isAckOnlyPacket: false);

            Assert.Equal(paddingPacketSizeBytes, state.BytesInFlightBytes);
        }
    }
}

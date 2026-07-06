// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S2P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StreamIdentifierFuzz_RoundTripsNumericIdentityInitiatorAndDirectionBits()
    {
        Random random = new(0x5201_0001);

        for (int iteration = 0; iteration < 256; iteration++)
        {
            ulong value = SelectBoundaryOrRandom(random, iteration);
            byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

            Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.Equal(value, streamId.Value);
            Assert.Equal((value & 0x01UL) == 0, streamId.IsClientInitiated);
            Assert.Equal((value & 0x01UL) != 0, streamId.IsServerInitiated);
            Assert.Equal((value & 0x02UL) == 0, streamId.IsBidirectional);
            Assert.Equal((value & 0x02UL) != 0, streamId.IsUnidirectional);
            Assert.Equal(streamId.IsBidirectional ? QuicStreamType.Bidirectional : QuicStreamType.Unidirectional, streamId.StreamType);

            if (streamId.IsClientInitiated)
            {
                Assert.Equal(0UL, streamId.Value & 0x01UL);
            }
            else
            {
                Assert.Equal(1UL, streamId.Value & 0x01UL);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void OutOfOrderPeerStreamFuzz_OpensLowerNumberedStreamsOfTheSameType()
    {
        for (ulong streamOrdinal = 1; streamOrdinal <= 16; streamOrdinal++)
        {
            AssertPeerStreamSequenceOpensLowerSameTypeStreams(streamOrdinal, bidirectional: true);
            AssertPeerStreamSequenceOpensLowerSameTypeStreams(streamOrdinal, bidirectional: false);
        }
    }

    private static void AssertPeerStreamSequenceOpensLowerSameTypeStreams(ulong streamOrdinal, bool bidirectional)
    {
        QuicConnectionStreamState state = CreatePeerStreamState();
        ulong directionBit = bidirectional ? 0UL : 0x02UL;
        ulong peerStreamId = (streamOrdinal << 2) | 0x01UL | directionBit;
        byte[] payload = [(byte)(0x40 + streamOrdinal)];

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, peerStreamId, payload, offset: 0),
            out QuicStreamFrame streamFrame));
        Assert.True(state.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        for (ulong lowerOrdinal = 0; lowerOrdinal <= streamOrdinal; lowerOrdinal++)
        {
            ulong openedStreamId = (lowerOrdinal << 2) | 0x01UL | directionBit;
            Assert.True(state.TryGetStreamSnapshot(openedStreamId, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(openedStreamId, snapshot.StreamId);
        }

        ulong higherSameTypeStreamId = ((streamOrdinal + 1UL) << 2) | 0x01UL | directionBit;
        Assert.False(state.TryGetStreamSnapshot(higherSameTypeStreamId, out _));
    }

    private static QuicConnectionStreamState CreatePeerStreamState()
    {
        return QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 1024,
            connectionSendLimit: 1024,
            incomingBidirectionalStreamLimit: 1024,
            incomingUnidirectionalStreamLimit: 1024,
            peerBidirectionalStreamLimit: 1024,
            peerUnidirectionalStreamLimit: 1024,
            peerBidirectionalReceiveLimit: 1024,
            peerUnidirectionalReceiveLimit: 1024,
            localBidirectionalReceiveLimit: 1024,
            localUnidirectionalSendLimit: 1024,
            peerBidirectionalSendLimit: 1024);
    }

    private static ulong SelectBoundaryOrRandom(Random random, int iteration)
        => (iteration % 10) switch
        {
            0 => 0UL,
            1 => 1UL,
            2 => 2UL,
            3 => 3UL,
            4 => 63UL,
            5 => 64UL,
            6 => 16_383UL,
            7 => 16_384UL,
            8 => QuicVariableLengthInteger.MaxValue,
            _ => (ulong)random.Next(0, 1 << 20),
        };
}

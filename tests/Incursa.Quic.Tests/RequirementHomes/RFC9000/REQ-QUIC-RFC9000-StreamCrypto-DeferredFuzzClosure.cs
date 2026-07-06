// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_StreamCrypto_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0034")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void LocalStreamIdAllocationFuzz_DoesNotReuseStreamIdsWithinAConnection()
    {
        foreach ((bool IsServer, bool Bidirectional, ulong ExpectedFirstStreamId) testCase in new[]
        {
            (false, true, 0UL),
            (false, false, 2UL),
            (true, true, 1UL),
            (true, false, 3UL),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: testCase.IsServer,
                peerBidirectionalStreamLimit: 4,
                peerUnidirectionalStreamLimit: 4);
            HashSet<ulong> allocatedStreamIds = [];

            for (int index = 0; index < 4; index++)
            {
                Assert.True(state.TryOpenLocalStream(
                    testCase.Bidirectional,
                    out QuicStreamId streamId,
                    out QuicStreamsBlockedFrame blockedFrame));
                Assert.Equal(default, blockedFrame);
                Assert.True(allocatedStreamIds.Add(streamId.Value));
                Assert.Equal(testCase.ExpectedFirstStreamId + ((ulong)index * 4), streamId.Value);
                Assert.Equal(testCase.Bidirectional, streamId.IsBidirectional);
                Assert.Equal(testCase.IsServer, streamId.IsServerInitiated);
            }

            Assert.False(state.TryOpenLocalStream(
                testCase.Bidirectional,
                out _,
                out QuicStreamsBlockedFrame limitFrame));
            Assert.Equal(testCase.Bidirectional, limitFrame.IsBidirectional);
            Assert.Equal(4UL, limitFrame.MaximumStreams);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0293")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CryptoFrameOffsetFuzz_StartsAtZeroInEachPacketNumberSpaceAndPreservesContinuationOffsets()
    {
        foreach ((QuicPacketNumberSpace PacketNumberSpace, byte StartByte) testCase in new[]
        {
            (QuicPacketNumberSpace.Initial, (byte)0x10),
            (QuicPacketNumberSpace.Handshake, (byte)0x30),
            (QuicPacketNumberSpace.ApplicationData, (byte)0x50),
        })
        {
            byte[] firstCryptoData = QuicS12P3TestSupport.CreateSequentialBytes(testCase.StartByte, 3);
            byte[] secondCryptoData = QuicS12P3TestSupport.CreateSequentialBytes((byte)(testCase.StartByte + 0x10), 5);
            byte[] firstFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, firstCryptoData));
            byte[] secondFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame((ulong)firstCryptoData.Length, secondCryptoData));

            Assert.True(QuicFrameCodec.TryParseCryptoFrame(firstFrame, out QuicCryptoFrame parsedFirstFrame, out int firstBytesConsumed));
            Assert.Equal(firstFrame.Length, firstBytesConsumed);
            Assert.Equal(0UL, parsedFirstFrame.Offset);
            Assert.True(firstCryptoData.AsSpan().SequenceEqual(parsedFirstFrame.CryptoData));

            Assert.True(QuicFrameCodec.TryParseCryptoFrame(secondFrame, out QuicCryptoFrame parsedSecondFrame, out int secondBytesConsumed));
            Assert.Equal(secondFrame.Length, secondBytesConsumed);
            Assert.Equal((ulong)firstCryptoData.Length, parsedSecondFrame.Offset);
            Assert.True(secondCryptoData.AsSpan().SequenceEqual(parsedSecondFrame.CryptoData));
        }
    }
}

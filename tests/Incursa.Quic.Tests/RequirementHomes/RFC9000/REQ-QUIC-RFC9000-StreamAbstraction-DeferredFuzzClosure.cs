// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_StreamAbstraction_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0019")]
    [Requirement("REQ-QUIC-RFC9000-0021")]
    [Requirement("REQ-QUIC-RFC9000-0022")]
    [Requirement("REQ-QUIC-RFC9000-0025")]
    [Requirement("REQ-QUIC-RFC9000-0047")]
    [Requirement("REQ-QUIC-RFC9000-0048")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StreamReceiveFuzz_DeliversEachStreamAsAnIndependentOrderedByteStream()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 256,
                incomingBidirectionalStreamLimit: 4,
                peerBidirectionalReceiveLimit: 64);
            ulong firstStreamId = 1;
            ulong secondStreamId = 5;
            byte[] firstHead = [(byte)(0x10 + iteration), (byte)(0x20 + iteration)];
            byte[] firstTail = [(byte)(0x30 + iteration), (byte)(0x40 + iteration)];
            byte[] secondPayload = [(byte)(0x50 + iteration), (byte)(0x60 + iteration), (byte)(0x70 + iteration)];

            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(0x0F, firstStreamId, firstTail, offset: (ulong)firstHead.Length),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            byte[] missingPrefixDestination = new byte[4];
            Assert.False(ReadStream(state, firstStreamId, missingPrefixDestination, out _, out _, out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(0x0F, secondStreamId, secondPayload, offset: 0),
                out errorCode));
            Assert.Equal(default, errorCode);

            byte[] secondDestination = new byte[3];
            Assert.True(ReadStream(state, secondStreamId, secondDestination, out int bytesWritten, out bool completed, out errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(completed);
            Assert.Equal(secondPayload.Length, bytesWritten);
            Assert.True(secondPayload.AsSpan().SequenceEqual(secondDestination[..bytesWritten]));

            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(0x0E, firstStreamId, firstHead, offset: 0),
                out errorCode));
            Assert.Equal(default, errorCode);

            byte[] firstDestination = new byte[4];
            Assert.True(ReadStream(state, firstStreamId, firstDestination, out bytesWritten, out completed, out errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(completed);
            Assert.Equal(firstHead.Length + firstTail.Length, bytesWritten);
            Assert.True(firstHead.Concat(firstTail).ToArray().AsSpan().SequenceEqual(firstDestination[..bytesWritten]));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task WriteStreamFuzz_CreatesOnlyTheNextLocalStreamWhenDataIsSent()
    {
        for (int payloadLength = 1; payloadLength <= 8; payloadLength++)
        {
            (QuicConnectionRuntime runtime, List<QuicConnectionEffect> effects) = CreateRuntimeWithEffectCapture();

            Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
                bidirectional: true,
                out QuicStreamId nextStreamId,
                out _));
            byte[] payload = Enumerable
                .Range(0, payloadLength)
                .Select(value => (byte)(0x80 + value))
                .ToArray();

            await runtime.WriteStreamAsync(nextStreamId.Value, payload);

            Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
                nextStreamId.Value,
                out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal((ulong)payload.Length, snapshot.UniqueBytesSent);
            Assert.NotEmpty(effects);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                runtime.WriteStreamAsync(nextStreamId.Value + 8, payload).AsTask());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0023")]
    [Requirement("REQ-QUIC-RFC9000-0027")]
    [Requirement("REQ-QUIC-RFC9000-0031")]
    [Requirement("REQ-QUIC-RFC9000-0045")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StreamCreationFuzz_KeepsLocalAndPeerStreamIdsUniqueConcurrentAndIncreasing()
    {
        foreach (bool isServer in new[] { false, true })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: isServer,
                connectionReceiveLimit: 256,
                peerBidirectionalStreamLimit: 8,
                peerUnidirectionalStreamLimit: 8,
                incomingBidirectionalStreamLimit: 8,
                incomingUnidirectionalStreamLimit: 8,
                peerBidirectionalReceiveLimit: 64,
                peerUnidirectionalReceiveLimit: 64);
            List<ulong> streamIds = [];
            ulong previousBidi = ulong.MaxValue;
            ulong previousUni = ulong.MaxValue;

            for (int index = 0; index < 4; index++)
            {
                Assert.True(state.TryOpenLocalStream(true, out QuicStreamId bidi, out QuicStreamsBlockedFrame blockedFrame));
                Assert.Equal(default, blockedFrame);
                Assert.True(state.TryOpenLocalStream(false, out QuicStreamId uni, out blockedFrame));
                Assert.Equal(default, blockedFrame);

                if (index > 0)
                {
                    Assert.True(bidi.Value > previousBidi);
                    Assert.True(uni.Value > previousUni);
                }

                previousBidi = bidi.Value;
                previousUni = uni.Value;
                streamIds.Add(bidi.Value);
                streamIds.Add(uni.Value);
            }

            for (int index = 0; index < 4; index++)
            {
                ulong peerBidirectionalStreamId = isServer ? (ulong)(index * 4) : (ulong)(1 + (index * 4));
                ulong peerUnidirectionalStreamId = isServer ? (ulong)(2 + (index * 4)) : (ulong)(3 + (index * 4));
                Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(0x0E, peerBidirectionalStreamId, [(byte)(0x10 + index)]), out QuicTransportErrorCode errorCode));
                Assert.Equal(default, errorCode);
                Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(0x0E, peerUnidirectionalStreamId, [(byte)(0x20 + index)]), out errorCode));
                Assert.Equal(default, errorCode);
                streamIds.Add(peerBidirectionalStreamId);
                streamIds.Add(peerUnidirectionalStreamId);
            }

            Assert.Equal(streamIds.Count, streamIds.Distinct().Count());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0024")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StreamCancellationFrameFuzz_RoundTripsResetAndStopSendingAcrossRepresentativeValues()
    {
        ulong[] streamIds = [0, 1, 2, 3, 4, 63, 64, 16_383];

        foreach (ulong streamId in streamIds)
        {
            QuicResetStreamFrame resetFrame = new(
                streamId,
                applicationProtocolErrorCode: streamId + 7,
                finalSize: streamId + 11);
            byte[] resetEncoded = QuicFrameTestData.BuildResetStreamFrame(resetFrame);

            Assert.True(QuicFrameCodec.TryParseResetStreamFrame(resetEncoded, out QuicResetStreamFrame parsedReset, out int resetBytesConsumed));
            Assert.Equal(resetEncoded.Length, resetBytesConsumed);
            Assert.Equal(resetFrame.StreamId, parsedReset.StreamId);
            Assert.Equal(resetFrame.ApplicationProtocolErrorCode, parsedReset.ApplicationProtocolErrorCode);
            Assert.Equal(resetFrame.FinalSize, parsedReset.FinalSize);

            QuicStopSendingFrame stopSendingFrame = new(streamId, applicationProtocolErrorCode: streamId + 13);
            byte[] stopSendingEncoded = QuicFrameTestData.BuildStopSendingFrame(stopSendingFrame);

            Assert.True(QuicFrameCodec.TryParseStopSendingFrame(stopSendingEncoded, out QuicStopSendingFrame parsedStopSending, out int stopSendingBytesConsumed));
            Assert.Equal(stopSendingEncoded.Length, stopSendingBytesConsumed);
            Assert.Equal(stopSendingFrame.StreamId, parsedStopSending.StreamId);
            Assert.Equal(stopSendingFrame.ApplicationProtocolErrorCode, parsedStopSending.ApplicationProtocolErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0032")]
    [Requirement("REQ-QUIC-RFC9000-0033")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StreamIdEncodingFuzz_RoundTripsOnlyValidVariableLengthIntegerEncodings()
    {
        ulong[] streamIds =
        [
            0,
            1,
            2,
            3,
            63,
            64,
            16_383,
            16_384,
            QuicVariableLengthInteger.MaxValue - 1,
            QuicVariableLengthInteger.MaxValue,
        ];

        foreach (ulong streamIdValue in streamIds)
        {
            byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(streamIdValue);
            Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
            Assert.Equal(streamIdValue, streamId.Value);
            Assert.Equal(encoded.Length, bytesConsumed);
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => QuicStreamTestData.BuildStreamIdentifier(QuicVariableLengthInteger.MaxValue + 1));
        Assert.False(QuicStreamParser.TryParseStreamIdentifier([0x40], out _, out _));
        Assert.False(QuicStreamParser.TryParseStreamIdentifier([0x80, 0x00, 0x00], out _, out _));
    }

    private static QuicStreamFrame ParseStreamFrame(byte frameType, ulong streamId, ReadOnlySpan<byte> streamData, ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(frameType, streamId, streamData, offset),
            out QuicStreamFrame frame));
        return frame;
    }

    private static bool ReadStream(
        QuicConnectionStreamState state,
        ulong streamId,
        Span<byte> destination,
        out int bytesWritten,
        out bool completed,
        out QuicTransportErrorCode errorCode)
    {
        return state.TryReadStreamData(
            streamId,
            destination,
            out bytesWritten,
            out completed,
            out _,
            out _,
            out errorCode);
    }

    private static (QuicConnectionRuntime Runtime, List<QuicConnectionEffect> Effects) CreateRuntimeWithEffectCapture()
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 8,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 8).StateChanged);
        List<QuicConnectionEffect> effects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            effects.AddRange(transition.Effects);
            return true;
        });

        return (runtime, effects);
    }
}

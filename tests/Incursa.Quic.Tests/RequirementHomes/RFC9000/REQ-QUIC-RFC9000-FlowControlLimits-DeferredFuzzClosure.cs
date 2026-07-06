// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_FlowControlLimits_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0157")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PeerInitiatedStreamLimitFuzz_AllowsOnlyStreamsInsideTheAdvertisedLimit()
    {
        foreach (bool isServer in new[] { false, true })
        {
            foreach (bool bidirectional in new[] { true, false })
            {
                for (int limit = 1; limit <= 4; limit++)
                {
                    QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                        isServer: isServer,
                        connectionReceiveLimit: 128,
                        incomingBidirectionalStreamLimit: bidirectional ? (ulong)limit : 8,
                        incomingUnidirectionalStreamLimit: bidirectional ? 8 : (ulong)limit,
                        peerBidirectionalReceiveLimit: 16,
                        peerUnidirectionalReceiveLimit: 16);

                    ulong lastAllowedStreamId = PeerStreamId(isServer, bidirectional, limit - 1);
                    Assert.True(state.TryReceiveStreamFrame(
                        ParseStreamFrame(lastAllowedStreamId, [(byte)(0x10 + limit)]),
                        out QuicTransportErrorCode errorCode));
                    Assert.Equal(default, errorCode);
                    Assert.True(state.TryGetStreamSnapshot(lastAllowedStreamId, out QuicConnectionStreamSnapshot allowedSnapshot));
                    Assert.Equal(QuicStreamReceiveState.Recv, allowedSnapshot.ReceiveState);

                    ulong overLimitStreamId = PeerStreamId(isServer, bidirectional, limit);
                    Assert.False(state.TryReceiveStreamFrame(
                        ParseStreamFrame(overLimitStreamId, [(byte)(0x20 + limit)]),
                        out errorCode));
                    Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
                }
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0158")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CryptoFrameOffsetFuzz_RoundTripsOffsetsOutsideStreamFlowControl()
    {
        ulong[] offsets = [0, 1, 63, 64, 4096, QuicVariableLengthInteger.MaxValue - 2];

        foreach (ulong offset in offsets)
        {
            QuicCryptoFrame frame = new(offset, [(byte)(offset & 0xFF)]);
            byte[] destination = new byte[32];

            Assert.True(QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten));
            Assert.True(QuicFrameCodec.TryParseCryptoFrame(destination.AsSpan(0, bytesWritten), out QuicCryptoFrame parsedFrame, out int bytesConsumed));

            Assert.Equal(bytesWritten, bytesConsumed);
            Assert.Equal(frame.Offset, parsedFrame.Offset);
            Assert.True(frame.CryptoData.SequenceEqual(parsedFrame.CryptoData));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0159")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CryptoBufferCapacityFuzz_ExposesConfiguredLimitsAndRejectsBelowMinimum()
    {
        foreach (int capacity in new[] { 4096, 4097, 8192, 16384 })
        {
            QuicCryptoBuffer buffer = new(capacity);

            Assert.Equal(capacity, buffer.Capacity);
        }

        foreach (int invalidCapacity in new[] { 0, 1, 4095 })
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new QuicCryptoBuffer(invalidCapacity));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0164")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void InitialFlowControlTransportParameterFuzz_PreservesAndAppliesAdvertisedLimits()
    {
        ulong[] values = [1, 2, 16, 63, 64, 1024];

        foreach (ulong value in values)
        {
            QuicTransportParameters parameters = new()
            {
                InitialMaxData = value + 20,
                InitialMaxStreamDataBidiLocal = value + 1,
                InitialMaxStreamDataBidiRemote = value + 2,
                InitialMaxStreamDataUni = value + 3,
            };
            byte[] destination = new byte[64];

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Client,
                destination,
                out int bytesWritten));
            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                destination.AsSpan(0, bytesWritten),
                QuicTransportParameterRole.Server,
                out QuicTransportParameters parsedParameters));

            Assert.Equal(parameters.InitialMaxData, parsedParameters.InitialMaxData);
            Assert.Equal(parameters.InitialMaxStreamDataBidiLocal, parsedParameters.InitialMaxStreamDataBidiLocal);
            Assert.Equal(parameters.InitialMaxStreamDataBidiRemote, parsedParameters.InitialMaxStreamDataBidiRemote);
            Assert.Equal(parameters.InitialMaxStreamDataUni, parsedParameters.InitialMaxStreamDataUni);

            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 1,
                peerBidirectionalReceiveLimit: 1,
                peerUnidirectionalReceiveLimit: 1);
            Assert.True(state.TryApplyInitialReceiveLimits(
                parsedParameters.InitialMaxData!.Value,
                parsedParameters.InitialMaxStreamDataBidiLocal!.Value,
                parsedParameters.InitialMaxStreamDataBidiRemote!.Value,
                parsedParameters.InitialMaxStreamDataUni!.Value));

            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0xA0]), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(parsedParameters.InitialMaxStreamDataBidiRemote, snapshot.ReceiveLimit);
            Assert.Equal(parsedParameters.InitialMaxData, state.ConnectionReceiveLimit);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0167")]
    [Requirement("REQ-QUIC-RFC9000-0168")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MaxStreamDataFuzz_AdvertisesOnlyLargerAbsoluteOffsetsForTheTargetStream()
    {
        for (int iteration = 1; iteration <= 8; iteration++)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 256,
                peerBidirectionalSendLimit: 8,
                peerBidirectionalStreamLimit: 4);

            Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);
            Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId secondStreamId, out blockedFrame));
            Assert.Equal(default, blockedFrame);

            ulong largerAbsoluteOffset = (ulong)(8 + iteration);
            Assert.True(state.TryApplyMaxStreamDataFrame(
                new QuicMaxStreamDataFrame(firstStreamId.Value, largerAbsoluteOffset),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.False(state.TryApplyMaxStreamDataFrame(
                new QuicMaxStreamDataFrame(firstStreamId.Value, largerAbsoluteOffset - 1),
                out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot firstSnapshot));
            Assert.True(state.TryGetStreamSnapshot(secondStreamId.Value, out QuicConnectionStreamSnapshot secondSnapshot));
            Assert.Equal(largerAbsoluteOffset, firstSnapshot.SendLimit);
            Assert.Equal(8UL, secondSnapshot.SendLimit);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0173")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReceiveFlowControlViolationFuzz_RejectsStreamAndConnectionLimitOverruns()
    {
        for (int iteration = 1; iteration <= 8; iteration++)
        {
            QuicConnectionStreamState streamLimitedState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 128,
                peerBidirectionalReceiveLimit: (ulong)iteration);
            Assert.False(streamLimitedState.TryReceiveStreamFrame(
                ParseStreamFrame(1, Enumerable.Repeat((byte)0x30, iteration + 1).ToArray()),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);

            QuicConnectionStreamState connectionLimitedState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: (ulong)iteration,
                incomingBidirectionalStreamLimit: 4,
                peerBidirectionalReceiveLimit: 64);
            Assert.True(connectionLimitedState.TryReceiveStreamFrame(
                ParseStreamFrame(1, Enumerable.Repeat((byte)0x40, iteration).ToArray()),
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.False(connectionLimitedState.TryReceiveStreamFrame(
                ParseStreamFrame(5, [0x41]),
                out errorCode));
            Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
            Assert.Equal((ulong)iteration, connectionLimitedState.ConnectionAccountedBytesReceived);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0180")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CreditUpdateFuzz_EmitsMaxDataAndMaxStreamDataWhenApplicationConsumesBytes()
    {
        for (int payloadLength = 1; payloadLength <= 8; payloadLength++)
        {
            byte[] payload = Enumerable.Repeat((byte)(0x50 + payloadLength), payloadLength).ToArray();
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 16,
                peerBidirectionalReceiveLimit: 8);

            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, payload), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            byte[] destination = new byte[payloadLength];
            Assert.True(state.TryReadStreamData(
                1,
                destination,
                out int bytesWritten,
                out bool completed,
                out QuicMaxDataFrame maxDataFrame,
                out QuicMaxStreamDataFrame maxStreamDataFrame,
                out errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(payloadLength, bytesWritten);
            Assert.False(completed);
            Assert.True(payload.AsSpan().SequenceEqual(destination));
            Assert.Equal((ulong)(16 + payloadLength), maxDataFrame.MaximumData);
            Assert.Equal(1UL, maxStreamDataFrame.StreamId);
            Assert.Equal((ulong)(8 + payloadLength), maxStreamDataFrame.MaximumStreamData);
        }
    }

    private static ulong PeerStreamId(bool endpointIsServer, bool bidirectional, int streamIndex)
    {
        ulong initiatorBit = endpointIsServer ? 0UL : 1UL;
        ulong unidirectionalBit = bidirectional ? 0UL : 2UL;
        return ((ulong)streamIndex << 2) | initiatorBit | unidirectionalBit;
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, ReadOnlySpan<byte> data, ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, data, offset),
            out QuicStreamFrame frame));
        return frame;
    }
}

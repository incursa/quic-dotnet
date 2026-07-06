// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S4P1_DeferredFuzzClosure
{
    private const ulong MaximumFlowControlLimit = 0x3FFF_FFFF_FFFF_FFFFUL;

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StreamReceiveLimitFuzz_AdvertisesConsumedCreditAndRejectsPerStreamOverrun()
    {
        for (int iteration = 0; iteration < 32; iteration++)
        {
            ulong streamReceiveLimit = (ulong)(4 + (iteration % 7));
            ulong connectionReceiveLimit = streamReceiveLimit + 8UL;
            int payloadLength = 1 + (iteration % (int)streamReceiveLimit);
            ulong streamId = (ulong)(1 + (iteration % 4) * 4);

            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: connectionReceiveLimit,
                peerBidirectionalReceiveLimit: streamReceiveLimit);

            QuicStreamFrame acceptedFrame = ParseStreamFrame(
                streamId,
                BuildPayload(payloadLength, seed: iteration),
                offset: 0);
            Assert.True(state.TryReceiveStreamFrame(acceptedFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            QuicStreamFrame overflowFrame = ParseStreamFrame(
                streamId,
                [0xFF],
                offset: streamReceiveLimit);
            Assert.False(state.TryReceiveStreamFrame(overflowFrame, out errorCode));
            Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);

            byte[] destination = new byte[payloadLength];
            Assert.True(state.TryReadStreamData(
                streamId,
                destination,
                out int bytesWritten,
                out bool completed,
                out QuicMaxDataFrame maxDataFrame,
                out QuicMaxStreamDataFrame maxStreamDataFrame,
                out errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(payloadLength, bytesWritten);
            Assert.False(completed);
            Assert.Equal(connectionReceiveLimit + (ulong)payloadLength, maxDataFrame.MaximumData);
            Assert.Equal(streamId, maxStreamDataFrame.StreamId);
            Assert.Equal(streamReceiveLimit + (ulong)payloadLength, maxStreamDataFrame.MaximumStreamData);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MaxDataLimitFuzz_OnlyLargerConnectionLimitsAdvanceSendCredit()
    {
        ulong[] initialLimits =
        [
            0UL,
            1UL,
            7UL,
            64UL,
            1024UL,
            MaximumFlowControlLimit - 1UL,
        ];

        foreach (ulong initialLimit in initialLimits)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionSendLimit: initialLimit);

            Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(initialLimit)));
            Assert.Equal(initialLimit, state.ConnectionSendLimit);

            if (initialLimit > 0)
            {
                Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(initialLimit - 1UL)));
                Assert.Equal(initialLimit, state.ConnectionSendLimit);
            }

            ulong largerLimit = initialLimit == MaximumFlowControlLimit
                ? MaximumFlowControlLimit
                : Math.Min(MaximumFlowControlLimit, initialLimit + 1UL);

            Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(largerLimit)));
            Assert.Equal(largerLimit, state.ConnectionSendLimit);
        }
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] data, ulong offset)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, data, offset: offset),
            out QuicStreamFrame frame));
        return frame;
    }

    private static byte[] BuildPayload(int length, int seed)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(seed + index + 1);
        }

        return payload;
    }
}

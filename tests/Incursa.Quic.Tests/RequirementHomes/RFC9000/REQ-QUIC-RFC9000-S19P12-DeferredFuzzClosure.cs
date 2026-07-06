// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P12_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ConnectionFlowControlLimitFuzz_EmitsDataBlockedAtTheObservedConnectionLimit()
    {
        for (ulong connectionLimit = 1; connectionLimit <= 8; connectionLimit++)
        {
            QuicConnectionStreamState state = CreateWritableStreamState(
                connectionLimit,
                out QuicStreamId streamId);

            Assert.False(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length: (int)connectionLimit + 1,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(connectionLimit, dataBlockedFrame.MaximumData);
            Assert.Equal(default, streamDataBlockedFrame);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ConnectionFlowControlTuningFuzz_UsesDataBlockedMaximumDataAsTheRecoverableLimit()
    {
        for (ulong connectionLimit = 1; connectionLimit <= 8; connectionLimit++)
        {
            QuicConnectionStreamState state = CreateWritableStreamState(
                connectionLimit,
                out QuicStreamId streamId);

            Assert.False(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length: (int)connectionLimit + 1,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(connectionLimit, dataBlockedFrame.MaximumData);
            Assert.Equal(default, streamDataBlockedFrame);

            Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(connectionLimit + 1)));
            Assert.True(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length: (int)connectionLimit + 1,
                fin: false,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
        }
    }

    private static QuicConnectionStreamState CreateWritableStreamState(
        ulong connectionLimit,
        out QuicStreamId streamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: connectionLimit,
            localBidirectionalSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        return state;
    }
}

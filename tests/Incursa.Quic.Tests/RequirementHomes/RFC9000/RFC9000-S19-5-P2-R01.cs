// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S19-5-P2-R01")]
public sealed class REQ_QUIC_RFC9000_1216
{
    [Fact]
    [Requirement("RFC9000-S19-5-P2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_RejectsUncreatedLocalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.False(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId: 4, applicationProtocolErrorCode: 0x44),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, resetStreamFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [Requirement("RFC9000-S19-5-P2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStopSendingFrame_AcceptsCreatedLocalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, applicationProtocolErrorCode: 0x44),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(streamId.Value, resetStreamFrame.StreamId);
    }

    [Fact]
    [Requirement("RFC9000-S19-5-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryReceiveStopSendingFrame_RejectsUncreatedLocalStreams()
    {
        (ulong StreamId, ulong ApplicationErrorCode)[] cases =
        [
            (0, 0x44),
            (4, 0x45),
            (8, 0x46),
            (12, 0x47),
        ];

        foreach ((ulong streamId, ulong applicationErrorCode) in cases)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

            Assert.False(state.TryReceiveStopSendingFrame(
                new QuicStopSendingFrame(streamId, applicationErrorCode),
                out QuicResetStreamFrame resetStreamFrame,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, resetStreamFrame);
            Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        }
    }
}

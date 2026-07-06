// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S19-10-P2-S1-R01")]
public sealed class REQ_QUIC_RFC9000_1275
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_AcceptsCreatedLocallyInitiatedStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 12), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(12UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_RejectsUncreatedLocallyInitiatedStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(0, 12), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(0, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxStreamDataFrame_RejectsSkippedLocallyInitiatedStreamIds()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(0UL, streamId.Value);
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(4, 12), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(4, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryApplyMaxStreamDataFrame_RejectsUncreatedLocallyInitiatedStreams()
    {
        (ulong StreamId, ulong SendLimit)[] cases =
        [
            (0, 12),
            (4, 16),
            (8, 32),
            (12, 64),
        ];

        foreach ((ulong streamId, ulong sendLimit) in cases)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 16,
                connectionSendLimit: 16);

            Assert.False(state.TryApplyMaxStreamDataFrame(
                new QuicMaxStreamDataFrame(streamId, sendLimit),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
            Assert.False(state.TryGetStreamSnapshot(streamId, out _));
        }
    }
}

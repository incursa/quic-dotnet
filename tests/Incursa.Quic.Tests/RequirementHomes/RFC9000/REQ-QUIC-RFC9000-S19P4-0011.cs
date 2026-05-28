// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
public sealed class REQ_QUIC_RFC9000_S19P4_0011
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveResetStreamFrame_RecordsFinalSize()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 4),
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveResetStreamFrame_RejectsFinalSizeBelowReceivedOffset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 4),
            out QuicStreamFrame streamFrame));
        Assert.True(state.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveResetStreamFrame_AllowsFinalSizeThatMatchesKnownFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame finFrame));
        Assert.True(state.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 2),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        _ = maxDataFrame;
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
    }
}

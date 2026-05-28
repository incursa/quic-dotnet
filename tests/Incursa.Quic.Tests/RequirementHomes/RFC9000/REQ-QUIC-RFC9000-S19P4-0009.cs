// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
public sealed class REQ_QUIC_RFC9000_S19P4_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseResetStreamFrame_PreservesTerminatedStreamId()
    {
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(
            new QuicResetStreamFrame(streamId: 0x44, applicationProtocolErrorCode: 0x55, finalSize: 0x66));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out _));
        Assert.Equal(0x44UL, parsed.StreamId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveResetStreamFrame_TerminatesOnlyTheNamedStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: 4);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0A, 5, [0xAA], offset: 0),
            out QuicStreamFrame unrelatedStreamFrame));
        Assert.True(state.TryReceiveStreamFrame(unrelatedStreamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 0),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot resetSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, resetSnapshot.ReceiveState);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot unrelatedSnapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, unrelatedSnapshot.ReceiveState);
        Assert.Equal(1UL, unrelatedSnapshot.UniqueBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseResetStreamFrame_PreservesMaximumEncodedStreamId()
    {
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(
            new QuicResetStreamFrame(
                QuicVariableLengthInteger.MaxValue,
                applicationProtocolErrorCode: 0x55,
                finalSize: 0x66));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.StreamId);
    }
}

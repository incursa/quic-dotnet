// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
public sealed class REQ_QUIC_RFC9000_S19P4_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveResetStreamFrame_StoresApplicationErrorReason()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 0),
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetReceiveAbortErrorCode(1, out ulong applicationErrorCode));
        Assert.Equal(0x55UL, applicationErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveResetStreamFrame_DoesNotStoreRejectedApplicationErrorReason()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 4),
            out QuicStreamFrame streamFrame));
        Assert.True(state.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 1),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
        Assert.False(state.TryGetReceiveAbortErrorCode(1, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveResetStreamFrame_StoresMaximumApplicationErrorReason()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(
                streamId: 1,
                applicationProtocolErrorCode: QuicVariableLengthInteger.MaxValue,
                finalSize: 0),
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetReceiveAbortErrorCode(1, out ulong applicationErrorCode));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, applicationErrorCode);
    }
}

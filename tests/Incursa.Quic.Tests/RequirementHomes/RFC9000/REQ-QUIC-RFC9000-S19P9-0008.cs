// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0008">This MUST include violations of remembered limits in Early Data; see Section 7.4.1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P9-0008")]
public sealed class REQ_QUIC_RFC9000_S19P9_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_RejectsEarlyDataAboveRememberedMaxDataLimit()
    {
        QuicTransportParameters rememberedServerParameters = new()
        {
            InitialMaxData = 3,
            InitialMaxStreamDataBidiRemote = 8,
        };
        QuicConnectionStreamState state = CreateServerEarlyDataReceiveState(rememberedServerParameters);

        Assert.True(state.TryReceiveStreamFrame(ParseClientStreamFrame([0x10, 0x11], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReceiveStreamFrame(ParseClientStreamFrame([0x12, 0x13], offset: 2), out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_AllowsEarlyDataWithinRememberedMaxDataLimit()
    {
        QuicTransportParameters rememberedServerParameters = new()
        {
            InitialMaxData = 4,
            InitialMaxStreamDataBidiRemote = 8,
        };
        QuicConnectionStreamState state = CreateServerEarlyDataReceiveState(rememberedServerParameters);

        Assert.True(state.TryReceiveStreamFrame(ParseClientStreamFrame([0x10, 0x11], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseClientStreamFrame([0x12, 0x13], offset: 2), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);
    }

    private static QuicConnectionStreamState CreateServerEarlyDataReceiveState(QuicTransportParameters rememberedServerParameters)
    {
        Assert.True(rememberedServerParameters.InitialMaxData.HasValue);
        Assert.True(rememberedServerParameters.InitialMaxStreamDataBidiRemote.HasValue);

        return QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: rememberedServerParameters.InitialMaxData.Value,
            peerBidirectionalReceiveLimit: rememberedServerParameters.InitialMaxStreamDataBidiRemote.Value);
    }

    private static QuicStreamFrame ParseClientStreamFrame(ReadOnlySpan<byte> streamData, ulong offset)
    {
        byte[] frameBytes = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 0,
            streamData,
            offset);

        Assert.True(QuicStreamParser.TryParseStreamFrame(frameBytes, out QuicStreamFrame frame));
        return frame;
    }
}

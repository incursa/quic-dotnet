// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P14-0009")]
public sealed class REQ_QUIC_RFC9000_S19P14_0009
{
    [Theory]
    [InlineData(true, 0x16UL)]
    [InlineData(false, 0x17UL)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtectedStreamsBlockedFrame_ClosesWithFrameEncodingErrorAboveTheAllowedLimit(
        bool isBidirectional,
        ulong expectedFrameType)
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicStreamsBlockedFrame invalidFrame = new(
            isBidirectional,
            QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit + 1);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(invalidFrame);

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.FrameEncodingError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(expectedFrameType, runtime.TerminalState.Value.Close.TriggeringFrameType);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0008">This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0009">Receipt of a frame that encodes a larger stream ID MUST be treated as a connection error of type STREAM_LIMIT_ERROR or FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamsBlockedFrame_RejectsValuesAboveTheEncodingLimit()
    {
        QuicStreamsBlockedFrame frame = new(true, (1UL << 60) + 1);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamsBlockedFrame(frame, stackalloc byte[16], out _));
    }
}

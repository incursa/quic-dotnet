// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1244")]
public sealed class REQ_QUIC_RFC9000_1244
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientTreatsEmptyNewTokenFrameAsFrameEncodingError()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(Array.Empty<byte>());

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.FrameEncodingError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(0x07UL, runtime.TerminalState.Value.Close.TriggeringFrameType);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewTokenFrame_RejectsEmptyTokens()
    {
        QuicNewTokenFrame emptyFrame = new(Array.Empty<byte>());
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(emptyFrame);

        Assert.False(QuicFrameCodec.TryParseNewTokenFrame(encoded, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientTreatsZeroLengthNewTokenFrameWithTrailingPayloadAsFrameEncodingError()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        byte[] encoded = [.. QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(Array.Empty<byte>()), 0x01];

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.FrameEncodingError, runtime.TerminalState!.Value.Close.TransportErrorCode);
        Assert.Equal(0x07UL, runtime.TerminalState.Value.Close.TriggeringFrameType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1244")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzNewTokenFrame_RoundTripsNonEmptyTokensAndRejectsTruncation()
    {
        QuicFrameCodecFuzzSupport.FuzzNewTokenFrame();
    }
}

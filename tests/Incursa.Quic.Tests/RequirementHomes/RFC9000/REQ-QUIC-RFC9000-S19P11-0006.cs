// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P11-0006")]
public sealed class REQ_QUIC_RFC9000_S19P11_0006
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamsFrame_AcceptsValuesBelowTheEncodingLimit(bool isBidirectional)
    {
        ulong maximumStreamsBelowTheEncodingLimit = (1UL << 60) - 1;
        QuicMaxStreamsFrame frame = new(isBidirectional, maximumStreamsBelowTheEncodingLimit);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame, parsed);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(frame, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamsFrame_RejectsValuesAboveTheEncodingLimit()
    {
        QuicMaxStreamsFrame invalidFrame = new(true, (1UL << 60) + 1);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(invalidFrame);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatMaxStreamsFrame(invalidFrame, destination, out _));
    }

    [Theory]
    [InlineData(true, 0x12UL)]
    [InlineData(false, 0x13UL)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedMaxStreamsFrame_ClosesWithFrameEncodingErrorAboveTheEncodingLimit(
        bool isBidirectional,
        ulong expectedFrameType)
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicMaxStreamsFrame invalidFrame = new(isBidirectional, (1UL << 60) + 1);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(invalidFrame);

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.FrameEncodingError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(expectedFrameType, runtime.TerminalState.Value.Close.TriggeringFrameType);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamsFrame_AcceptsValuesAtTheEncodingLimit(bool isBidirectional)
    {
        QuicMaxStreamsFrame frame = new(isBidirectional, 1UL << 60);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame, parsed);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(frame, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ProtectedMaxStreamsFrame_AcceptsValuesAtTheEncodingLimit(bool isBidirectional)
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicMaxStreamsFrame frame = new(isBidirectional, 1UL << 60);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        ulong peerLimit = isBidirectional
            ? runtime.StreamRegistry.Bookkeeping.PeerBidirectionalStreamLimit
            : runtime.StreamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit;
        Assert.Equal(frame.MaximumStreams, peerLimit);
    }
}

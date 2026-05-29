// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S4-0001")]
[Requirement("REQ-QUIC-RFC9221-S4-0002")]
[Requirement("REQ-QUIC-RFC9221-S4-0003")]
[Requirement("REQ-QUIC-RFC9221-S4-0004")]
[Requirement("REQ-QUIC-RFC9221-S4-0005")]
[Requirement("REQ-QUIC-RFC9221-S4-0006")]
public sealed class REQ_QUIC_RFC9221_S4_0001
{
    [Theory]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(0x30, new byte[] { 0xA0, 0xA1, 0xA2 })]
    [InlineData(0x31, new byte[] { 0xB0, 0xB1 })]
    [InlineData(0x31, new byte[] { })]
    public void TryParseDatagramFrame_And_TryFormatDatagramFrame_RoundTrip(byte frameType, byte[] datagramData)
    {
        QuicDatagramFrame frame = new()
        {
            FrameType = frameType,
            DatagramData = datagramData,
        };
        byte[] encoded = QuicFrameTestData.BuildDatagramFrame(frame);

        Assert.True(QuicFrameCodec.TryParseDatagramFrame(encoded, out QuicDatagramFrame parsed, out int bytesConsumed));
        Assert.Equal(frameType, parsed.FrameType);
        Assert.True(datagramData.AsSpan().SequenceEqual(parsed.DatagramData.Span));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatDatagramFrame(parsed, destination, out int bytesWritten));
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseDatagramFrame_RejectsInvalidTypesAndTruncatedLength()
    {
        Assert.False(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x2F, 0x00 }, out _, out _));
        Assert.False(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x32, 0x00 }, out _, out _));
        Assert.False(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x31, 0x03, 0xA0 }, out _, out _));
        Assert.False(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x31, 0x40 }, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S4-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedOneRttDatagramFrame_ClosesOnMalformedLength()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedApplicationPayload(
            runtime,
            [QuicFrameCodec.DatagramWithLengthFrameType, 0x40, 0xFF]);

        Assert.True(result.StateChanged);
        QuicConnectionTerminalState terminalState = Assert.IsType<QuicConnectionTerminalState>(runtime.TerminalState);
        Assert.Equal(QuicTransportErrorCode.FrameEncodingError, terminalState.Close.TransportErrorCode);
        Assert.Equal(QuicFrameCodec.DatagramWithLengthFrameType, terminalState.Close.TriggeringFrameType);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDeliverDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzDatagramFrame_RoundTripsRepresentativeShapes()
    {
        QuicFrameCodecFuzzSupport.FuzzDatagramFrame();
    }
}

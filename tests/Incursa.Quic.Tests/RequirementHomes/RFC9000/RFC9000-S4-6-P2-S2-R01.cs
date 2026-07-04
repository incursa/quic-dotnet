// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S4-6-P2-S2-R01")]
public sealed class RFC9000_S4_6_P2_S2_R01
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("RFC9000-S4-6-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamsFrame_AcceptsMaximumValidStreamCount(bool isBidirectional)
    {
        QuicMaxStreamsFrame frame = new(isBidirectional, 1UL << 60);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(0x12)]
    [InlineData(0x13)]
    [Requirement("RFC9000-S4-6-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedApplicationDataPacket_ClosesOnOversizedMaxStreamsFrame(byte frameType)
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        byte[] payload = BuildMaxStreamsPayload(frameType, (1UL << 60) + 1);

        QuicConnectionTransitionResult result =
            QuicStreamControlFrameTestSupport.ReceiveProtectedApplicationPayload(runtime, payload, nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.FrameEncodingError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal((ulong)frameType, runtime.TerminalState.Value.Close.TriggeringFrameType);
    }

    [Fact]
    [Requirement("RFC9000-S4-6-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamsFrame_RejectsValuesAboveTheEncodingLimit()
    {
        ulong maximumStreamLimit = 1UL << 60;
        ulong oversizedMaximumStreamLimit = maximumStreamLimit + 1;

        Span<byte> encoded = stackalloc byte[16];
        Assert.True(QuicVariableLengthInteger.TryFormat(oversizedMaximumStreamLimit, encoded[1..], out int encodedValueBytes));
        encoded[0] = 0x12;

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encoded[..(encodedValueBytes + 1)], out QuicMaxStreamsFrame frame, out int bytesConsumed));
        Assert.Equal(default, frame);
        Assert.Equal(default, bytesConsumed);
    }

    private static byte[] BuildMaxStreamsPayload(byte frameType, ulong maximumStreams)
    {
        Span<byte> encoded = stackalloc byte[16];
        Assert.True(QuicVariableLengthInteger.TryFormat(maximumStreams, encoded[1..], out int encodedValueBytes));
        encoded[0] = frameType;

        return encoded[..(encodedValueBytes + 1)].ToArray();
    }
}

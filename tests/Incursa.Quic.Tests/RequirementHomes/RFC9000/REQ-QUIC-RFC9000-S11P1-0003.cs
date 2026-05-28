// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0003">Transport errors, including all those described in this document, MUST be carried in the CONNECTION_CLOSE frame with a frame type of 0x1c.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11P1-0003")]
public sealed class REQ_QUIC_RFC9000_S11P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorsUseConnectionCloseTypeOneC()
    {
        byte[] reasonPhrase = [0x74, 0x72, 0x6E];
        QuicConnectionCloseFrame frame = new(QuicTransportErrorCode.ProtocolViolation, 0x02, reasonPhrase);

        Assert.False(frame.IsApplicationError);
        Assert.Equal((byte)0x1C, frame.FrameType);
        Assert.True(frame.HasTriggeringFrameType);
        Assert.Equal(0x02UL, frame.TriggeringFrameType);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(
            QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.ProtocolViolation, parsed.ErrorCode);
        Assert.Equal(0x02UL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}

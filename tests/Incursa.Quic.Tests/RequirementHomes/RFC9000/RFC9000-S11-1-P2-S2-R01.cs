// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S11-1-P2-S2-R01">Transport errors, including all those described in this document, MUST be carried in the CONNECTION_CLOSE frame with a frame type of 0x1c.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S11-1-P2-S2-R01")]
public sealed class RFC9000_S11_1_P2_S2_R01
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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TransportErrorsUseConnectionCloseTypeOneC()
    {
        (ulong ErrorCode, ulong TriggeringFrameType, byte[] ReasonPhrase)[] cases =
        [
            ((ulong)QuicTransportErrorCode.NoError, 0x00, []),
            ((ulong)QuicTransportErrorCode.ProtocolViolation, 0x02, [0x70]),
            ((ulong)QuicTransportErrorCode.FlowControlError, 0x10, [0x66, 0x63]),
            ((ulong)QuicTransportErrorCode.FrameEncodingError, 0x06, [0x66, 0x72, 0x6D]),
            ((ulong)QuicTransportErrorCode.ConnectionIdLimitError, 0x18, [0x63, 0x69, 0x64]),
        ];

        byte[] destination = new byte[64];
        foreach ((ulong errorCode, ulong triggeringFrameType, byte[] reasonPhrase) in cases)
        {
            byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
                errorCode,
                triggeringFrameType,
                reasonPhrase);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));

            Assert.False(parsed.IsApplicationError);
            Assert.Equal((byte)0x1C, parsed.FrameType);
            Assert.Equal(errorCode, parsed.ErrorCode);
            Assert.True(parsed.HasTriggeringFrameType);
            Assert.Equal(triggeringFrameType, parsed.TriggeringFrameType);
            Assert.Equal(reasonPhrase, parsed.ReasonPhrase.ToArray());
            Assert.Equal(encoded.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination.AsSpan(0, bytesWritten)));
        }
    }
}

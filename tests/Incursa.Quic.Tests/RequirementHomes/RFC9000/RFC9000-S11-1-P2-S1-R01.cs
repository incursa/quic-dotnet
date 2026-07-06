// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S11-1-P2-S1-R01">Application-specific protocol errors MUST be signaled using the CONNECTION_CLOSE frame with a frame type of 0x1d.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S11-1-P2-S1-R01")]
public sealed class RFC9000_S11_1_P2_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportErrorsDoNotUseApplicationConnectionCloseTypeOneD()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x02,
            reasonPhrase: [0x74, 0x72, 0x6E]);

        Assert.True(
            QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.True(parsed.HasTriggeringFrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.ProtocolViolation, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ApplicationErrorsUseConnectionCloseTypeOneD()
    {
        byte[] reasonPhrase = [0x61, 0x70, 0x70];
        QuicConnectionCloseFrame frame = new(0x1234, reasonPhrase);

        Assert.True(frame.IsApplicationError);
        Assert.Equal((byte)0x1D, frame.FrameType);
        Assert.False(frame.HasTriggeringFrameType);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(
            QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ApplicationErrorsUseConnectionCloseTypeOneD()
    {
        (ulong ErrorCode, byte[] ReasonPhrase)[] cases =
        [
            (0UL, []),
            (1UL, [0x61]),
            (42UL, [0x61, 0x70]),
            (0x1234UL, [0x61, 0x70, 0x70]),
            (0x3FFFUL, [0x71, 0x75, 0x69, 0x63]),
        ];

        byte[] destination = new byte[64];
        foreach ((ulong errorCode, byte[] reasonPhrase) in cases)
        {
            byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode, reasonPhrase);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));

            Assert.True(parsed.IsApplicationError);
            Assert.Equal((byte)0x1D, parsed.FrameType);
            Assert.Equal(errorCode, parsed.ErrorCode);
            Assert.False(parsed.HasTriggeringFrameType);
            Assert.Equal(reasonPhrase, parsed.ReasonPhrase.ToArray());
            Assert.Equal(encoded.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination.AsSpan(0, bytesWritten)));
        }
    }
}

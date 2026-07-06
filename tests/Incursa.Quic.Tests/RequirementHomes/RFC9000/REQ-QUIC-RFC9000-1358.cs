// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1358")]
public sealed class REQ_QUIC_RFC9000_1358
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_DoesNotUseTransportErrorCodeSpaceForApplicationCloseFrames()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(
            errorCode: (ulong)QuicTransportErrorCode.FrameEncodingError,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.False(parsed.HasTriggeringFrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.FrameEncodingError, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesTransportErrorCodesOnTransportCloseFrames()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.FrameEncodingError,
            triggeringFrameType: 0x19,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.FrameEncodingError, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryParseConnectionCloseFrame_KeepsTransportAndApplicationErrorCodeSpacesDistinct()
    {
        ulong[] errorCodes =
        [
            0,
            (ulong)QuicTransportErrorCode.InternalError,
            (ulong)QuicTransportErrorCode.FrameEncodingError,
            0x3F,
            0x4000,
        ];

        foreach (ulong errorCode in errorCodes)
        {
            byte[] transportClose = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
                errorCode,
                triggeringFrameType: 0x19,
                reasonPhrase: [0x74, 0x78]);
            byte[] applicationClose = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(
                errorCode,
                reasonPhrase: [0x61, 0x70, 0x70]);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                transportClose,
                out QuicConnectionCloseFrame parsedTransportClose,
                out int transportCloseBytesConsumed));
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                applicationClose,
                out QuicConnectionCloseFrame parsedApplicationClose,
                out int applicationCloseBytesConsumed));

            Assert.False(parsedTransportClose.IsApplicationError);
            Assert.True(parsedTransportClose.HasTriggeringFrameType);
            Assert.Equal((byte)0x1C, parsedTransportClose.FrameType);
            Assert.Equal(errorCode, parsedTransportClose.ErrorCode);
            Assert.Equal(transportClose.Length, transportCloseBytesConsumed);

            Assert.True(parsedApplicationClose.IsApplicationError);
            Assert.False(parsedApplicationClose.HasTriggeringFrameType);
            Assert.Equal((byte)0x1D, parsedApplicationClose.FrameType);
            Assert.Equal(errorCode, parsedApplicationClose.ErrorCode);
            Assert.Equal(applicationClose.Length, applicationCloseBytesConsumed);
        }
    }
}

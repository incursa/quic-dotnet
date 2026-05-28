// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0008")]
public sealed class REQ_QUIC_RFC9000_S19P19_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesTheCloseReasonErrorCode()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.ProtocolViolation,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal((ulong)QuicTransportErrorCode.ProtocolViolation, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsMissingCloseReasonErrorCode()
    {
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1D], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_PreservesNoErrorAsAValidCloseReason()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.NoError,
            triggeringFrameType: 0,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal((ulong)QuicTransportErrorCode.NoError, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0004")]
public sealed class REQ_QUIC_RFC9000_S19P19_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesVariableLengthErrorCode()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(errorCode: 0x1234, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsMissingErrorCode()
    {
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1C], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_PreservesMaximumVariableLengthErrorCode()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: QuicVariableLengthInteger.MaxValue,
            triggeringFrameType: 0,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

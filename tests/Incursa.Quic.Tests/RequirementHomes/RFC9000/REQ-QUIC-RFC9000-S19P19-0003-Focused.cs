// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0003")]
public sealed class REQ_QUIC_RFC9000_S19P19_0003_Focused
{
    [Theory]
    [InlineData(0x1C, false)]
    [InlineData(0x1D, true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_AcceptsOnlyTheConnectionCloseTypeRange(byte frameType, bool expectedApplicationError)
    {
        byte[] encoded = frameType == 0x1D
            ? QuicConnectionCloseFrameProofSupport.BuildApplicationClose(reasonPhrase: [])
            : QuicConnectionCloseFrameProofSupport.BuildTransportClose(reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(expectedApplicationError, parsed.IsApplicationError);
        Assert.Equal(frameType, parsed.FrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Theory]
    [InlineData(0x1B)]
    [InlineData(0x1E)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsTypesOutsideTheConnectionCloseTypeRange(byte frameType)
    {
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([frameType, 0x00], out _, out _));
    }

    [Theory]
    [InlineData(0x1C)]
    [InlineData(0x1D)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_RejectsNonMinimalVarintEncodingsOfTheConnectionCloseTypes(byte frameType)
    {
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x40, frameType, 0x00], out _, out _));
    }
}

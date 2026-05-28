// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0014")]
public sealed class REQ_QUIC_RFC9000_S19P19_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_UsesReasonPhraseLengthToBoundReasonBytes()
    {
        byte[] reasonPhrase = [0x6F, 0x6B, 0x21];
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(reasonPhrase: reasonPhrase);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(reasonPhrase.Length, parsed.ReasonPhrase.Length);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsReasonPhraseLengthThatExceedsRemainingBytes()
    {
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1D, 0x00, 0x02, 0xAA], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_PreservesTwoByteApplicationReasonPhraseLength()
    {
        byte[] reasonPhrase = Enumerable.Repeat((byte)0x52, 64).ToArray();
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(reasonPhrase: reasonPhrase);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(64, parsed.ReasonPhrase.Length);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}

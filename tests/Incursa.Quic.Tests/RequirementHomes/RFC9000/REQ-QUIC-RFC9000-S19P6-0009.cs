// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0009")]
public sealed class REQ_QUIC_RFC9000_S19P6_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_LengthFieldControlsConsumedCryptoData()
    {
        byte[] frame = [.. QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(0, 2, [0xAA, 0xBB]), 0xCC];

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(frame, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.Length - 1, bytesConsumed);
        Assert.Equal(0UL, parsed.Offset);
        Assert.True(parsed.CryptoData.SequenceEqual(new byte[] { 0xAA, 0xBB }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsDeclaredLengthBeyondPayload()
    {
        byte[] frame = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(
            offset: 0,
            declaredLength: 3,
            cryptoData: [0xAA, 0xBB]);

        QuicS19P6CryptoFrameTestSupport.AssertRejects(frame);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseCryptoFrame_AcceptsZeroDeclaredLengthWithoutConsumingTrailingBytes()
    {
        byte[] frame = [.. QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(0, 0, []), 0xCC];

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(frame, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.Length - 1, bytesConsumed);
        Assert.Equal(0UL, parsed.Offset);
        Assert.True(parsed.CryptoData.IsEmpty);
    }
}

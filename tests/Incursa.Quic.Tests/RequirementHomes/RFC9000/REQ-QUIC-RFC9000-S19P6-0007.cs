// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0007")]
public sealed class REQ_QUIC_RFC9000_S19P6_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatCryptoFrame_EmitsTypeOffsetLengthAndDataInOrder()
    {
        byte[] cryptoData = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] expected =
        [
            0x06,
            .. QuicVarintTestData.EncodeMinimal(0x1234),
            .. QuicVarintTestData.EncodeMinimal((ulong)cryptoData.Length),
            .. cryptoData,
        ];

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(new QuicCryptoFrame(0x1234, cryptoData), destination, out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
        QuicS19P6CryptoFrameTestSupport.AssertParses(destination[..bytesWritten], 0x1234, cryptoData);
    }
}

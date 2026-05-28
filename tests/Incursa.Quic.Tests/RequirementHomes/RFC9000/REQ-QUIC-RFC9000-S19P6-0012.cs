// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0012")]
public sealed class REQ_QUIC_RFC9000_S19P6_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatCryptoFrame_CarriesSingleEncryptionLevelStreamDataWithoutStreamId()
    {
        byte[] cryptoData = [0xA0, 0xA1, 0xA2];
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, cryptoData));

        Assert.Equal(QuicS19P6CryptoFrameTestSupport.CryptoFrameType, encoded[0]);
        Assert.Equal(0x00, encoded[1]);
        Assert.Equal((byte)cryptoData.Length, encoded[2]);
        Assert.True(cryptoData.AsSpan().SequenceEqual(encoded.AsSpan(3)));
        QuicS19P6CryptoFrameTestSupport.AssertParses(encoded, 0, cryptoData);
    }
}

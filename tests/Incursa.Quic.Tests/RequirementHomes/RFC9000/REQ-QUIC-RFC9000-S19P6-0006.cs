// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0006")]
public sealed class REQ_QUIC_RFC9000_S19P6_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_ConsumesVariableLengthLengthField()
    {
        byte[] cryptoData = Enumerable.Range(0, 64).Select(static value => (byte)value).ToArray();
        byte[] frame = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithEncodedLength(
            offset: 0,
            declaredLength: 64,
            encodedLengthLength: 2,
            cryptoData);

        QuicS19P6CryptoFrameTestSupport.AssertParses(frame, 0, cryptoData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsTruncatedLengthVarint()
    {
        QuicS19P6CryptoFrameTestSupport.AssertRejects([QuicS19P6CryptoFrameTestSupport.CryptoFrameType, 0x00, 0x40]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseCryptoFrame_AcceptsZeroLengthCryptoData()
    {
        byte[] frame = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(
            offset: 3,
            declaredLength: 0,
            cryptoData: []);

        QuicS19P6CryptoFrameTestSupport.AssertParses(frame, 3, []);
    }
}

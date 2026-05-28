// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1222")]
public sealed class REQ_QUIC_RFC9000_1222
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-1222")]
    public void TryParseCryptoFrame_RejectsNonCryptoFrameTypesForHandshakeMessages()
    {
        byte[] frameWithStreamType = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithFields(
            [0x08],
            QuicVarintTestData.EncodeMinimal(0),
            QuicVarintTestData.EncodeMinimal(4),
            [0x01, 0x00, 0x00, 0x20]);

        QuicS19P6CryptoFrameTestSupport.AssertRejects(frameWithStreamType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatCryptoFrame_UsesType06ForHandshakeMessages()
    {
        byte[] handshakeBytes = [0x01, 0x00, 0x00, 0x20];
        QuicCryptoFrame frame = new(0, handshakeBytes);
        Span<byte> destination = stackalloc byte[32];

        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten));
        Assert.Equal(QuicS19P6CryptoFrameTestSupport.CryptoFrameType, destination[0]);
        QuicS19P6CryptoFrameTestSupport.AssertParses(destination[..bytesWritten], 0, handshakeBytes);
    }
}

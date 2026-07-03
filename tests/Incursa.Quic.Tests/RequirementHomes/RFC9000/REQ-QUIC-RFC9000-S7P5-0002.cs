// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-5-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S7P5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAddFrame_AllowsConfiguredCapacityDuringHandshake()
    {
        QuicCryptoBuffer buffer = new(8192);
        byte[] cryptoData = new byte[5000];

        Assert.Equal(8192, buffer.Capacity);
        Assert.False(buffer.HandshakeComplete);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, cryptoData), out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);
        Assert.Equal(5000, buffer.BufferedBytes);
    }
}

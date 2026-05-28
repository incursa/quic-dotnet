// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0159")]
public sealed class REQ_QUIC_RFC9000_0159
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Constructor_ExposesConfiguredBufferCapacity()
    {
        QuicCryptoBuffer minimumBuffer = new();
        QuicCryptoBuffer configuredBuffer = new(8192);

        Assert.Equal(4096, minimumBuffer.Capacity);
        Assert.Equal(8192, configuredBuffer.Capacity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Constructor_RejectsBufferCapacityBelowTheMinimumInterfaceLimit()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicCryptoBuffer(4095));
    }
}

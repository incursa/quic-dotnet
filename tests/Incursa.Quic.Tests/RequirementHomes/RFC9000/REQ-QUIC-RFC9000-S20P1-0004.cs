// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
public sealed class REQ_QUIC_RFC9000_S20P1_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesCryptoBufferExceeded()
    {
        (ulong wireValue, string expectedName, string expectedDescription) = Assert.Single(
            QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes,
            candidate => candidate.ExpectedName == nameof(QuicTransportErrorCode.CryptoBufferExceeded));

        Assert.Equal(0x0DUL, wireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.CryptoBufferExceeded), expectedName);
        Assert.NotEmpty(expectedDescription);
    }
}

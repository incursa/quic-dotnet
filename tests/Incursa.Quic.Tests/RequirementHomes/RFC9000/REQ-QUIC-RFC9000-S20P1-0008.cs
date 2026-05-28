// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0008")]
public sealed class REQ_QUIC_RFC9000_S20P1_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_UsesGeneralFunctionCodesForTheRestOfTheStack()
    {
        Assert.Contains(
            QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes,
            candidate => candidate.ExpectedName == nameof(QuicTransportErrorCode.FlowControlError));
        Assert.Contains(
            QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes,
            candidate => candidate.ExpectedName == nameof(QuicTransportErrorCode.TransportParameterError));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportErrorCodeRegistry_DoesNotInventAdditionalGeneralPurposeCodes()
    {
        Assert.False(Enum.IsDefined(typeof(QuicTransportErrorCode), 0x11UL));
    }
}

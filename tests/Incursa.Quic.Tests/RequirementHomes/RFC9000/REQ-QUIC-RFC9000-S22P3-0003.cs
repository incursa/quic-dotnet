// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P3-0003")]
public sealed class REQ_QUIC_RFC9000_S22P3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S22P3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportParameterRegistry_IncludesTheParameterNameField()
    {
        foreach ((_, string parameterName) in QuicTransportParameterRegistryProofSupport.PermanentTransportParameters)
        {
            Assert.NotEmpty(parameterName);
        }
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicVersionInformationParserUnitTests
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseTransportParameters_RejectsVersionInformationWithMisalignedLength()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x11,
                [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryParseTransportParameters_RejectsMalformedVersionInformationAcrossRepresentativeShapes()
    {
        QuicVersionInformationFuzzSupport.FuzzTransportParameterCodecRejectsMalformedVersionInformationAcrossRepresentativeShapes();
    }
}

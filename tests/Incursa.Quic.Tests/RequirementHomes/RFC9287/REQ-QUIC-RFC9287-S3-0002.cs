// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9287-S3-0002")]
public sealed class REQ_QUIC_RFC9287_S3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_AcceptsEmptyGreaseQuicBitParameter()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(0x2AB2, []);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.True(parsed.GreaseQuicBit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsNonEmptyGreaseQuicBitParameter()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(0x2AB2, [0x01]);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseTransportParameters_RejectsNonEmptyGreaseQuicBitAtTheParameterBlockBoundary()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(1200UL)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, [0x01]),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x2AB2, [0x01, 0x02]));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryParseTransportParameters_RejectsNonEmptyGreaseQuicBitAcrossRepresentativeShapes()
    {
        QuicGreaseQuicBitFuzzSupport.FuzzTransportParameterCodecRejectsNonEmptyGreaseBitValues();
    }
}

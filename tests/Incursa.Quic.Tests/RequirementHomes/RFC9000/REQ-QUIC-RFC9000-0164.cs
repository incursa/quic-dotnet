// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0164")]
public sealed class REQ_QUIC_RFC9000_0164
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0164")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_DoesNotInjectInitialFlowControlLimitsWhenUnset()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(30)));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedParameters));

        Assert.Equal(30UL, parsedParameters.MaxIdleTimeout);
        Assert.Null(parsedParameters.InitialMaxData);
        Assert.Null(parsedParameters.InitialMaxStreamDataBidiLocal);
        Assert.Null(parsedParameters.InitialMaxStreamDataBidiRemote);
        Assert.Null(parsedParameters.InitialMaxStreamDataUni);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0164")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAndFormatTransportParameters_PreservesInitialFlowControlLimits()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 16,
            InitialMaxStreamDataBidiLocal = 8,
            InitialMaxStreamDataBidiRemote = 10,
            InitialMaxStreamDataUni = 12,
        };

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsedParameters));

        Assert.Equal(16UL, parsedParameters.InitialMaxData);
        Assert.Equal(8UL, parsedParameters.InitialMaxStreamDataBidiLocal);
        Assert.Equal(10UL, parsedParameters.InitialMaxStreamDataBidiRemote);
        Assert.Equal(12UL, parsedParameters.InitialMaxStreamDataUni);
    }
}

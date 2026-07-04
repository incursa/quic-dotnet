// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-3-P2-S2-R01")]
public sealed class RFC9000_S7_3_P2_S2_R01
{
    [Fact]
    [Requirement("RFC9000-S7-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsOriginalDestinationConnectionIdFromServer()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);

        Assert.Equal(parameters.OriginalDestinationConnectionId, parsed.OriginalDestinationConnectionId);
    }

    [Fact]
    [Requirement("RFC9000-S7-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatTransportParameters_RejectsOriginalDestinationConnectionIdFromClient()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
        };

        Span<byte> destination = stackalloc byte[64];
        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    [Requirement("RFC9000-S7-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatTransportParameters_RoundTripsMaximumLengthOriginalDestinationConnectionId()
    {
        byte[] connectionId = Enumerable.Range(0, 20).Select(value => (byte)value).ToArray();
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = connectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);

        Assert.Equal(connectionId, parsed.OriginalDestinationConnectionId);
    }
}

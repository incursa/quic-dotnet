// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S5-1-1-P4-S2-R01">Endpoints MUST advertise the number of active connection IDs they are willing to maintain using the active_connection_id_limit transport parameter.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S5-1-1-P4-S2-R01")]
public sealed class RFC9000_S5_1_1_P4_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatTransportParameters_DoesNotEmitActiveConnectionIdLimitWhenUnset()
    {
        QuicTransportParameters parameters = new()
        {
            InitialSourceConnectionId = [0xA0, 0xA1],
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, [0xA0, 0xA1]));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.Null(parsed.ActiveConnectionIdLimit);
        Assert.True(new byte[] { 0xA0, 0xA1 }.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsActiveConnectionIdLimitForClients()
    {
        QuicTransportParameters parameters = new()
        {
            ActiveConnectionIdLimit = 8,
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.Equal(8UL, parsed.ActiveConnectionIdLimit);
        Assert.Null(parsed.InitialSourceConnectionId);
        Assert.Null(parsed.PreferredAddress);
    }
}

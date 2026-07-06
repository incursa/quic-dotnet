// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S5-1-P9-S1-R01">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S5-1-P9-S1-R01")]
public sealed class RFC9000_S5_1_P9_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S5-1-P9-S1-R01">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S5-1-P9-S1-R01")]
    public void TryFormatTransportParameters_AdvertisesActiveConnectionIdLimit()
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
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S5-1-P9-S1-R01">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S5-1-P9-S1-R01")]
    public void TryParseTransportParameters_RejectsActiveConnectionIdLimitBelowTwo()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x0E,
            QuicVarintTestData.EncodeMinimal(1));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S5-1-P9-S1-R01">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S5-1-P9-S1-R01")]
    public void TryParseTransportParameters_AcceptsMinimumActiveConnectionIdLimit()
    {
        QuicTransportParameters parameters = new()
        {
            ActiveConnectionIdLimit = 2,
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

        Assert.Equal(2UL, parsed.ActiveConnectionIdLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S5-1-P9-S1-R01">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S5-1-P9-S1-R01")]
    public void TryFormatAndParseTransportParametersFuzz_RoundTripsActiveConnectionIdSupply()
    {
        ulong[] activeConnectionIdLimits = [2, 3, 4, 8, 16, 32];
        Span<byte> destination = stackalloc byte[32];

        foreach (ulong activeConnectionIdLimit in activeConnectionIdLimits)
        {
            QuicTransportParameters parameters = new()
            {
                ActiveConnectionIdLimit = activeConnectionIdLimit,
            };

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Client,
                destination,
                out int bytesWritten));

            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                destination[..bytesWritten],
                QuicTransportParameterRole.Server,
                out QuicTransportParameters parsed));

            Assert.Equal(activeConnectionIdLimit, parsed.ActiveConnectionIdLimit);
        }
    }
}

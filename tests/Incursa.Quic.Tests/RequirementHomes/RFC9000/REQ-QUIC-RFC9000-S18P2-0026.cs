// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0026")]
public sealed class REQ_QUIC_RFC9000_S18P2_0026
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_AcceptsNonZeroPreferredAddressConnectionId()
    {
        byte[] encoded = QuicPreferredAddressRequirementTestSupport.FormatAsServer(
            QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters());

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredConnectionId, parsed.PreferredAddress!.ConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsZeroLengthPreferredAddressConnectionId()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address,
            ipv4Port: 443,
            ipv6Address: QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            ipv6Port: 8443,
            connectionId: [],
            statelessResetToken: QuicPreferredAddressRequirementTestSupport.StatelessResetToken);
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0F,
                QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatTransportParameters_RejectsZeroLengthPreferredAddressConnectionId()
    {
        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters(preferredConnectionId: []),
            QuicTransportParameterRole.Server,
            stackalloc byte[128],
            out _));
    }
}

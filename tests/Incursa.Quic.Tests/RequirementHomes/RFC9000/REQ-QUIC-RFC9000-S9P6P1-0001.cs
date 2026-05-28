// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P1-0001")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerPreferredAddressCanCommunicateBothAddressFamilies()
    {
        QuicTransportParameters parameters = QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters();
        byte[] encoded = QuicPreferredAddressRequirementTestSupport.FormatAsServer(parameters);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address, parsed.PreferredAddress!.IPv4Address);
        Assert.Equal(443, parsed.PreferredAddress.IPv4Port);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address, parsed.PreferredAddress.IPv6Address);
        Assert.Equal(8443, parsed.PreferredAddress.IPv6Port);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredConnectionId, parsed.PreferredAddress.ConnectionId);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.StatelessResetToken, parsed.PreferredAddress.StatelessResetToken);
    }
}

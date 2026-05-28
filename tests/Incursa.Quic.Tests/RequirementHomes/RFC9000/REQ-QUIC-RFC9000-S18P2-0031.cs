// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0031")]
public sealed class REQ_QUIC_RFC9000_S18P2_0031
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_WritesTwoBytePreferredAddressIpv6PortField()
    {
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(preferredIpv6Port: 8443));

        Assert.Equal(2, QuicPreferredAddressRequirementTestSupport.PortLength);
        Assert.Equal(new byte[] { 0x20, 0xFB }, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv6PortOffset,
            QuicPreferredAddressRequirementTestSupport.PortLength).ToArray());

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            value,
            out QuicTransportParameters parsed));
        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal((ushort)8443, parsed.PreferredAddress!.IPv6Port);
    }
}

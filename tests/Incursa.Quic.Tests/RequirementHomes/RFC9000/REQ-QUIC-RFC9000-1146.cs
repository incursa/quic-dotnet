// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1146")]
public sealed class REQ_QUIC_RFC9000_1146
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_WritesPreferredAddressIpBytesInNetworkByteOrder()
    {
        byte[] expectedIpv4Address = [192, 0, 2, 123];
        byte[] expectedIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x10, 0x00, 0x20, 0x00, 0x30, 0x00, 0x40, 0x00, 0x50, 0x00, 0x7B];
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredIpv4Address: expectedIpv4Address,
            preferredIpv6Address: expectedIpv6Address);

        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);

        Assert.Equal(expectedIpv4Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv4AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv4AddressLength).ToArray());
        Assert.Equal(expectedIpv6Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv6AddressLength).ToArray());

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            value,
            out QuicTransportParameters parsed));
        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(expectedIpv4Address, parsed.PreferredAddress!.IPv4Address);
        Assert.Equal(expectedIpv6Address, parsed.PreferredAddress.IPv6Address);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatTransportParameters_DoesNotWritePreferredAddressIpBytesInReverseByteOrder()
    {
        byte[] expectedIpv4Address = [192, 0, 2, 123];
        byte[] expectedIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x10, 0x00, 0x20, 0x00, 0x30, 0x00, 0x40, 0x00, 0x50, 0x00, 0x7B];
        byte[] reversedIpv4Address = [.. expectedIpv4Address.Reverse()];
        byte[] reversedIpv6Address = [.. expectedIpv6Address.Reverse()];
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredIpv4Address: expectedIpv4Address,
            preferredIpv6Address: expectedIpv6Address);

        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);

        Assert.NotEqual(reversedIpv4Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv4AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv4AddressLength).ToArray());
        Assert.NotEqual(reversedIpv6Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv6AddressLength).ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreferredAddressIpAddressBytesRemainInNetworkByteOrder()
    {
        for (int i = 0; i < 12; i++)
        {
            byte[] expectedIpv4Address = [198, 51, 100, (byte)(40 + i)];
            byte[] expectedIpv6Address =
            [
                0x20, 0x01, 0x0D, 0xB8,
                0x00, 0x10, 0x00, (byte)(0x20 + i),
                0x00, 0x30, 0x00, (byte)(0x40 + i),
                0x00, 0x50, 0x00, (byte)(0x60 + i),
            ];
            QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                preferredIpv4Address: expectedIpv4Address,
                preferredIpv6Address: expectedIpv6Address);

            byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);

            Assert.Equal(expectedIpv4Address, value.AsSpan(
                QuicPreferredAddressRequirementTestSupport.IPv4AddressOffset,
                QuicPreferredAddressRequirementTestSupport.IPv4AddressLength).ToArray());
            Assert.Equal(expectedIpv6Address, value.AsSpan(
                QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset,
                QuicPreferredAddressRequirementTestSupport.IPv6AddressLength).ToArray());
        }
    }
}

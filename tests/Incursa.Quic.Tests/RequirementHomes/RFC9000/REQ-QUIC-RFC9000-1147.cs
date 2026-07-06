// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1147")]
public sealed class REQ_QUIC_RFC9000_1147
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_ContainsIpv4AndIpv6AddressAndPortFields()
    {
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress());

        Assert.Equal(QuicPreferredAddressRequirementTestSupport.IPv4AddressLength, QuicPreferredAddressRequirementTestSupport.IPv4PortOffset);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.IPv6AddressLength, QuicPreferredAddressRequirementTestSupport.IPv6PortOffset - QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.ConnectionIdLengthOffset, QuicPreferredAddressRequirementTestSupport.IPv6PortOffset + QuicPreferredAddressRequirementTestSupport.PortLength);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv4AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv4AddressLength).ToArray());
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv6AddressLength).ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsTruncatedPreferredAddressValue()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: [192, 0, 2, 1],
            ipv4Port: 443,
            ipv6Address: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
            ipv6Port: 8443,
            connectionId: [0xAA, 0xBB],
            statelessResetToken: Enumerable.Range(0, 16).Select(value => (byte)(0x70 + value)).ToArray());

        byte[] truncated = preferredAddressValue[..^1];

        Assert.False(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            truncated,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreferredAddressRequiresCompleteIpv4AndIpv6AddressPortFields()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: [192, 0, 2, 1],
            ipv4Port: 443,
            ipv6Address: QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            ipv6Port: 8443,
            connectionId: QuicPreferredAddressRequirementTestSupport.PreferredConnectionId,
            statelessResetToken: QuicPreferredAddressRequirementTestSupport.StatelessResetToken);

        foreach (int truncatedLength in TruncatedFieldLengths(preferredAddressValue.Length))
        {
            Assert.False(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
                preferredAddressValue[..truncatedLength],
                out _));
        }

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            preferredAddressValue,
            out QuicTransportParameters parsed));
        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address, parsed.PreferredAddress!.IPv4Address);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address, parsed.PreferredAddress.IPv6Address);
    }

    private static IEnumerable<int> TruncatedFieldLengths(int fullLength)
    {
        yield return QuicPreferredAddressRequirementTestSupport.IPv4AddressLength - 1;
        yield return QuicPreferredAddressRequirementTestSupport.IPv4PortOffset + QuicPreferredAddressRequirementTestSupport.PortLength - 1;
        yield return QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset + QuicPreferredAddressRequirementTestSupport.IPv6AddressLength - 1;
        yield return QuicPreferredAddressRequirementTestSupport.IPv6PortOffset + QuicPreferredAddressRequirementTestSupport.PortLength - 1;
        yield return fullLength - 1;
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1145">Servers MAY choose to only send a preferred address of one address family by sending an all-zero address and port (0.0.0.0:0 or [::]:0) for the other family.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1145")]
public sealed class REQ_QUIC_RFC9000_1145
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_AcceptsPreferredAddressWithZeroedIpv4Family()
    {
        byte[] expectedIpv4Address = [0, 0, 0, 0];
        byte[] expectedIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06];
        byte[] expectedConnectionId = [0xAA, 0xBB];
        byte[] expectedResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x90 + value)).ToArray();

        QuicTransportParameters parameters = new()
        {
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = expectedIpv4Address,
                IPv4Port = 0,
                IPv6Address = expectedIpv6Address,
                IPv6Port = 8443,
                ConnectionId = expectedConnectionId,
                StatelessResetToken = expectedResetToken,
            },
        };

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        QuicPreferredAddress preferredAddress = parsed.PreferredAddress!;
        Assert.Equal(expectedIpv4Address, preferredAddress.IPv4Address);
        Assert.Equal((ushort)0, preferredAddress.IPv4Port);
        Assert.Equal(expectedIpv6Address, preferredAddress.IPv6Address);
        Assert.Equal((ushort)8443, preferredAddress.IPv6Port);
        Assert.Equal(expectedConnectionId, preferredAddress.ConnectionId);
        Assert.Equal(expectedResetToken, preferredAddress.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsPreferredAddressThatOmitsTheUnusedAddressFamily()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: [0, 0, 0, 0],
            ipv4Port: 0,
            ipv6Address: QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            ipv6Port: 8443,
            connectionId: QuicPreferredAddressRequirementTestSupport.PreferredConnectionId,
            statelessResetToken: QuicPreferredAddressRequirementTestSupport.StatelessResetToken);
        byte[] valueThatOmitsTheZeroedIpv4Family =
            preferredAddressValue[(QuicPreferredAddressRequirementTestSupport.IPv4PortOffset + QuicPreferredAddressRequirementTestSupport.PortLength)..];

        Assert.False(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            valueThatOmitsTheZeroedIpv4Family,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreferredAddressAcceptsEitherAddressFamilyWithTheOtherFamilyZeroed()
    {
        foreach (QuicPreferredAddress preferredAddress in OneFamilyPreferredAddresses())
        {
            byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);

            Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
                value,
                out QuicTransportParameters parsed));

            Assert.NotNull(parsed.PreferredAddress);
            Assert.Equal(preferredAddress.IPv4Address, parsed.PreferredAddress!.IPv4Address);
            Assert.Equal(preferredAddress.IPv4Port, parsed.PreferredAddress.IPv4Port);
            Assert.Equal(preferredAddress.IPv6Address, parsed.PreferredAddress.IPv6Address);
            Assert.Equal(preferredAddress.IPv6Port, parsed.PreferredAddress.IPv6Port);
        }
    }

    private static IEnumerable<QuicPreferredAddress> OneFamilyPreferredAddresses()
    {
        yield return QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredIpv4Address: [0, 0, 0, 0],
            preferredIpv4Port: 0,
            preferredIpv6Address: QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            preferredIpv6Port: 8443);
        yield return QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredIpv4Address: QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address,
            preferredIpv4Port: 443,
            preferredIpv6Address: new byte[QuicPreferredAddressRequirementTestSupport.IPv6AddressLength],
            preferredIpv6Port: 0);
    }
}

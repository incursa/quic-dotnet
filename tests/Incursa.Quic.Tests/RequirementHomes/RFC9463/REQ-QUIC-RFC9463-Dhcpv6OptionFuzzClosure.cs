// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9463_Dhcpv6OptionFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionV6DnrFieldsStayInWireOrder()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption(priority: 7);
        byte[] encoded = option.Encode();
        int addressLengthOffset = 8 + option.AuthenticationDomainNameLength;

        Assert.Equal(option.OptionCode, BinaryPrimitives.ReadUInt16BigEndian(encoded));
        Assert.Equal(option.OptionLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(2)));
        Assert.Equal(7, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(4)));
        Assert.Equal(option.AuthenticationDomainNameLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6)));
        Assert.Equal(option.AddressLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(addressLengthOffset)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0022")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionV6DnrUsesCode144()
    {
        byte[] encoded = CreatePopulatedOption().Encode();

        Assert.Equal(144, BinaryPrimitives.ReadUInt16BigEndian(encoded));
        Assert.Equal(EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr, BinaryPrimitives.ReadUInt16BigEndian(encoded));

        encoded[1] = 0;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0023")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionLengthCoversEnclosedDataOctets()
    {
        byte[] encoded = CreatePopulatedOption().Encode();

        Assert.Equal(encoded.Length - 4, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(2)));

        encoded[3]++;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0024")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlyOptionLengthIsAdnLengthPlusFour()
    {
        EncryptedDnsDiscoveryDhcpv6Option option =
            EncryptedDnsDiscoveryDhcpv6Option.CreateAdnOnly("resolver.example", servicePriority: 9);

        Assert.True(option.UsesAdnOnlyMode);
        Assert.Equal(option.AuthenticationDomainNameLength + 4, option.OptionLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0025")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServicePriorityIsSixteenBitAndSortsInstances()
    {
        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded = DecodeTwoOptions();

        Assert.Equal(10, decoded[0].ServicePriority);
        Assert.Equal(20, decoded[1].ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0026")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnLengthMatchesAuthenticationNameOctets()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();
        byte[] encoded = option.Encode();

        Assert.Equal(option.AuthenticationDomainNameWire.Length, option.AuthenticationDomainNameLength);
        Assert.Equal(option.AuthenticationDomainNameLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0027")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AuthenticationDomainNameIsResolverFqdn()
    {
        EncryptedDnsDiscoveryDhcpv6Option decoded =
            EncryptedDnsDiscoveryDhcpv6Option.Decode(CreatePopulatedOption().Encode());

        Assert.Equal("resolver.example.", decoded.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0028")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AuthenticationDomainNameUsesRfc8415WireFormat()
    {
        EncryptedDnsDiscoveryDhcpv6Option decoded =
            EncryptedDnsDiscoveryDhcpv6Option.Decode(CreatePopulatedOption().Encode());

        Assert.Equal(
            [8, (byte)'r', (byte)'e', (byte)'s', (byte)'o', (byte)'l', (byte)'v', (byte)'e', (byte)'r', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0],
            decoded.AuthenticationDomainNameWire.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0029")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressLengthCoversIpv6AddressOctets()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption(address: IPAddress.Parse("2001:db8::53"));

        Assert.Equal(16, option.AddressLength);
        Assert.Equal(option.Addresses.Count * 16, option.AddressLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0030")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressLengthMustBeMultipleOfSixteen()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        int addressLengthOffset = 8 + BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(addressLengthOffset), 15);

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0031")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv6AddressesCarryResolverAddress()
    {
        IPAddress address = IPAddress.Parse("2001:db8::53");
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption(address: address);

        Assert.Equal([address], option.Addresses);
        Assert.True(ContainsSubsequence(option.Encode(), address.GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0032")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv6AddressFieldUsesVariableAddressLengthLayout()
    {
        EncryptedDnsDiscoveryDhcpv6Option oneAddress = CreatePopulatedOption(address: IPAddress.Parse("2001:db8::53"));
        EncryptedDnsDiscoveryDhcpv6Option twoAddresses = EncryptedDnsDiscoveryDhcpv6Option.Create(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53"), IPAddress.Parse("2001:db8::54")],
            serviceParameters: [CreateAlpnParameter()]);

        Assert.Equal(16, oneAddress.AddressLength);
        Assert.Equal(32, twoAddresses.AddressLength);
        Assert.True(twoAddresses.OptionLength > oneAddress.OptionLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0033")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsAreVariableLengthRfc9460EncodedSet()
    {
        EncryptedDnsDiscoveryDhcpv6Option alpnOnly = CreatePopulatedOption();
        EncryptedDnsDiscoveryDhcpv6Option withPort = EncryptedDnsDiscoveryDhcpv6Option.Create(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            serviceParameters: [CreateAlpnParameter(), EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]);

        Assert.True(withPort.ServiceParametersLength > alpnOnly.ServiceParametersLength);
        Assert.True(ContainsSubsequence(alpnOnly.Encode(), [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3']));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0034")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsIncludeAlpn()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();

        Assert.Contains(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryDhcpv6Option.Create(
                "resolver.example",
                [IPAddress.Parse("2001:db8::53")],
                serviceParameters: [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0035")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsOmitAddressHints()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();

        Assert.DoesNotContain(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv4HintKey);
        Assert.DoesNotContain(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv6HintKey);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv4HintKey, []));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv6HintKey, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0036")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DefaultPortsFollowEncryptedDnsAlpnWhenPortIsAbsent()
    {
        foreach ((string alpn, int expectedPort) in new[] { ("dot", 853), ("doq", 853), ("h2", 443), ("h3", 443) })
        {
            Assert.Equal(expectedPort, EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn(alpn));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0037")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServiceParameterLengthMatchesOptionLengthFormula()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();

        Assert.Equal(
            option.OptionLength - 6 - option.AuthenticationDomainNameLength - option.AddressLength,
            option.ServiceParametersLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0038")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlyModeOmitsTrailingFields()
    {
        EncryptedDnsDiscoveryDhcpv6Option option =
            EncryptedDnsDiscoveryDhcpv6Option.CreateAdnOnly("resolver.example", servicePriority: 9);
        byte[] encoded = option.Encode();

        Assert.True(option.UsesAdnOnlyMode);
        Assert.Empty(option.Addresses);
        Assert.Empty(option.ServiceParameters);
        Assert.False(ContainsSubsequence(encoded, IPAddress.Parse("2001:db8::53").GetAddressBytes()));
    }

    [Fact]
    [Requirement("RFC9463-S4-2-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionRequestOptionRequestsOptionV6Dnr()
    {
        byte[] optionRequestData = EncryptedDnsDiscoveryDhcpv6Option.CreateOptionRequestOptionData();

        Assert.Equal([0x00, 0x90], optionRequestData);
        Assert.NotEqual([0x00, 0x00], optionRequestData);
        Assert.NotEqual([0x00, EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr], optionRequestData);
    }

    [Fact]
    [Requirement("RFC9463-S4-2-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Dhcpv6ClientReceivesMultipleOptionV6DnrInstances()
    {
        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded = DecodeTwoOptions();

        Assert.Equal(2, decoded.Count);
    }

    [Fact]
    [Requirement("RFC9463-S4-2-P2-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EachOptionV6DnrOptionIsSeparateResolver()
    {
        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded = DecodeTwoOptions();

        Assert.NotSame(decoded[0], decoded[1]);
        Assert.NotEqual(decoded[0].Addresses[0], decoded[1].Addresses[0]);
    }

    [Fact]
    [Requirement("RFC9463-S4-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionV6DnrInstancesAreSortedByServicePriority()
    {
        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded = DecodeTwoOptions();

        Assert.Collection(
            decoded,
            first => Assert.Equal(10, first.ServicePriority),
            second => Assert.Equal(20, second.ServicePriority));
    }

    [Fact]
    [Requirement("RFC9463-S4-2-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InvalidOptionV6DnrValuesAreSilentlyDiscarded()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.IPv6Loopback);
        byte[] multicast = CreateEncodedOptionWithRawAddress(IPAddress.Parse("ff02::fb"));
        byte[] valid = CreatePopulatedOption(address: IPAddress.Parse("2001:db8::53")).Encode();

        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded =
            EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. loopback, .. multicast, .. valid]);

        Assert.Single(decoded);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryDhcpv6Option.DecodeMany(loopback, silentlyDiscardInvalidOptions: false));
    }

    [Fact]
    [Requirement("RFC9463-S4-2-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MulticastAndLoopbackAddressesAreSilentlyDiscarded()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.IPv6Loopback);
        byte[] multicast = CreateEncodedOptionWithRawAddress(IPAddress.Parse("ff02::fb"));
        byte[] valid = CreatePopulatedOption(address: IPAddress.Parse("2001:db8::53")).Encode();

        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded =
            EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. loopback, .. multicast, .. valid]);

        EncryptedDnsDiscoveryDhcpv6Option option = Assert.Single(decoded);
        Assert.Equal([IPAddress.Parse("2001:db8::53")], option.Addresses);
    }

    private static IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> DecodeTwoOptions()
    {
        byte[] second = CreatePopulatedOption(priority: 20, address: IPAddress.Parse("2001:db8::54")).Encode();
        byte[] first = CreatePopulatedOption(priority: 10, address: IPAddress.Parse("2001:db8::53")).Encode();

        return EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. second, .. first]);
    }

    private static EncryptedDnsDiscoveryDhcpv6Option CreatePopulatedOption(
        ushort priority = 1,
        IPAddress? address = null)
    {
        return EncryptedDnsDiscoveryDhcpv6Option.Create(
            "resolver.example",
            [address ?? IPAddress.Parse("2001:db8::53")],
            priority,
            [CreateAlpnParameter()]);
    }

    private static EncryptedDnsProvisioningServiceParameter CreateAlpnParameter()
    {
        return EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'h', (byte)'3']);
    }

    private static byte[] CreateEncodedOptionWithRawAddress(IPAddress address)
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();
        byte[] encoded = option.Encode();
        int addressOffset = 10 + option.AuthenticationDomainNameLength;
        address.GetAddressBytes().CopyTo(encoded, addressOffset);
        return encoded;
    }

    private static bool ContainsSubsequence(ReadOnlySpan<byte> source, ReadOnlySpan<byte> candidate)
    {
        for (int offset = 0; offset <= source.Length - candidate.Length; offset++)
        {
            if (source.Slice(offset, candidate.Length).SequenceEqual(candidate))
            {
                return true;
            }
        }

        return false;
    }
}

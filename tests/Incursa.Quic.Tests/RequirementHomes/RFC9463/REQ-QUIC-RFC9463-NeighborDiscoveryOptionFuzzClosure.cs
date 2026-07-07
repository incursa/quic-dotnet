// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9463_NeighborDiscoveryOptionFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0077")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EncryptedDnsOptionFieldsStayInWireOrder()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption(priority: 7, lifetime: 900);
        byte[] encoded = option.Encode();
        int addressLengthOffset = 10 + option.AuthenticationDomainNameLength;
        int serviceParametersLengthOffset = addressLengthOffset + 2 + option.AddressLength;

        Assert.Equal(option.OptionType, encoded[0]);
        Assert.Equal(option.LengthUnits, encoded[1]);
        Assert.Equal(7, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(2)));
        Assert.Equal(900u, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
        Assert.Equal(option.AuthenticationDomainNameLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(8)));
        Assert.Equal(option.AddressLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(addressLengthOffset)));
        Assert.Equal(option.ServiceParametersLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(serviceParametersLengthOffset)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0078")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EncryptedDnsOptionUsesType144()
    {
        byte[] encoded = CreatePopulatedOption().Encode();

        Assert.Equal(144, encoded[0]);
        Assert.Equal(EncryptedDnsDiscoveryOptionCodes.NeighborDiscoveryEncryptedDnsOptionType, encoded[0]);

        encoded[0] = 0;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0079")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NeighborDiscoveryLengthFieldIsOneOctet()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();
        byte[] encoded = option.Encode();

        Assert.Equal(option.LengthUnits, encoded[1]);
        Assert.InRange(encoded[1], 1, byte.MaxValue);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0080")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NeighborDiscoveryLengthUsesEightOctetUnits()
    {
        byte[] encoded = CreatePopulatedOption().Encode();

        Assert.Equal(encoded.Length, encoded[1] * 8);

        encoded[1]++;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0081")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServicePriorityIsSixteenBitUnsignedInteger()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption decoded =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(CreatePopulatedOption(priority: ushort.MaxValue).Encode());

        Assert.Equal(ushort.MaxValue, decoded.ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0082")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServicePriorityDeterminesPreferenceOrder()
    {
        IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> decoded = DecodeTwoOptionsWithLoopback();

        Assert.Equal(10, decoded[0].ServicePriority);
        Assert.Equal(20, decoded[1].ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0083")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LifetimeIsThirtyTwoBitUnsignedInteger()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example", lifetime: uint.MaxValue);
        byte[] encoded = option.Encode();

        Assert.Equal(uint.MaxValue, option.Lifetime);
        Assert.Equal(uint.MaxValue, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0084")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LifetimeRepresentsRelativeValiditySeconds()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option =
            CreatePopulatedOption(lifetime: 600);

        Assert.Equal(600u, option.Lifetime);
        Assert.False(option.HasInfiniteLifetime);
        Assert.False(option.RetiresAuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0085")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DefaultLifetimeIsThreeTimesRouterAdvertisementInterval()
    {
        foreach ((uint interval, uint expectedLifetime) in new[] { (1u, 3u), (300u, 900u), (600u, 1800u) })
        {
            Assert.Equal(expectedLifetime, EncryptedDnsDiscoveryNeighborDiscoveryOption.GetDefaultLifetimeSeconds(interval));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0086")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AllOneBitsLifetimeRepresentsInfinity()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example");

        Assert.Equal(0xffffffff, option.Lifetime);
        Assert.True(option.HasInfiniteLifetime);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0087")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroLifetimeRetiresAuthenticationDomainName()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example", lifetime: 0);

        Assert.Equal(0u, option.Lifetime);
        Assert.True(option.RetiresAuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0088")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnLengthIsSixteenBitUnsignedInteger()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();
        byte[] encoded = option.Encode();

        Assert.Equal(option.AuthenticationDomainNameLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(8)));
        Assert.InRange(option.AuthenticationDomainNameLength, 1, ushort.MaxValue);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0089")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnLengthMatchesAuthenticationDomainNameOctets()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();

        Assert.Equal(option.AuthenticationDomainNameWire.Length, option.AuthenticationDomainNameLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0090")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AuthenticationDomainNameCarriesResolverAdn()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption decoded =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(CreatePopulatedOption().Encode());

        Assert.Equal("resolver.example.", decoded.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0091")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AuthenticationDomainNameUsesRfc8415WireFormat()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption decoded =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(CreatePopulatedOption().Encode());

        Assert.Equal(
            [8, (byte)'r', (byte)'e', (byte)'s', (byte)'o', (byte)'l', (byte)'v', (byte)'e', (byte)'r', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0],
            decoded.AuthenticationDomainNameWire.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0092")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressLengthIsSixteenBitUnsignedInteger()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();
        byte[] encoded = option.Encode();
        int addressLengthOffset = 10 + option.AuthenticationDomainNameLength;

        Assert.Equal(option.AddressLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(addressLengthOffset)));
        Assert.InRange(option.AddressLength, 1, ushort.MaxValue);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0093")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressLengthCoversIpv6AddressOctets()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption(address: IPAddress.Parse("2001:db8::53"));

        Assert.Equal(16, option.AddressLength);
        Assert.Equal(option.Addresses.Count * 16, option.AddressLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0094")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressLengthMustBeMultipleOfSixteen()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        int addressLengthOffset = 10 + BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(8));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(addressLengthOffset), 15);

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0095")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv6AddressesCarryResolverAddresses()
    {
        IPAddress address = IPAddress.Parse("2001:db8::53");
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption(address: address);

        Assert.Equal([address], option.Addresses);
        Assert.True(ContainsSubsequence(option.Encode(), address.GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0096")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AllAddressesShareOneLifetimeValue()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = EncryptedDnsDiscoveryNeighborDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53"), IPAddress.Parse("2001:db8::54")],
            lifetime: 600,
            serviceParameters: [CreateAlpnParameter()]);

        Assert.Equal(600u, option.Lifetime);
        Assert.Equal(2, option.Addresses.Count);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0097")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsLengthIsSixteenBitUnsignedInteger()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();

        Assert.InRange(option.ServiceParametersLength, 1, ushort.MaxValue);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0098")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsLengthCoversSvcParamOctets()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();
        byte[] encoded = option.Encode();
        int serviceParameterLengthOffset = 12 + option.AuthenticationDomainNameLength + option.AddressLength;

        Assert.Equal(option.ServiceParametersLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(serviceParameterLengthOffset)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0099")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsUseRfc9460KeyLengthValueEncoding()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        byte[] expectedAlpnParameter = [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3'];

        Assert.True(ContainsSubsequence(encoded, expectedAlpnParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0100")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsFieldIsVariableLength()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption alpnOnly = CreatePopulatedOption();
        EncryptedDnsDiscoveryNeighborDiscoveryOption withPort = EncryptedDnsDiscoveryNeighborDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            serviceParameters: [CreateAlpnParameter(), EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]);

        Assert.True(withPort.ServiceParametersLength > alpnOnly.ServiceParametersLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0101")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsIncludeAlpn()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();

        Assert.Contains(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryNeighborDiscoveryOption.Create(
                "resolver.example",
                [IPAddress.Parse("2001:db8::53")],
                serviceParameters: [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0102")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsExcludeAddressHints()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();

        Assert.DoesNotContain(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv4HintKey);
        Assert.DoesNotContain(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv6HintKey);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv6HintKey, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0103")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DefaultPortsFollowEncryptedDnsAlpnWhenPortIsAbsent()
    {
        foreach ((string alpn, int expectedPort) in new[] { ("dot", 853), ("doq", 853), ("h2", 443), ("h3", 443) })
        {
            Assert.Equal(expectedPort, EncryptedDnsDiscoveryNeighborDiscoveryOption.GetDefaultPortForAlpn(alpn));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0104")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlyModeOmitsTrailingFields()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example", servicePriority: 9);
        byte[] encoded = option.Encode();

        Assert.True(option.UsesAdnOnlyMode);
        Assert.Empty(option.Addresses);
        Assert.Empty(option.ServiceParameters);
        Assert.False(ContainsSubsequence(encoded, IPAddress.Parse("2001:db8::53").GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0105")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionIsZeroPaddedToEightOctets()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example", servicePriority: 9);
        byte[] encoded = option.Encode();

        Assert.Equal(0, option.EncodedLength % 8);
        Assert.True(option.PaddingLength > 0);
        Assert.All(encoded.AsSpan(^option.PaddingLength..).ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0106")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HostProcessesValidOptionsAndDiscardsInvalidOptions()
    {
        IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> decoded = DecodeTwoOptionsWithLoopback();

        Assert.Equal(2, decoded.Count);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryNeighborDiscoveryOption.DecodeMany(
                [CreateEncodedOptionWithRawAddress(IPAddress.IPv6Loopback)],
                silentlyDiscardInvalidOptions: false));
    }

    [Fact]
    [Requirement("RFC9463-S6-2-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HostReceivesMultipleEncryptedDnsRouterAdvertisementOptions()
    {
        IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> decoded = DecodeTwoOptionsWithLoopback();

        Assert.Equal(2, decoded.Count);
        Assert.NotSame(decoded[0], decoded[1]);
    }

    [Fact]
    [Requirement("RFC9463-S6-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MultipleRouterAdvertisementOptionsAreSortedByServicePriority()
    {
        IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> decoded = DecodeTwoOptionsWithLoopback();

        Assert.Collection(
            decoded,
            first => Assert.Equal(10, first.ServicePriority),
            second => Assert.Equal(20, second.ServicePriority));
    }

    private static IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> DecodeTwoOptionsWithLoopback()
    {
        byte[] second = CreatePopulatedOption(priority: 20, address: IPAddress.Parse("2001:db8::54")).Encode();
        byte[] first = CreatePopulatedOption(priority: 10, address: IPAddress.Parse("2001:db8::53")).Encode();
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.IPv6Loopback);

        return EncryptedDnsDiscoveryNeighborDiscoveryOption.DecodeMany([second, loopback, first]);
    }

    private static EncryptedDnsDiscoveryNeighborDiscoveryOption CreatePopulatedOption(
        ushort priority = 1,
        IPAddress? address = null,
        uint lifetime = 300)
    {
        return EncryptedDnsDiscoveryNeighborDiscoveryOption.Create(
            "resolver.example",
            [address ?? IPAddress.Parse("2001:db8::53")],
            priority,
            lifetime,
            [CreateAlpnParameter()]);
    }

    private static EncryptedDnsProvisioningServiceParameter CreateAlpnParameter()
    {
        return EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'h', (byte)'3']);
    }

    private static byte[] CreateEncodedOptionWithRawAddress(IPAddress address)
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();
        byte[] encoded = option.Encode();
        int addressOffset = 12 + option.AuthenticationDomainNameLength;
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

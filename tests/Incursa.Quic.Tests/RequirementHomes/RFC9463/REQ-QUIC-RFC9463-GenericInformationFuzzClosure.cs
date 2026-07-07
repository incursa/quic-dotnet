// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9463_GenericInformationFuzzClosure
{
    [Fact]
    [Requirement("RFC9463-S3-1-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EmbeddedRouterPublishesLanFacingAddress()
    {
        IPAddress lanAddress = IPAddress.Parse("192.168.1.1");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "router.example",
            [lanAddress],
            serviceParameterKeys: ["alpn"]);

        Assert.Equal([lanAddress], option.Addresses);
        Assert.True(EncryptedDnsDiscoveryOption.IsUsableResolverAddress(lanAddress));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MultipleResolverAddressesRetainPreferenceOrder()
    {
        IPAddress firstAddress = IPAddress.Parse("192.0.2.53");
        IPAddress secondAddress = IPAddress.Parse("192.0.2.54");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [firstAddress, secondAddress],
            servicePriority: 7);

        Assert.Equal([firstAddress, secondAddress], option.Addresses);
        Assert.Equal(7, option.ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DnrServiceParametersUseRfc9460WireEncoding()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreateDhcpv6Option();
        byte[] encoded = option.Encode();
        byte[] expectedAlpnParameter = [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3'];

        Assert.Equal(option.ServiceParametersLength, expectedAlpnParameter.Length);
        Assert.True(encoded.AsSpan(^expectedAlpnParameter.Length..).SequenceEqual(expectedAlpnParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlyProvisioningModeIsAvailableForAllOptionFamilies()
    {
        Assert.True(EncryptedDnsDiscoveryDhcpv6Option.CreateAdnOnly("resolver.example").UsesAdnOnlyMode);
        Assert.True(EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance.CreateAdnOnly("resolver.example").UsesAdnOnlyMode);
        Assert.True(EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example").UsesAdnOnlyMode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnIsPresentAndNormalizedAsFqdn()
    {
        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "Resolver.Example",
            [IPAddress.Parse("192.0.2.53")]);

        Assert.Equal("resolver.example.", option.AuthenticationDomainName);
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(null, [IPAddress.Parse("192.0.2.53")], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServiceParametersAreEncodedAccordingToRfc9460()
    {
        EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance instance = CreateDhcpv4Instance();
        byte[] encoded = instance.EncodeInstance();
        byte[] expectedAlpnParameter = [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3'];

        Assert.Equal(expectedAlpnParameter.Length, instance.ServiceParametersLength);
        Assert.True(encoded.AsSpan(^expectedAlpnParameter.Length..).SequenceEqual(expectedAlpnParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MultipleEncryptedDnsInstancesCarryServicePriority()
    {
        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded = DecodeTwoDhcpv6Options();

        Assert.Equal([10, 20], decoded.Select(static resolver => (int)resolver.ServicePriority).ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DnrInformationRequiresAdn()
    {
        Assert.True(EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            out EncryptedDnsDiscoveryOption? option));

        Assert.Equal("resolver.example.", option!.AuthenticationDomainName);
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(" ", [IPAddress.Parse("192.0.2.53")], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DnrInformationIncludesResolverAddresses()
    {
        IPAddress address = IPAddress.Parse("192.0.2.53");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create("resolver.example", [address]);

        Assert.Equal([address], option.Addresses);
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate("resolver.example", [], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DnrInformationIncludesServiceParameterSet()
    {
        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            serviceParameterKeys: ["alpn", "port"]);

        Assert.Equal(["alpn", "port"], option.ServiceParameterKeys);
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            out _,
            serviceParameterKeys: [" "]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0111")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Dhcpv6DnrIsRequestableInClientOro()
    {
        byte[] oroData = EncryptedDnsDiscoveryDhcpv6Option.CreateOptionRequestOptionData();

        Assert.Equal([0x00, 0x90], oroData);
        Assert.NotEqual([0x00, 0x00], oroData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0113")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Dhcpv6DnrIsNotSingleton()
    {
        byte[] first = CreateDhcpv6Option(priority: 10, address: IPAddress.Parse("2001:db8::53")).Encode();
        byte[] second = CreateDhcpv6Option(priority: 20, address: IPAddress.Parse("2001:db8::54")).Encode();

        Assert.False(EncryptedDnsDiscoveryDhcpv6Option.IsSingletonOption);
        Assert.Equal(2, EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. first, .. second]).Count);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0115")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Dhcpv4OptionDataLengthIsN()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = EncryptedDnsDiscoveryDhcpv4Option.Create([CreateDhcpv4Instance()]);
        byte[] encoded = option.Encode();

        Assert.Equal(option.OptionDataLength, encoded[1]);
        Assert.Equal(encoded.Length - 2, encoded[1]);

        encoded[1]++;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded));
    }

    private static IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> DecodeTwoDhcpv6Options()
    {
        byte[] second = CreateDhcpv6Option(priority: 20, address: IPAddress.Parse("2001:db8::54")).Encode();
        byte[] first = CreateDhcpv6Option(priority: 10, address: IPAddress.Parse("2001:db8::53")).Encode();

        return EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. second, .. first]);
    }

    private static EncryptedDnsDiscoveryDhcpv6Option CreateDhcpv6Option(
        ushort priority = 1,
        IPAddress? address = null)
    {
        return EncryptedDnsDiscoveryDhcpv6Option.Create(
            "resolver.example",
            [address ?? IPAddress.Parse("2001:db8::53")],
            priority,
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'h', (byte)'3'])]);
    }

    private static EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance CreateDhcpv4Instance()
    {
        return EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance.CreateInstance(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            serviceParameters: [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'h', (byte)'3'])]);
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsDiscoveryGenericInformationTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0002")]
    [Requirement("REQ-QUIC-RFC9463-0006")]
    [Requirement("REQ-QUIC-RFC9463-0012")]
    [Requirement("REQ-QUIC-RFC9463-0013")]
    [Requirement("REQ-QUIC-RFC9463-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiscoveryInformationCarriesAdnAddressAndServiceParameterSet()
    {
        IPAddress address = IPAddress.Parse("192.0.2.53");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [address],
            serviceParameterKeys: ["alpn", "port"]);

        Assert.Equal("resolver.example.", option.AuthenticationDomainName);
        Assert.Equal([address], option.Addresses);
        Assert.Equal(["alpn", "port"], option.ServiceParameterKeys);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0002")]
    [Requirement("REQ-QUIC-RFC9463-0006")]
    [Requirement("REQ-QUIC-RFC9463-0012")]
    [Requirement("REQ-QUIC-RFC9463-0013")]
    [Requirement("REQ-QUIC-RFC9463-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DiscoveryInformationRejectsMissingAdnAddressOrServiceParameterKey()
    {
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(
            null,
            [IPAddress.Parse("192.0.2.53")],
            out _));

        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [],
            out _));

        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            out _,
            serviceParameterKeys: [" "]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0003")]
    [Requirement("REQ-QUIC-RFC9463-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MultipleAddressesAndInstancesRetainPreferenceInformation()
    {
        IPAddress firstAddress = IPAddress.Parse("192.0.2.53");
        IPAddress secondAddress = IPAddress.Parse("192.0.2.54");
        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [firstAddress, secondAddress],
            servicePriority: 7);

        EncryptedDnsDiscoveryDhcpv6Option second = CreateDhcpv6Option(priority: 20, address: IPAddress.Parse("2001:db8::54"));
        EncryptedDnsDiscoveryDhcpv6Option first = CreateDhcpv6Option(priority: 10, address: IPAddress.Parse("2001:db8::53"));

        Assert.Equal([firstAddress, secondAddress], option.Addresses);
        Assert.Equal(7, option.ServicePriority);
        Assert.Equal(
            [10, 20],
            EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. second.Encode(), .. first.Encode()])
                .Select(static resolver => (int)resolver.ServicePriority)
                .ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0003")]
    [Requirement("REQ-QUIC-RFC9463-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidAddressesAreFilteredWithoutReorderingPreference()
    {
        IPAddress firstAddress = IPAddress.Parse("192.0.2.53");
        IPAddress secondAddress = IPAddress.Parse("192.0.2.54");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.Loopback, firstAddress, IPAddress.Parse("224.0.0.251"), secondAddress]);

        Assert.Equal([firstAddress, secondAddress], option.Addresses);
        Assert.Equal(0, option.ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0004")]
    [Requirement("REQ-QUIC-RFC9463-0007")]
    [Requirement("REQ-QUIC-RFC9463-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServiceParametersUseRfc9460WireEncoding()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreateDhcpv6Option();

        byte[] encoded = option.Encode();
        byte[] expectedAlpnParameter = [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3'];

        Assert.Equal(option.ServiceParametersLength, expectedAlpnParameter.Length);
        Assert.True(encoded.AsSpan(^expectedAlpnParameter.Length..).SequenceEqual(expectedAlpnParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0004")]
    [Requirement("REQ-QUIC-RFC9463-0007")]
    [Requirement("REQ-QUIC-RFC9463-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServiceParametersRejectForbiddenHintsAndMissingAlpn()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv6HintKey, []));

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryDhcpv6Option.Create(
                "resolver.example",
                [IPAddress.Parse("2001:db8::53")],
                serviceParameters: [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdnOnlyModeIsAvailableAcrossDnrOptionFamilies()
    {
        Assert.True(EncryptedDnsDiscoveryDhcpv6Option.CreateAdnOnly("resolver.example").UsesAdnOnlyMode);
        Assert.True(EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance.CreateAdnOnly("resolver.example").UsesAdnOnlyMode);
        Assert.True(EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example").UsesAdnOnlyMode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PopulatedModeCarriesAddressesWhenAdnOnlyModeIsNotUsed()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreateDhcpv6Option();

        Assert.False(option.UsesAdnOnlyMode);
        Assert.NotEmpty(option.Addresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0111")]
    [Requirement("REQ-QUIC-RFC9463-0113")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Dhcpv6DnrIsRequestableInOroAndNotSingleton()
    {
        Assert.Equal([0x00, 0x90], EncryptedDnsDiscoveryDhcpv6Option.CreateOptionRequestOptionData());
        Assert.False(EncryptedDnsDiscoveryDhcpv6Option.IsSingletonOption);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0111")]
    [Requirement("REQ-QUIC-RFC9463-0113")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Dhcpv6DnrOroDataDoesNotRequestUnknownOrSingletonOnlyOption()
    {
        byte[] oroData = EncryptedDnsDiscoveryDhcpv6Option.CreateOptionRequestOptionData();

        Assert.NotEqual([0x00, 0x00], oroData);
        Assert.NotEqual([0x00, EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr], oroData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0115")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Dhcpv4OptionLengthIsOptionDataLengthN()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = EncryptedDnsDiscoveryDhcpv4Option.Create([CreateDhcpv4Instance()]);

        byte[] encoded = option.Encode();

        Assert.Equal(option.OptionDataLength, encoded[1]);
        Assert.Equal(encoded.Length - 2, encoded[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0115")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Dhcpv4DecodeRejectsMismatchedOptionDataLength()
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreateDhcpv4Instance()]).Encode();
        encoded[1]++;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded));
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

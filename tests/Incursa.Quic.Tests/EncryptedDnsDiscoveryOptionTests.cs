// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsDiscoveryOptionTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0022")]
    [Requirement("REQ-QUIC-RFC9463-0112")]
    [Requirement("REQ-QUIC-RFC9463-0114")]
    [Requirement("REQ-QUIC-RFC9463-0116")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConstantsExposeAssignedEncryptedDnsOptionCodePoints()
    {
        Assert.Equal(144, EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr);
        Assert.Equal(162, EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr);
        Assert.Equal(144, EncryptedDnsDiscoveryOptionCodes.NeighborDiscoveryEncryptedDnsOptionType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0083")]
    [Requirement("REQ-QUIC-RFC9463-0086")]
    [Requirement("REQ-QUIC-RFC9463-0087")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LifetimeConstantsModelInfinityAndRetirement()
    {
        EncryptedDnsDiscoveryOption infinite = EncryptedDnsDiscoveryOption.Create(
            "Resolver.Example",
            [IPAddress.Parse("2001:db8::53")]);
        EncryptedDnsDiscoveryOption retiring = EncryptedDnsDiscoveryOption.Create(
            "resolver.example.",
            [IPAddress.Parse("2001:db8::54")],
            lifetime: EncryptedDnsDiscoveryOptionCodes.RetiringLifetime);

        Assert.Equal(uint.MaxValue, EncryptedDnsDiscoveryOptionCodes.InfiniteLifetime);
        Assert.True(infinite.HasInfiniteLifetime);
        Assert.False(infinite.RetiresAuthenticationDomainName);
        Assert.Equal(0U, EncryptedDnsDiscoveryOptionCodes.RetiringLifetime);
        Assert.False(retiring.HasInfiniteLifetime);
        Assert.True(retiring.RetiresAuthenticationDomainName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("192.0.2.53")]
    [InlineData("[2001:db8::53]")]
    [InlineData("resolver..example")]
    [Requirement("REQ-QUIC-RFC9463-0001")]
    [Requirement("REQ-QUIC-RFC9463-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreateRejectsMissingOrInvalidAuthenticationDomainName(string? authenticationDomainName)
    {
        bool created = EncryptedDnsDiscoveryOption.TryCreate(
            authenticationDomainName,
            [IPAddress.Parse("2001:db8::53")],
            out EncryptedDnsDiscoveryOption? option);

        Assert.False(created);
        Assert.Null(option);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreateNormalizesAuthenticationDomainNameToAbsoluteName()
    {
        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "Resolver.Example",
            [IPAddress.Parse("2001:db8::53")]);

        Assert.Equal("resolver.example.", option.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0008")]
    [Requirement("REQ-QUIC-RFC9463-0010")]
    [Requirement("REQ-QUIC-RFC9463-0109")]
    [Requirement("REQ-QUIC-RFC9463-0110")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreateRejectsOptionWhenNoUsableResolverAddressRemains()
    {
        bool created = EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [
                IPAddress.Loopback,
                IPAddress.IPv6Loopback,
                IPAddress.Parse("224.0.0.251"),
                IPAddress.Parse("ff02::fb"),
            ],
            out EncryptedDnsDiscoveryOption? option);

        Assert.False(created);
        Assert.Null(option);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0008")]
    [Requirement("REQ-QUIC-RFC9463-0109")]
    [Requirement("REQ-QUIC-RFC9463-0110")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreateSilentlyFiltersLoopbackAndMulticastAddresses()
    {
        IPAddress usable = IPAddress.Parse("2001:db8::53");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [
                IPAddress.IPv6Loopback,
                IPAddress.Parse("ff02::fb"),
                usable,
            ]);

        Assert.Equal([usable], option.Addresses);
    }

    [Theory]
    [InlineData("ipv4hint")]
    [InlineData("ipv6hint")]
    [InlineData("IPv4Hint")]
    [InlineData(" IPV6HINT ")]
    [Requirement("REQ-QUIC-RFC9463-0009")]
    [Requirement("REQ-QUIC-RFC9463-0010")]
    [Requirement("REQ-QUIC-RFC9463-0102")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreateRejectsForbiddenAddressHintServiceParameters(string serviceParameterKey)
    {
        bool created = EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            out EncryptedDnsDiscoveryOption? option,
            serviceParameterKeys: [serviceParameterKey]);

        Assert.False(created);
        Assert.Null(option);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0025")]
    [Requirement("REQ-QUIC-RFC9463-0102")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreatePreservesServicePriorityAndNonHintServiceParameterKeys()
    {
        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            servicePriority: ushort.MaxValue,
            serviceParameterKeys: ["alpn", "port"]);

        Assert.Equal(ushort.MaxValue, option.ServicePriority);
        Assert.Equal(["alpn", "port"], option.ServiceParameterKeys);
    }
}

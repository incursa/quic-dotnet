// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9463_SharedOptionFuzzClosure
{
    [Fact]
    [Requirement("RFC9463-S3-1-1-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EncryptedDnsOptionsAlwaysRequireAdn()
    {
        Assert.True(EncryptedDnsDiscoveryOption.TryCreate(
            "Resolver.Example",
            [IPAddress.Parse("2001:db8::53")],
            out EncryptedDnsDiscoveryOption? option));

        Assert.Equal("resolver.example.", option!.AuthenticationDomainName);
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(null, [IPAddress.Parse("2001:db8::53")], out _));
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate("192.0.2.53", [IPAddress.Parse("2001:db8::53")], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EncryptedDnsOptionRequiresAtLeastOneUsableIpAddress()
    {
        IPAddress usable = IPAddress.Parse("2001:db8::53");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.IPv6Loopback, IPAddress.Parse("ff02::fb"), usable]);

        Assert.Equal([usable], option.Addresses);
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate("resolver.example", [IPAddress.IPv6Loopback], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServiceParametersExcludeAddressHints()
    {
        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            serviceParameterKeys: ["alpn", "port"]);

        Assert.Equal(["alpn", "port"], option.ServiceParameterKeys);
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            out _,
            serviceParameterKeys: ["ipv4hint"]));
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            out _,
            serviceParameterKeys: [" IPV6HINT "]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ValidationFailuresDiscardEncryptedDnsOption()
    {
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate("", [IPAddress.Parse("2001:db8::53")], out _));
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate("resolver.example", [], out _));
        Assert.False(EncryptedDnsDiscoveryOption.TryCreate(
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            out _,
            serviceParameterKeys: ["ipv6hint"]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0109")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HostLoopbackAddressesAreSilentlyDiscarded()
    {
        IPAddress usable = IPAddress.Parse("2001:db8::53");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.Loopback, IPAddress.IPv6Loopback, usable]);

        Assert.Equal([usable], option.Addresses);
        Assert.False(EncryptedDnsDiscoveryOption.IsUsableResolverAddress(IPAddress.Loopback));
        Assert.False(EncryptedDnsDiscoveryOption.IsUsableResolverAddress(IPAddress.IPv6Loopback));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0110")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MulticastAddressesAreSilentlyDiscarded()
    {
        IPAddress usable = IPAddress.Parse("2001:db8::53");

        EncryptedDnsDiscoveryOption option = EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [IPAddress.Parse("224.0.0.251"), IPAddress.Parse("ff02::fb"), usable]);

        Assert.Equal([usable], option.Addresses);
        Assert.False(EncryptedDnsDiscoveryOption.IsUsableResolverAddress(IPAddress.Parse("224.0.0.251")));
        Assert.False(EncryptedDnsDiscoveryOption.IsUsableResolverAddress(IPAddress.Parse("ff02::fb")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0112")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Dhcpv6OptionV6DnrCodeIs144()
    {
        Assert.Equal(144, EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr);
        Assert.Equal([0x00, 0x90], EncryptedDnsDiscoveryDhcpv6Option.CreateOptionRequestOptionData());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0114")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Dhcpv4OptionV4DnrTagIs162()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = EncryptedDnsDiscoveryDhcpv4Option.Create(
            [EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance.CreateAdnOnly("resolver.example")]);

        Assert.Equal(162, EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr);
        Assert.Equal(EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr, option.Encode()[0]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0116")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NeighborDiscoveryEncryptedDnsOptionTypeIs144()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example");

        Assert.Equal(144, EncryptedDnsDiscoveryOptionCodes.NeighborDiscoveryEncryptedDnsOptionType);
        Assert.Equal(EncryptedDnsDiscoveryOptionCodes.NeighborDiscoveryEncryptedDnsOptionType, option.Encode()[0]);
    }
}

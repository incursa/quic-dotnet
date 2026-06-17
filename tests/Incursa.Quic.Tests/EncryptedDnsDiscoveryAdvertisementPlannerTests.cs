// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsDiscoveryAdvertisementPlannerTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0120")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MixedLanAddressesCreateDhcpAndRouterAdvertisementPayloads()
    {
        EncryptedDnsDiscoveryAdvertisementPlan plan = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53"), IPAddress.Parse("2001:db8::53")],
            servicePriority: 10,
            lifetime: 1800);

        Assert.Equal(EncryptedDnsDiscoveryAdvertisementStatus.Ready, plan.Status);
        Assert.True(plan.RequiresPlatformAdvertisementAdapter);
        Assert.True(plan.PublishesDhcpv4);
        Assert.True(plan.PublishesDhcpv6);
        Assert.True(plan.PublishesRouterAdvertisements);
        Assert.False(plan.AdnOnly);

        EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance dhcpv4Instance =
            Assert.Single(plan.Dhcpv4Option!.Instances);
        Assert.Equal("resolver.example.", dhcpv4Instance.AuthenticationDomainName);
        Assert.Equal(10, dhcpv4Instance.ServicePriority);
        Assert.Contains(dhcpv4Instance.ServiceParameters, static parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey);

        EncryptedDnsDiscoveryDhcpv6Option dhcpv6 = Assert.Single(plan.Dhcpv6Options);
        Assert.Equal(IPAddress.Parse("2001:db8::53"), Assert.Single(dhcpv6.Addresses));

        EncryptedDnsDiscoveryNeighborDiscoveryOption routerAdvertisement = Assert.Single(plan.RouterAdvertisementOptions);
        Assert.Equal(1800u, routerAdvertisement.Lifetime);
        Assert.Equal(IPAddress.Parse("2001:db8::53"), Assert.Single(routerAdvertisement.Addresses));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0120")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdnOnlyPlanPublishesAllRequestedSurfacesWithoutAddresses()
    {
        EncryptedDnsDiscoveryAdvertisementPlan plan = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            lanFacingAddresses: null,
            adnOnly: true);

        Assert.Equal(EncryptedDnsDiscoveryAdvertisementStatus.Ready, plan.Status);
        Assert.True(plan.AdnOnly);
        Assert.True(Assert.Single(plan.Dhcpv4Option!.Instances).UsesAdnOnlyMode);
        Assert.True(Assert.Single(plan.Dhcpv6Options).UsesAdnOnlyMode);
        Assert.True(Assert.Single(plan.RouterAdvertisementOptions).UsesAdnOnlyMode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0120")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Ipv4OnlyPlanDoesNotInventIpv6Advertisements()
    {
        EncryptedDnsDiscoveryAdvertisementPlan plan = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")]);

        Assert.Equal(EncryptedDnsDiscoveryAdvertisementStatus.Ready, plan.Status);
        Assert.True(plan.PublishesDhcpv4);
        Assert.False(plan.PublishesDhcpv6);
        Assert.False(plan.PublishesRouterAdvertisements);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0120")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PopulatedPlanWithoutUsableAddressesIsNotInstallable()
    {
        EncryptedDnsDiscoveryAdvertisementPlan plan = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            [IPAddress.Loopback, IPAddress.IPv6Loopback]);

        Assert.Equal(EncryptedDnsDiscoveryAdvertisementStatus.NoUsableAddresses, plan.Status);
        Assert.False(plan.RequiresPlatformAdvertisementAdapter);
        Assert.Null(plan.Dhcpv4Option);
        Assert.Empty(plan.Dhcpv6Options);
        Assert.Empty(plan.RouterAdvertisementOptions);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0120")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DisabledAdvertisementSurfacesReturnPolicyBlockedPlan()
    {
        EncryptedDnsDiscoveryAdvertisementPlan plan = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53"), IPAddress.Parse("2001:db8::53")],
            publishDhcpv4: false,
            publishDhcpv6: false,
            publishRouterAdvertisements: false);

        Assert.Equal(EncryptedDnsDiscoveryAdvertisementStatus.BlockedByPolicy, plan.Status);
        Assert.False(plan.RequiresPlatformAdvertisementAdapter);
    }
}

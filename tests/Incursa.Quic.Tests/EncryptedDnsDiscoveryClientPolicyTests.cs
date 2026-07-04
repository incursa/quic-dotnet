// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsDiscoveryClientPolicyTests
{
    [Fact]
    [Requirement("RFC9463-S3-2-P1-S1-R01")]
    [Requirement("REQ-QUIC-RFC9463-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MixedRaAndDhcpDiscoveryKeepsDhcpFirstThenServicePriority()
    {
        IPAddress dhcpAddress = IPAddress.Parse("192.0.2.53");
        IPAddress lowerPriorityRaAddress = IPAddress.Parse("2001:db8::54");
        IPAddress higherPriorityRaAddress = IPAddress.Parse("2001:db8::53");

        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateOption(dhcpAddress, priority: 20)],
            routerAdvertisementOptions:
            [
                CreateOption(lowerPriorityRaAddress, priority: 20),
                CreateOption(higherPriorityRaAddress, priority: 10),
            ]);

        Assert.Equal(
            [dhcpAddress, higherPriorityRaAddress, lowerPriorityRaAddress],
            plan.EncryptedResolverEndpoints.Select(static endpoint => endpoint.Address).ToArray());
        Assert.Equal(EncryptedDnsDiscoverySource.Dhcp, plan.EncryptedResolverEndpoints[0].Source);
    }

    [Fact]
    [Requirement("RFC9463-S3-2-P1-S1-R01")]
    [Requirement("REQ-QUIC-RFC9463-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SingleSourceDiscoveryDoesNotInventOtherSourcePrecedence()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            routerAdvertisementOptions: [CreateOption(IPAddress.Parse("2001:db8::53"), priority: 10)]);

        EncryptedDnsDiscoveryResolverEndpoint endpoint = Assert.Single(plan.EncryptedResolverEndpoints);
        Assert.Equal(EncryptedDnsDiscoverySource.RouterAdvertisement, endpoint.Source);
        Assert.Equal(10, endpoint.ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncryptedDnsIsPreferredWhenDo53IsAlsoLearned()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")]);

        Assert.True(plan.UsesEncryptedDnsResolvers);
        Assert.NotEmpty(plan.Do53ResolverAddresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ExplicitConfigurationCanPreferDo53()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            explicitConfigurationPrefersDo53: true);

        Assert.False(plan.UsesEncryptedDnsResolvers);
        Assert.True(plan.ExplicitConfigurationPrefersDo53);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FailedEncryptedConnectionCanFallbackToDo53WhenAllowed()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            encryptedConnectionEstablished: false,
            allowDo53Fallback: true);

        Assert.True(plan.CanFallbackToDo53);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EstablishedEncryptedConnectionDoesNotFallbackToDo53()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            encryptedConnectionEstablished: true,
            allowDo53Fallback: true);

        Assert.False(plan.CanFallbackToDo53);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0019")]
    [Requirement("RFC9463-S3-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CertificateValidationRequiresPkixAndAdnMatchWithDefaultTrustAnchors()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateOption(IPAddress.Parse("192.0.2.53"))]);
        EncryptedDnsDiscoveryResolverEndpoint endpoint = Assert.Single(plan.EncryptedResolverEndpoints);

        EncryptedDnsDiscoveryCertificateValidationStatus status =
            EncryptedDnsDiscoveryClientPolicy.ValidateResolverCertificate(
                endpoint,
                pkixValidationSucceeded: true,
                authenticationDomainNameMatchesCertificate: true);

        Assert.Equal(EncryptedDnsDiscoveryCertificateValidationStatus.Validated, status);
        Assert.Equal(EncryptedDnsDiscoveryTrustAnchorMode.DefaultSystemOrApplication, plan.TrustAnchorMode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0019")]
    [Requirement("RFC9463-S3-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CertificateValidationFailsWithoutAdnMatchAndCanUseExplicitTrustAnchors()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateOption(IPAddress.Parse("192.0.2.53"))],
            useExplicitTrustAnchors: true);
        EncryptedDnsDiscoveryResolverEndpoint endpoint = Assert.Single(plan.EncryptedResolverEndpoints);

        EncryptedDnsDiscoveryCertificateValidationStatus status =
            EncryptedDnsDiscoveryClientPolicy.ValidateResolverCertificate(
                endpoint,
                pkixValidationSucceeded: true,
                authenticationDomainNameMatchesCertificate: false);

        Assert.Equal(EncryptedDnsDiscoveryCertificateValidationStatus.Failed, status);
        Assert.Equal(EncryptedDnsDiscoveryTrustAnchorMode.Explicit, plan.TrustAnchorMode);
    }

    private static EncryptedDnsDiscoveryOption CreateOption(IPAddress address, ushort priority = 1)
    {
        return EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [address],
            priority,
            serviceParameterKeys: ["alpn"]);
    }
}

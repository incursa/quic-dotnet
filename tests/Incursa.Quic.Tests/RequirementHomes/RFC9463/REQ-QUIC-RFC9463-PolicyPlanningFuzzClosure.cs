// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9463_PolicyPlanningFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EncryptedDnsResolversArePreferredOverDo53ByDefault()
    {
        EncryptedDnsDiscoveryClientPlan defaultPlan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")]);
        EncryptedDnsDiscoveryClientPlan explicitDo53Plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            explicitConfigurationPrefersDo53: true);

        Assert.True(defaultPlan.UsesEncryptedDnsResolvers);
        Assert.False(explicitDo53Plan.UsesEncryptedDnsResolvers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FailedEncryptedConnectionCanFallbackToDo53WhenAllowed()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            encryptedConnectionEstablished: false,
            allowDo53Fallback: true);

        Assert.True(plan.CanFallbackToDo53);

        EncryptedDnsDiscoveryClientPlan established = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            encryptedConnectionEstablished: true,
            allowDo53Fallback: true);

        Assert.False(established.CanFallbackToDo53);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientCreatesEncryptedSessionAttemptsInDiscoveryPriorityOrder()
    {
        IPAddress dhcpAddress = IPAddress.Parse("192.0.2.53");
        IPAddress raAddress = IPAddress.Parse("2001:db8::53");
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(dhcpAddress, priority: 30)],
            routerAdvertisementOptions: [CreateDiscoveryOption(raAddress, priority: 10)],
            encryptedConnectionEstablished: false,
            allowDo53Fallback: true);

        IReadOnlyList<EncryptedDnsSessionAttempt> attempts = EncryptedDnsSessionPlanner.CreateAttempts(plan);

        Assert.Equal([dhcpAddress, raAddress], attempts.Select(static attempt => attempt.Address).ToArray());
        Assert.All(attempts, static attempt =>
        {
            Assert.Equal(EncryptedDnsSessionAttemptSource.Discovery, attempt.Source);
            Assert.Equal(DnsServiceBindingProtocol.DnsOverQuic, attempt.Protocol);
            Assert.Equal(DoqDefaults.DefaultPort, attempt.Port);
            Assert.Contains("alpn", attempt.ServiceParameterKeys);
        });
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CertificateValidationRequiresPkixAndAdnMatch()
    {
        EncryptedDnsDiscoveryResolverEndpoint endpoint = Assert.Single(
            EncryptedDnsDiscoveryClientPolicy.CreatePlan(
                dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))])
                .EncryptedResolverEndpoints);

        Assert.Equal(
            EncryptedDnsDiscoveryCertificateValidationStatus.Validated,
            EncryptedDnsDiscoveryClientPolicy.ValidateResolverCertificate(
                endpoint,
                pkixValidationSucceeded: true,
                authenticationDomainNameMatchesCertificate: true));
        Assert.Equal(
            EncryptedDnsDiscoveryCertificateValidationStatus.Failed,
            EncryptedDnsDiscoveryClientPolicy.ValidateResolverCertificate(
                endpoint,
                pkixValidationSucceeded: true,
                authenticationDomainNameMatchesCertificate: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0117")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlySvcbParametersRequireSecureDnssecValidation()
    {
        Assert.Equal(
            EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus.Accepted,
            EncryptedDnsDiscoveryDnssecPolicy.EvaluateAdnOnlySvcbResolution(
                EncryptedDnsDiscoveryDnssecValidationStatus.Secure));

        foreach (EncryptedDnsDiscoveryDnssecValidationStatus status in new[]
        {
            EncryptedDnsDiscoveryDnssecValidationStatus.Insecure,
            EncryptedDnsDiscoveryDnssecValidationStatus.Bogus,
            EncryptedDnsDiscoveryDnssecValidationStatus.Indeterminate,
            EncryptedDnsDiscoveryDnssecValidationStatus.NotEvaluated,
        })
        {
            Assert.Equal(
                EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus.Rejected,
                EncryptedDnsDiscoveryDnssecPolicy.EvaluateAdnOnlySvcbResolution(status));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0118")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SessionPlannerProducesDeterministicAttemptsWithoutOpeningConnections()
    {
        EncryptedDnsSessionAttempt serviceBindingAttempt = EncryptedDnsSessionPlanner.CreateAttempt(CreateServiceBindingClientPlan());
        IReadOnlyList<EncryptedDnsSessionAttempt> discoveryAttempts = EncryptedDnsSessionPlanner.CreateAttempts(
            EncryptedDnsDiscoveryClientPolicy.CreatePlan(
                dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"), priority: 20)]));
        IReadOnlyList<EncryptedDnsSessionAttempt> provisioningAttempts = EncryptedDnsSessionPlanner.CreateAttempts(
            EncryptedDnsProvisioningClientPolicy.CreatePlan([CreateProvisioningReply(IPAddress.Parse("192.0.2.54"), priority: 30)]));

        Assert.Equal(EncryptedDnsSessionAttemptSource.ServiceBinding, serviceBindingAttempt.Source);
        Assert.Equal(DnsServiceBindingProtocol.DnsOverHttps3, serviceBindingAttempt.Protocol);
        Assert.Equal("/dns-query{?dns}", serviceBindingAttempt.DohPathTemplate);
        Assert.Equal(EncryptedDnsSessionAttemptSource.Discovery, Assert.Single(discoveryAttempts).Source);
        Assert.Equal(20, Assert.Single(discoveryAttempts).ServicePriority);
        Assert.Equal(EncryptedDnsSessionAttemptSource.Provisioning, Assert.Single(provisioningAttempts).Source);
        Assert.Equal(30, Assert.Single(provisioningAttempts).ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0119")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HostResolverPlannerProducesSideEffectFreeInstallationPlans()
    {
        EncryptedDnsHostResolverInstallationPlan serviceBindingPlan =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(CreateServiceBindingClientPlan());
        EncryptedDnsHostResolverInstallationPlan discoveryPlan =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(
                EncryptedDnsDiscoveryClientPolicy.CreatePlan(
                    dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
                    do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
                    encryptedConnectionEstablished: false,
                    allowDo53Fallback: true));
        EncryptedDnsHostResolverInstallationPlan provisioningPlan =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(
                EncryptedDnsProvisioningClientPolicy.CreatePlan(
                    [CreateProvisioningReply(IPAddress.Parse("192.0.2.54"))],
                    cleartextResolverAddresses: [IPAddress.Parse("198.51.100.54")],
                    internalDnsDomains: ["corp.example"],
                    splitTunnel: true));

        Assert.True(serviceBindingPlan.RequiresPlatformResolverAdapter);
        Assert.Equal(9443, Assert.Single(serviceBindingPlan.EncryptedSessionAttempts).Port);
        Assert.Equal(IPAddress.Parse("192.0.2.53"), Assert.Single(discoveryPlan.EncryptedSessionAttempts).Address);
        Assert.Equal(IPAddress.Parse("198.51.100.53"), Assert.Single(discoveryPlan.CleartextFallbackResolvers));
        Assert.True(provisioningPlan.AppliesToInternalDomainsOnly);
        Assert.Equal(["corp.example."], provisioningPlan.InternalDnsDomains);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0120")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdvertisementPlannerProducesAdapterNeutralPayloadPlan()
    {
        EncryptedDnsDiscoveryAdvertisementPlan plan = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53"), IPAddress.Parse("2001:db8::53")],
            servicePriority: 10,
            lifetime: 1800);
        EncryptedDnsDiscoveryAdvertisementPlan blocked = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            [IPAddress.Loopback],
            servicePriority: 10);

        Assert.Equal(EncryptedDnsDiscoveryAdvertisementStatus.Ready, plan.Status);
        Assert.True(plan.PublishesDhcpv4);
        Assert.True(plan.PublishesDhcpv6);
        Assert.True(plan.PublishesRouterAdvertisements);
        Assert.Equal(10, Assert.Single(plan.Dhcpv4Option!.Instances).ServicePriority);
        Assert.Equal(1800u, Assert.Single(plan.RouterAdvertisementOptions).Lifetime);
        Assert.Equal(EncryptedDnsDiscoveryAdvertisementStatus.NoUsableAddresses, blocked.Status);
        Assert.False(blocked.RequiresPlatformAdvertisementAdapter);
    }

    [Fact]
    [Requirement("RFC9463-S3-2-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MixedRaAndDhcpDiscoveryFollowsClientPrecedenceRules()
    {
        IPAddress dhcpAddress = IPAddress.Parse("192.0.2.53");
        IPAddress lowerPriorityRaAddress = IPAddress.Parse("2001:db8::54");
        IPAddress higherPriorityRaAddress = IPAddress.Parse("2001:db8::53");

        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(dhcpAddress, priority: 20)],
            routerAdvertisementOptions:
            [
                CreateDiscoveryOption(lowerPriorityRaAddress, priority: 20),
                CreateDiscoveryOption(higherPriorityRaAddress, priority: 10),
            ]);

        Assert.Equal(
            [dhcpAddress, higherPriorityRaAddress, lowerPriorityRaAddress],
            plan.EncryptedResolverEndpoints.Select(static endpoint => endpoint.Address).ToArray());
    }

    [Fact]
    [Requirement("RFC9463-S3-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientUsesDefaultTrustAnchorsUnlessExplicitlyConfigured()
    {
        EncryptedDnsDiscoveryClientPlan defaultPlan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))]);
        EncryptedDnsDiscoveryClientPlan explicitPlan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
            useExplicitTrustAnchors: true);

        Assert.Equal(EncryptedDnsDiscoveryTrustAnchorMode.DefaultSystemOrApplication, defaultPlan.TrustAnchorMode);
        Assert.Equal(EncryptedDnsDiscoveryTrustAnchorMode.Explicit, explicitPlan.TrustAnchorMode);
    }

    private static EncryptedDnsDiscoveryOption CreateDiscoveryOption(IPAddress address, ushort priority = 1)
    {
        return EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [address],
            priority,
            serviceParameterKeys: ["alpn"]);
    }

    private static DnsServiceBindingClientPlan CreateServiceBindingClientPlan()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            ["h3"],
            dohPathTemplate: "/dns-query{?dns}",
            port: 9443,
            httpsServiceParameters: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ech"] = "config",
            });
        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["h3"])));

        return DnsServiceBindingClientPolicy.CreatePlan(
            endpoint,
            dependentSpecificationAllowsCleartextFallback: true);
    }

    private static EncryptedDnsProvisioningAttribute CreateProvisioningReply(IPAddress address, ushort priority = 1)
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressListWithServiceParameters(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [address],
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'d', (byte)'o', (byte)'q'])],
            priority);
    }
}

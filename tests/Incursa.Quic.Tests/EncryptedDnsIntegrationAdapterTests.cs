// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsIntegrationAdapterTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0117")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DnssecPolicyConsumesDeterministicValidatorStatus()
    {
        FakeDnssecValidator validator = new(EncryptedDnsDiscoveryDnssecValidationStatus.Secure);

        EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus status =
            EncryptedDnsDiscoveryDnssecPolicy.EvaluateAdnOnlySvcbResolution("resolver.example", validator);

        Assert.Equal(EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus.Accepted, status);
        Assert.Equal("resolver.example", validator.AuthenticationDomainNames.Single());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0042")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PublicationExecutorPassesSignedRecordPlanToProviderAdapter()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            ["h3"],
            dohPathTemplate: "/dns-query{?dns}",
            port: 9443);
        DnsServiceBindingPublicationPlan plan = DnsServiceBindingPublicationPlan.Create(
            DnsServiceTransport.DnsOverHttps,
            record,
            "svc.resolver.example",
            DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: false));
        FakePublicationAdapter adapter = new();

        EncryptedDnsAdapterResult result = DnsServiceBindingPublicationExecutor.Publish(
            plan,
            adapter,
            requiresDnssecSigning: true);

        Assert.True(result.Applied);
        Assert.Equal(2, result.AppliedItemCount);
        DnsServiceBindingPublicationAdapterRequest request = Assert.Single(adapter.Requests);
        Assert.True(request.RequiresDnssecSigning);
        Assert.Equal(["SVCB", "HTTPS"], request.Plan.Records.Select(static item => item.ResourceRecordTypeName).ToArray());
        Assert.All(request.Plan.Records, static item => Assert.Contains("dohpath=", item.ToPresentationString(), StringComparison.Ordinal));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0077")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProvisioningTransportExecutorExchangesRequestThroughDeterministicFake()
    {
        EncryptedDnsProvisioningConfigurationPayload request =
            EncryptedDnsProvisioningExchangePlanner.CreateSupportRequest(
                digestHashAlgorithmIdentifiers: [EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier]);
        EncryptedDnsProvisioningAttribute replyAttribute = CreateIpv4Reply(IPAddress.Parse("192.0.2.53"));
        FakeProvisioningTransport transport = new(EncryptedDnsProvisioningExchangePlanner.CreateReply(
            request,
            EncryptedDnsProvisioningResponseOptions.Create([replyAttribute])));

        EncryptedDnsProvisioningConfigurationPayload reply =
            EncryptedDnsProvisioningTransportExecutor.Exchange(request, transport);
        EncryptedDnsProvisioningClientPlan clientPlan =
            EncryptedDnsProvisioningExchangePlanner.CreateClientPlan(reply);

        Assert.Same(request, Assert.Single(transport.Requests));
        Assert.Equal(EncryptedDnsProvisioningPayloadType.Reply, reply.PayloadType);
        Assert.Equal(IPAddress.Parse("192.0.2.53"), Assert.Single(clientPlan.EncryptedResolverEndpoints).Address);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0118")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SessionExecutorAttemptsPlannedEndpointsUntilConnectorSucceeds()
    {
        IPAddress firstAddress = IPAddress.Parse("192.0.2.53");
        IPAddress secondAddress = IPAddress.Parse("192.0.2.54");
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(firstAddress, priority: 10), CreateDiscoveryOption(secondAddress, priority: 20)]);
        IReadOnlyList<EncryptedDnsSessionAttempt> attempts = EncryptedDnsSessionPlanner.CreateAttempts(plan);
        FakeSessionConnector connector = new(successAddress: secondAddress);

        EncryptedDnsAdapterResult result = EncryptedDnsSessionExecutor.ConnectFirst(attempts, connector);

        Assert.True(result.Applied);
        Assert.Equal([firstAddress, secondAddress], connector.AttemptedAddresses);
        Assert.Equal(1, result.AppliedItemCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0119")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HostResolverExecutorAppliesReadyPlanThroughPlatformAdapter()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            cleartextResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            internalDnsDomains: ["corp.example"],
            splitTunnel: true);
        EncryptedDnsHostResolverInstallationPlan installation =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(plan);
        FakeHostResolverAdapter adapter = new();

        EncryptedDnsAdapterResult result = EncryptedDnsHostResolverInstallationExecutor.Apply(installation, adapter);

        Assert.True(result.Applied);
        Assert.Equal(["corp.example."], Assert.Single(adapter.Plans).InternalDnsDomains);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0119")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HostResolverExecutorDoesNotInvokeAdapterForBlockedPlan()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
            explicitConfigurationPrefersDo53: true);
        FakeHostResolverAdapter adapter = new();

        EncryptedDnsAdapterResult result = EncryptedDnsHostResolverInstallationExecutor.Apply(
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(plan),
            adapter);

        Assert.Equal(EncryptedDnsAdapterResultStatus.Blocked, result.Status);
        Assert.Empty(adapter.Plans);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0120")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdvertisementExecutorAppliesReadyPayloadPlanThroughPlatformAdapter()
    {
        EncryptedDnsDiscoveryAdvertisementPlan plan = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            [IPAddress.Parse("192.0.2.53"), IPAddress.Parse("2001:db8::53")]);
        FakeAdvertisementAdapter adapter = new();

        EncryptedDnsAdapterResult result = EncryptedDnsDiscoveryAdvertisementExecutor.Apply(plan, adapter);

        Assert.True(result.Applied);
        EncryptedDnsDiscoveryAdvertisementPlan appliedPlan = Assert.Single(adapter.Plans);
        Assert.True(appliedPlan.PublishesDhcpv4);
        Assert.True(appliedPlan.PublishesDhcpv6);
        Assert.True(appliedPlan.PublishesRouterAdvertisements);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0120")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AdvertisementExecutorDoesNotInvokeAdapterForNonReadyPlan()
    {
        EncryptedDnsDiscoveryAdvertisementPlan plan = EncryptedDnsDiscoveryAdvertisementPlanner.CreatePlan(
            "resolver.example",
            [IPAddress.Loopback]);
        FakeAdvertisementAdapter adapter = new();

        EncryptedDnsAdapterResult result = EncryptedDnsDiscoveryAdvertisementExecutor.Apply(plan, adapter);

        Assert.Equal(EncryptedDnsAdapterResultStatus.Blocked, result.Status);
        Assert.Empty(adapter.Plans);
    }

    private static EncryptedDnsDiscoveryOption CreateDiscoveryOption(IPAddress address, ushort priority = 1)
    {
        return EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [address],
            priority,
            serviceParameterKeys: ["alpn"]);
    }

    private static EncryptedDnsProvisioningAttribute CreateIpv4Reply(IPAddress address)
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressListWithServiceParameters(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [address],
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'d', (byte)'o', (byte)'q'])]);
    }

    private sealed class FakeDnssecValidator(EncryptedDnsDiscoveryDnssecValidationStatus status)
        : IEncryptedDnsDiscoveryDnssecValidator
    {
        public List<string> AuthenticationDomainNames { get; } = [];

        public EncryptedDnsDiscoveryDnssecValidationStatus ValidateAdnOnlySvcbResolution(string authenticationDomainName)
        {
            AuthenticationDomainNames.Add(authenticationDomainName);
            return status;
        }
    }

    private sealed class FakePublicationAdapter : IDnsServiceBindingPublicationAdapter
    {
        public List<DnsServiceBindingPublicationAdapterRequest> Requests { get; } = [];

        public EncryptedDnsAdapterResult Publish(DnsServiceBindingPublicationAdapterRequest request)
        {
            Requests.Add(request);
            return EncryptedDnsAdapterResult.CreateApplied("published by fake DNS provider", request.Plan.Records.Count);
        }
    }

    private sealed class FakeProvisioningTransport(EncryptedDnsProvisioningConfigurationPayload response)
        : IEncryptedDnsProvisioningTransport
    {
        public List<EncryptedDnsProvisioningConfigurationPayload> Requests { get; } = [];

        public EncryptedDnsProvisioningConfigurationPayload Exchange(EncryptedDnsProvisioningConfigurationPayload requestPayload)
        {
            Requests.Add(requestPayload);
            return response;
        }
    }

    private sealed class FakeSessionConnector(IPAddress successAddress) : IEncryptedDnsSessionConnector
    {
        public List<IPAddress?> AttemptedAddresses { get; } = [];

        public EncryptedDnsAdapterResult Connect(EncryptedDnsSessionAttempt attempt)
        {
            AttemptedAddresses.Add(attempt.Address);
            return Equals(attempt.Address, successAddress)
                ? EncryptedDnsAdapterResult.CreateApplied("connected by fake encrypted DNS transport", appliedItemCount: 1)
                : EncryptedDnsAdapterResult.CreateFailed("fake connector rejected the attempt");
        }
    }

    private sealed class FakeHostResolverAdapter : IEncryptedDnsHostResolverPlatformAdapter
    {
        public List<EncryptedDnsHostResolverInstallationPlan> Plans { get; } = [];

        public EncryptedDnsAdapterResult Apply(EncryptedDnsHostResolverInstallationPlan plan)
        {
            Plans.Add(plan);
            return EncryptedDnsAdapterResult.CreateApplied("applied by fake platform resolver", plan.EncryptedSessionAttempts.Count);
        }
    }

    private sealed class FakeAdvertisementAdapter : IEncryptedDnsDiscoveryAdvertisementPlatformAdapter
    {
        public List<EncryptedDnsDiscoveryAdvertisementPlan> Plans { get; } = [];

        public EncryptedDnsAdapterResult Apply(EncryptedDnsDiscoveryAdvertisementPlan plan)
        {
            Plans.Add(plan);
            int payloadCount = (plan.PublishesDhcpv4 ? 1 : 0) + plan.Dhcpv6Options.Count + plan.RouterAdvertisementOptions.Count;
            return EncryptedDnsAdapterResult.CreateApplied("applied by fake DHCP and Router Advertisement adapter", payloadCount);
        }
    }
}

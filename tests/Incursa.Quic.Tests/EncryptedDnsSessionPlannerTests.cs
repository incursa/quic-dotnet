// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsSessionPlannerTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0118")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServiceBindingEndpointBecomesEncryptedSessionAttempt()
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
        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(
            endpoint,
            dependentSpecificationAllowsCleartextFallback: true);

        EncryptedDnsSessionAttempt attempt = EncryptedDnsSessionPlanner.CreateAttempt(plan);

        Assert.Equal(EncryptedDnsSessionAttemptSource.ServiceBinding, attempt.Source);
        Assert.Equal(DnsServiceBindingProtocol.DnsOverHttps3, attempt.Protocol);
        Assert.Null(attempt.Address);
        Assert.Equal("resolver.example", attempt.AuthenticationName);
        Assert.Equal(9443, attempt.Port);
        Assert.Equal("/dns-query{?dns}", attempt.DohPathTemplate);
        Assert.True(attempt.CanTryCleartextResolverAfterEncryptedFailure);
        Assert.Equal("config", attempt.HttpsServiceParameters["ech"]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0118")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiscoveryPlanCreatesPriorityOrderedEncryptedSessionAttempts()
    {
        IPAddress firstAddress = IPAddress.Parse("192.0.2.53");
        IPAddress secondAddress = IPAddress.Parse("2001:db8::53");
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(firstAddress, priority: 30)],
            routerAdvertisementOptions: [CreateDiscoveryOption(secondAddress, priority: 10)],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            encryptedConnectionEstablished: false,
            allowDo53Fallback: true);

        IReadOnlyList<EncryptedDnsSessionAttempt> attempts = EncryptedDnsSessionPlanner.CreateAttempts(plan);

        Assert.Equal([firstAddress, secondAddress], attempts.Select(static attempt => attempt.Address).ToArray());
        Assert.All(attempts, static attempt =>
        {
            Assert.Equal(EncryptedDnsSessionAttemptSource.Discovery, attempt.Source);
            Assert.Equal(DnsServiceBindingProtocol.DnsOverQuic, attempt.Protocol);
            Assert.Equal(DoqDefaults.DefaultPort, attempt.Port);
            Assert.Equal("resolver.example.", attempt.AuthenticationName);
            Assert.Contains("alpn", attempt.ServiceParameterKeys);
            Assert.True(attempt.CanTryCleartextResolverAfterEncryptedFailure);
        });
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0118")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DiscoveryPlanThatPrefersDo53DoesNotInventEncryptedSessionAttempts()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
            do53ResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            explicitConfigurationPrefersDo53: true);

        Assert.Empty(EncryptedDnsSessionPlanner.CreateAttempts(plan));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0118")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProvisioningPlanBlockedByNullAuthenticationDoesNotCreateAttempts()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateProvisioningReply(IPAddress.Parse("192.0.2.53"))],
            responderUsedNullAuthentication: true,
            nullAuthenticationPreconfigured: false);

        Assert.Empty(EncryptedDnsSessionPlanner.CreateAttempts(plan));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0118")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EncryptedSessionAttemptRejectsCleartextDnsPort()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateProvisioningReply(IPAddress.Parse("192.0.2.53"))]);

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsSessionPlanner.CreateAttempts(
                plan,
                DnsServiceBindingProtocol.DnsOverQuic,
                DnsServiceBindingDefaults.CleartextDnsDefaultPort));
    }

    private static EncryptedDnsDiscoveryOption CreateDiscoveryOption(IPAddress address, ushort priority = 1)
    {
        return EncryptedDnsDiscoveryOption.Create(
            "resolver.example",
            [address],
            priority,
            serviceParameterKeys: ["alpn"]);
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

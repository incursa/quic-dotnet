// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsHostResolverInstallationPlannerTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0119")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServiceBindingPlanCreatesGlobalHostResolverInstallationPlan()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            ["doq"],
            port: 8853);
        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq"])));

        EncryptedDnsHostResolverInstallationPlan installation =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(
                DnsServiceBindingClientPolicy.CreatePlan(endpoint));

        Assert.Equal(EncryptedDnsHostResolverInstallationStatus.Ready, installation.Status);
        Assert.True(installation.CanInstallEncryptedResolver);
        Assert.True(installation.AppliesToAllDomains);
        Assert.True(installation.RequiresPlatformResolverAdapter);
        Assert.Equal(8853, Assert.Single(installation.EncryptedSessionAttempts).Port);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0119")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiscoveryPlanPreservesEncryptedAttemptsAndFallbackResolvers()
    {
        IPAddress encryptedAddress = IPAddress.Parse("192.0.2.53");
        IPAddress fallbackAddress = IPAddress.Parse("198.51.100.53");
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(encryptedAddress)],
            do53ResolverAddresses: [fallbackAddress],
            encryptedConnectionEstablished: false,
            allowDo53Fallback: true);

        EncryptedDnsHostResolverInstallationPlan installation =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(plan);

        Assert.Equal(EncryptedDnsHostResolverInstallationStatus.Ready, installation.Status);
        Assert.Equal(encryptedAddress, Assert.Single(installation.EncryptedSessionAttempts).Address);
        Assert.Equal(fallbackAddress, Assert.Single(installation.CleartextFallbackResolvers));
        Assert.True(installation.AppliesToAllDomains);
        Assert.False(installation.AppliesToInternalDomainsOnly);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0119")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DiscoveryPlanThatPrefersDo53BlocksEncryptedResolverInstallation()
    {
        EncryptedDnsDiscoveryClientPlan plan = EncryptedDnsDiscoveryClientPolicy.CreatePlan(
            dhcpOptions: [CreateDiscoveryOption(IPAddress.Parse("192.0.2.53"))],
            explicitConfigurationPrefersDo53: true);

        EncryptedDnsHostResolverInstallationPlan installation =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(plan);

        Assert.Equal(EncryptedDnsHostResolverInstallationStatus.BlockedByPolicy, installation.Status);
        Assert.False(installation.CanInstallEncryptedResolver);
        Assert.Empty(installation.EncryptedSessionAttempts);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0119")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProvisioningSplitTunnelPlanScopesInstallationToInternalDomains()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateProvisioningReply(IPAddress.Parse("192.0.2.53"))],
            cleartextResolverAddresses: [IPAddress.Parse("198.51.100.53")],
            internalDnsDomains: ["corp.example"],
            splitTunnel: true);

        EncryptedDnsHostResolverInstallationPlan installation =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(plan);

        Assert.Equal(EncryptedDnsHostResolverInstallationStatus.Ready, installation.Status);
        Assert.True(installation.AppliesToInternalDomainsOnly);
        Assert.False(installation.AppliesToAllDomains);
        Assert.Equal(["corp.example."], installation.InternalDnsDomains);
        Assert.Single(installation.CleartextFallbackResolvers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0119")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NullAuthenticatedProvisioningBlocksHostResolverInstallation()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateProvisioningReply(IPAddress.Parse("192.0.2.53"))],
            responderUsedNullAuthentication: true,
            nullAuthenticationPreconfigured: false);

        EncryptedDnsHostResolverInstallationPlan installation =
            EncryptedDnsHostResolverInstallationPlanner.CreatePlan(plan);

        Assert.Equal(EncryptedDnsHostResolverInstallationStatus.BlockedByPolicy, installation.Status);
        Assert.False(installation.CanInstallEncryptedResolver);
        Assert.False(installation.RequiresPlatformResolverAdapter);
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

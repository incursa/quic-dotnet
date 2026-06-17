// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Builds side-effect-free host resolver installation plans for encrypted DNS.
/// </summary>
public static class EncryptedDnsHostResolverInstallationPlanner
{
    /// <summary>
    /// Creates a global resolver installation plan from an RFC 9461 DNS service binding client plan.
    /// </summary>
    public static EncryptedDnsHostResolverInstallationPlan CreatePlan(DnsServiceBindingClientPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return new EncryptedDnsHostResolverInstallationPlan(
            EncryptedDnsHostResolverInstallationStatus.Ready,
            [EncryptedDnsSessionPlanner.CreateAttempt(plan)],
            cleartextFallbackResolvers: [],
            internalDnsDomains: [],
            splitTunnel: false);
    }

    /// <summary>
    /// Creates a resolver installation plan from an RFC 9463 encrypted DNS discovery client plan.
    /// </summary>
    public static EncryptedDnsHostResolverInstallationPlan CreatePlan(
        EncryptedDnsDiscoveryClientPlan plan,
        DnsServiceBindingProtocol protocol = DnsServiceBindingProtocol.DnsOverQuic,
        int? port = null)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!plan.UsesEncryptedDnsResolvers)
        {
            return new EncryptedDnsHostResolverInstallationPlan(
                plan.ExplicitConfigurationPrefersDo53
                    ? EncryptedDnsHostResolverInstallationStatus.BlockedByPolicy
                    : EncryptedDnsHostResolverInstallationStatus.NoEncryptedResolvers,
                encryptedSessionAttempts: [],
                cleartextFallbackResolvers: [],
                internalDnsDomains: [],
                splitTunnel: false);
        }

        return new EncryptedDnsHostResolverInstallationPlan(
            EncryptedDnsHostResolverInstallationStatus.Ready,
            EncryptedDnsSessionPlanner.CreateAttempts(plan, protocol, port),
            plan.CanFallbackToDo53 ? plan.Do53ResolverAddresses : [],
            internalDnsDomains: [],
            splitTunnel: false);
    }

    /// <summary>
    /// Creates a resolver installation plan from an RFC 9464 encrypted DNS provisioning client plan.
    /// </summary>
    public static EncryptedDnsHostResolverInstallationPlan CreatePlan(
        EncryptedDnsProvisioningClientPlan plan,
        DnsServiceBindingProtocol protocol = DnsServiceBindingProtocol.DnsOverQuic,
        int? port = null)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!plan.UsesEncryptedDnsResolvers)
        {
            return new EncryptedDnsHostResolverInstallationPlan(
                plan.BlockedByNullAuthentication
                    ? EncryptedDnsHostResolverInstallationStatus.BlockedByPolicy
                    : EncryptedDnsHostResolverInstallationStatus.NoEncryptedResolvers,
                encryptedSessionAttempts: [],
                cleartextFallbackResolvers: [],
                internalDnsDomains: [],
                splitTunnel: plan.SplitTunnel);
        }

        bool splitTunnel = plan.SplitTunnel && plan.InternalDnsDomains.Count != 0;
        return new EncryptedDnsHostResolverInstallationPlan(
            EncryptedDnsHostResolverInstallationStatus.Ready,
            EncryptedDnsSessionPlanner.CreateAttempts(plan, protocol, port),
            plan.CleartextResolverAddresses,
            splitTunnel ? plan.InternalDnsDomains : [],
            splitTunnel);
    }
}

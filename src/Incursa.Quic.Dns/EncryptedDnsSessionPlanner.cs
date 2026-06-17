// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Creates deterministic encrypted DNS session attempts without opening network connections.
/// </summary>
public static class EncryptedDnsSessionPlanner
{
    /// <summary>
    /// Creates a session attempt from a selected RFC 9461 DNS service binding client plan.
    /// </summary>
    public static EncryptedDnsSessionAttempt CreateAttempt(DnsServiceBindingClientPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        DnsServiceBindingEndpoint endpoint = plan.Endpoint;
        return new EncryptedDnsSessionAttempt(
            EncryptedDnsSessionAttemptSource.ServiceBinding,
            endpoint.Protocol,
            address: null,
            plan.ServerAuthenticationName,
            endpoint.Port,
            servicePriority: 0,
            plan.AllowsCleartextFallback,
            endpoint.DohPathTemplate,
            serviceParameterKeys: [],
            endpoint.HttpsServiceParameters);
    }

    /// <summary>
    /// Creates ordered session attempts from an RFC 9463 encrypted DNS discovery client plan.
    /// </summary>
    public static IReadOnlyList<EncryptedDnsSessionAttempt> CreateAttempts(
        EncryptedDnsDiscoveryClientPlan plan,
        DnsServiceBindingProtocol protocol = DnsServiceBindingProtocol.DnsOverQuic,
        int? port = null)
    {
        ArgumentNullException.ThrowIfNull(plan);
        int effectivePort = port ?? DnsServiceBindingRecord.GetDefaultPort(protocol);
        if (!plan.UsesEncryptedDnsResolvers)
        {
            return [];
        }

        List<EncryptedDnsSessionAttempt> attempts = [];
        foreach (EncryptedDnsDiscoveryResolverEndpoint endpoint in plan.EncryptedResolverEndpoints)
        {
            attempts.Add(new EncryptedDnsSessionAttempt(
                EncryptedDnsSessionAttemptSource.Discovery,
                protocol,
                endpoint.Address,
                endpoint.AuthenticationDomainName,
                effectivePort,
                endpoint.ServicePriority,
                plan.CanFallbackToDo53,
                dohPathTemplate: null,
                endpoint.ServiceParameterKeys,
                httpsServiceParameters: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)));
        }

        return attempts;
    }

    /// <summary>
    /// Creates ordered session attempts from an RFC 9464 encrypted DNS provisioning client plan.
    /// </summary>
    public static IReadOnlyList<EncryptedDnsSessionAttempt> CreateAttempts(
        EncryptedDnsProvisioningClientPlan plan,
        DnsServiceBindingProtocol protocol = DnsServiceBindingProtocol.DnsOverQuic,
        int? port = null)
    {
        ArgumentNullException.ThrowIfNull(plan);
        int effectivePort = port ?? DnsServiceBindingRecord.GetDefaultPort(protocol);
        if (!plan.UsesEncryptedDnsResolvers)
        {
            return [];
        }

        List<EncryptedDnsSessionAttempt> attempts = [];
        foreach (EncryptedDnsProvisioningResolverEndpoint endpoint in plan.EncryptedResolverEndpoints)
        {
            attempts.Add(new EncryptedDnsSessionAttempt(
                EncryptedDnsSessionAttemptSource.Provisioning,
                protocol,
                endpoint.Address,
                endpoint.AuthenticationDomainName,
                effectivePort,
                endpoint.ServicePriority,
                plan.HasCleartextDnsResolvers,
                dohPathTemplate: null,
                endpoint.ServiceParameterKeys,
                httpsServiceParameters: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)));
        }

        return attempts;
    }
}

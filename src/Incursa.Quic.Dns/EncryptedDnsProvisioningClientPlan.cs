// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Client-side resolver decision produced from RFC 9464 encrypted DNS provisioning data.
/// </summary>
public sealed class EncryptedDnsProvisioningClientPlan
{
    internal EncryptedDnsProvisioningClientPlan(
        IReadOnlyList<EncryptedDnsProvisioningResolverEndpoint> encryptedResolverEndpoints,
        IReadOnlyList<IPAddress> cleartextResolverAddresses,
        IReadOnlyList<string> internalDnsDomains,
        bool splitTunnel,
        bool blockedByNullAuthentication)
    {
        EncryptedResolverEndpoints = encryptedResolverEndpoints;
        CleartextResolverAddresses = cleartextResolverAddresses;
        InternalDnsDomains = internalDnsDomains;
        SplitTunnel = splitTunnel;
        BlockedByNullAuthentication = blockedByNullAuthentication;
    }

    /// <summary>
    /// Gets encrypted DNS resolver session targets sorted by service priority.
    /// </summary>
    public IReadOnlyList<EncryptedDnsProvisioningResolverEndpoint> EncryptedResolverEndpoints { get; }

    /// <summary>
    /// Gets classic INTERNAL_IP*_DNS resolver addresses learned from the same CFG_REPLY context.
    /// </summary>
    public IReadOnlyList<IPAddress> CleartextResolverAddresses { get; }

    /// <summary>
    /// Gets INTERNAL_DNS_DOMAIN names normalized for split-tunnel matching.
    /// </summary>
    public IReadOnlyList<string> InternalDnsDomains { get; }

    /// <summary>
    /// Gets a value indicating whether the IPsec configuration is split-tunnel.
    /// </summary>
    public bool SplitTunnel { get; }

    /// <summary>
    /// Gets a value indicating whether ENCDNS_IP* data was rejected because responder NULL authentication was not preconfigured.
    /// </summary>
    public bool BlockedByNullAuthentication { get; }

    /// <summary>
    /// Gets a value indicating whether the client should use encrypted DNS resolvers from this plan.
    /// </summary>
    public bool UsesEncryptedDnsResolvers => !BlockedByNullAuthentication && EncryptedResolverEndpoints.Count != 0;

    /// <summary>
    /// Gets a value indicating whether classic DNS resolvers are present in the provisioning context.
    /// </summary>
    public bool HasCleartextDnsResolvers => CleartextResolverAddresses.Count != 0;

    /// <summary>
    /// Gets a value indicating whether internal split-tunnel names should use the encrypted DNS resolvers.
    /// </summary>
    public bool UsesEncryptedDnsForInternalDomains => UsesEncryptedDnsResolvers && SplitTunnel && InternalDnsDomains.Count != 0;

    internal static EncryptedDnsProvisioningClientPlan Create(
        IEnumerable<EncryptedDnsProvisioningResolverEndpoint> encryptedResolverEndpoints,
        IEnumerable<IPAddress> cleartextResolverAddresses,
        IEnumerable<string> internalDnsDomains,
        bool splitTunnel,
        bool blockedByNullAuthentication)
    {
        return new EncryptedDnsProvisioningClientPlan(
            new ReadOnlyCollection<EncryptedDnsProvisioningResolverEndpoint>([.. encryptedResolverEndpoints]),
            new ReadOnlyCollection<IPAddress>([.. cleartextResolverAddresses]),
            new ReadOnlyCollection<string>([.. internalDnsDomains]),
            splitTunnel,
            blockedByNullAuthentication);
    }
}

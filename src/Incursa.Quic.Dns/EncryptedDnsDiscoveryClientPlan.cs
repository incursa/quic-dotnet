// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Client-side resolver decision produced from RFC 9463 encrypted DNS discovery data.
/// </summary>
public sealed class EncryptedDnsDiscoveryClientPlan
{
    internal EncryptedDnsDiscoveryClientPlan(
        IReadOnlyList<EncryptedDnsDiscoveryResolverEndpoint> encryptedResolverEndpoints,
        IReadOnlyList<IPAddress> do53ResolverAddresses,
        bool explicitConfigurationPrefersDo53,
        bool encryptedConnectionEstablished,
        bool allowDo53Fallback,
        EncryptedDnsDiscoveryTrustAnchorMode trustAnchorMode)
    {
        EncryptedResolverEndpoints = encryptedResolverEndpoints;
        Do53ResolverAddresses = do53ResolverAddresses;
        ExplicitConfigurationPrefersDo53 = explicitConfigurationPrefersDo53;
        EncryptedConnectionEstablished = encryptedConnectionEstablished;
        AllowDo53Fallback = allowDo53Fallback;
        TrustAnchorMode = trustAnchorMode;
    }

    /// <summary>
    /// Gets encrypted DNS resolver endpoints sorted by RFC 8106 source precedence and service priority.
    /// </summary>
    public IReadOnlyList<EncryptedDnsDiscoveryResolverEndpoint> EncryptedResolverEndpoints { get; }

    /// <summary>
    /// Gets classic Do53 resolver addresses learned from the same network.
    /// </summary>
    public IReadOnlyList<IPAddress> Do53ResolverAddresses { get; }

    /// <summary>
    /// Gets a value indicating whether explicit local configuration prefers Do53 over discovered encrypted DNS.
    /// </summary>
    public bool ExplicitConfigurationPrefersDo53 { get; }

    /// <summary>
    /// Gets a value indicating whether an authenticated encrypted DNS connection has been established.
    /// </summary>
    public bool EncryptedConnectionEstablished { get; }

    /// <summary>
    /// Gets a value indicating whether fallback to Do53 is allowed when encrypted connection establishment fails.
    /// </summary>
    public bool AllowDo53Fallback { get; }

    /// <summary>
    /// Gets the PKI trust-anchor mode for resolver certificate validation.
    /// </summary>
    public EncryptedDnsDiscoveryTrustAnchorMode TrustAnchorMode { get; }

    /// <summary>
    /// Gets a value indicating whether encrypted DNS resolvers should be used by default.
    /// </summary>
    public bool UsesEncryptedDnsResolvers => EncryptedResolverEndpoints.Count != 0 && !ExplicitConfigurationPrefersDo53;

    /// <summary>
    /// Gets a value indicating whether fallback to Do53 is allowed for this network.
    /// </summary>
    public bool CanFallbackToDo53 => UsesEncryptedDnsResolvers
        && !EncryptedConnectionEstablished
        && AllowDo53Fallback
        && Do53ResolverAddresses.Count != 0;

    internal static EncryptedDnsDiscoveryClientPlan Create(
        IEnumerable<EncryptedDnsDiscoveryResolverEndpoint> encryptedResolverEndpoints,
        IEnumerable<IPAddress> do53ResolverAddresses,
        bool explicitConfigurationPrefersDo53,
        bool encryptedConnectionEstablished,
        bool allowDo53Fallback,
        EncryptedDnsDiscoveryTrustAnchorMode trustAnchorMode)
    {
        return new EncryptedDnsDiscoveryClientPlan(
            new ReadOnlyCollection<EncryptedDnsDiscoveryResolverEndpoint>([.. encryptedResolverEndpoints]),
            new ReadOnlyCollection<IPAddress>([.. do53ResolverAddresses]),
            explicitConfigurationPrefersDo53,
            encryptedConnectionEstablished,
            allowDo53Fallback,
            trustAnchorMode);
    }
}

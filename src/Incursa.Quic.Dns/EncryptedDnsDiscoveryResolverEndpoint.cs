// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Resolver session target learned through RFC 9463 encrypted DNS discovery.
/// </summary>
public sealed class EncryptedDnsDiscoveryResolverEndpoint
{
    internal EncryptedDnsDiscoveryResolverEndpoint(
        IPAddress address,
        string authenticationDomainName,
        ushort servicePriority,
        uint lifetime,
        EncryptedDnsDiscoverySource source,
        IEnumerable<string> serviceParameterKeys)
    {
        Address = address;
        AuthenticationDomainName = authenticationDomainName;
        ServicePriority = servicePriority;
        Lifetime = lifetime;
        Source = source;
        ServiceParameterKeys = new ReadOnlyCollection<string>([.. serviceParameterKeys]);
    }

    /// <summary>
    /// Gets the encrypted DNS resolver IP address.
    /// </summary>
    public IPAddress Address { get; }

    /// <summary>
    /// Gets the normalized authentication domain name conveyed by discovery.
    /// </summary>
    public string AuthenticationDomainName { get; }

    /// <summary>
    /// Gets the resolver service priority.
    /// </summary>
    public ushort ServicePriority { get; }

    /// <summary>
    /// Gets the lifetime associated with the discovered ADN.
    /// </summary>
    public uint Lifetime { get; }

    /// <summary>
    /// Gets the discovery source that supplied this resolver endpoint.
    /// </summary>
    public EncryptedDnsDiscoverySource Source { get; }

    /// <summary>
    /// Gets normalized service parameter keys that apply to this resolver endpoint.
    /// </summary>
    public IReadOnlyList<string> ServiceParameterKeys { get; }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Resolver session target conveyed by RFC 9464 ENCDNS_IP* configuration.
/// </summary>
public sealed class EncryptedDnsProvisioningResolverEndpoint
{
    internal EncryptedDnsProvisioningResolverEndpoint(
        IPAddress address,
        string authenticationDomainName,
        ushort servicePriority,
        EncryptedDnsProvisioningAddressFamily addressFamily,
        IEnumerable<string> serviceParameterKeys)
    {
        Address = address;
        AuthenticationDomainName = authenticationDomainName;
        ServicePriority = servicePriority;
        AddressFamily = addressFamily;
        ServiceParameterKeys = new ReadOnlyCollection<string>([.. serviceParameterKeys]);
    }

    /// <summary>
    /// Gets the resolver IP address conveyed in ENCDNS_IP*.
    /// </summary>
    public IPAddress Address { get; }

    /// <summary>
    /// Gets the normalized authentication domain name conveyed in ENCDNS_IP*.
    /// </summary>
    public string AuthenticationDomainName { get; }

    /// <summary>
    /// Gets the resolver service priority.
    /// </summary>
    public ushort ServicePriority { get; }

    /// <summary>
    /// Gets the ENCDNS_IP* address family.
    /// </summary>
    public EncryptedDnsProvisioningAddressFamily AddressFamily { get; }

    /// <summary>
    /// Gets normalized service parameter keys that apply to this resolver endpoint.
    /// </summary>
    public IReadOnlyList<string> ServiceParameterKeys { get; }
}

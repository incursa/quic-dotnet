// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 CONNECT-IP target, protocol, route advertisement, and access-control policy helpers.
/// </summary>
public static class Http3ConnectIpScopePolicy
{
    /// <summary>
    /// Gets the IPv4 version number used by CONNECT-IP capsules and scope decisions.
    /// </summary>
    public const int Ipv4Version = 4;

    /// <summary>
    /// Gets the IPv6 version number used by CONNECT-IP capsules and scope decisions.
    /// </summary>
    public const int Ipv6Version = 6;

    /// <summary>
    /// Returns the IP version number for an IP address.
    /// </summary>
    public static int GetIpVersion(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => Ipv4Version,
            AddressFamily.InterNetworkV6 => Ipv6Version,
            _ => throw new ArgumentException("CONNECT-IP address scopes support only IPv4 and IPv6.", nameof(address)),
        };
    }

    /// <summary>
    /// Returns true when an IP prefix target is scoped to exactly one IP version.
    /// </summary>
    public static bool PrefixTargetUsesSingleIpVersion(Http3ConnectIpTargetScope target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return target.Address is null || GetIpVersion(target.Address) is Ipv4Version or Ipv6Version;
    }

    /// <summary>
    /// Returns true when a resolved address should be included in a scoped ROUTE_ADVERTISEMENT capsule.
    /// </summary>
    public static bool ShouldAdvertiseResolvedRoute(
        IPAddress resolvedAddress,
        bool accessibleToProxy,
        IReadOnlyCollection<int> assignedAddressFamilies)
    {
        ArgumentNullException.ThrowIfNull(resolvedAddress);
        ArgumentNullException.ThrowIfNull(assignedAddressFamilies);

        if (!accessibleToProxy)
        {
            return false;
        }

        int version = GetIpVersion(resolvedAddress);
        foreach (int assignedAddressFamily in assignedAddressFamilies)
        {
            if (assignedAddressFamily == version)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns true when a CONNECT-IP proxy should reject the request using client-provided scope information.
    /// </summary>
    public static bool ShouldRejectForAccessControl(bool accessControlEnabled, bool clientAuthorizedForAnyDestinationInScope)
    {
        return accessControlEnabled && !clientAuthorizedForAnyDestinationInScope;
    }
}

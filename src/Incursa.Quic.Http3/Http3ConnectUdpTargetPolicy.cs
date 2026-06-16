// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9298 CONNECT-UDP target filtering and rejection helpers.
/// </summary>
public static class Http3ConnectUdpTargetPolicy
{
    private const byte Ipv4LinkLocalFirstOctet = 169;
    private const byte Ipv4LinkLocalSecondOctet = 254;
    private const byte Ipv4MulticastMinimumFirstOctet = 224;
    private const byte Ipv4MulticastMaximumFirstOctet = 239;

    /// <summary>
    /// Gets the Proxy-Status error type used when a destination IP is prohibited.
    /// </summary>
    public const string DestinationIpProhibitedErrorType = "destination_ip_prohibited";

    /// <summary>
    /// Returns true when the resolved target address is prohibited for UDP proxying.
    /// </summary>
    public static bool IsVulnerableTarget(IPAddress targetAddress, IReadOnlyCollection<IPAddress>? proxyLocalAddresses = null)
    {
        ArgumentNullException.ThrowIfNull(targetAddress);

        if (IPAddress.IsLoopback(targetAddress)
            || IsLinkLocal(targetAddress)
            || IsMulticast(targetAddress)
            || IsBroadcast(targetAddress)
            || IsUnspecified(targetAddress))
        {
            return true;
        }

        if (proxyLocalAddresses is not null)
        {
            foreach (IPAddress localAddress in proxyLocalAddresses)
            {
                if (targetAddress.Equals(localAddress))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Creates the Proxy-Status field for a destination_ip_prohibited rejection.
    /// </summary>
    public static QPackFieldLine CreateDestinationIpProhibitedProxyStatusHeader()
    {
        return new QPackFieldLine("proxy-status", $"error={DestinationIpProhibitedErrorType}");
    }

    private static bool IsLinkLocal(IPAddress address)
    {
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal;
        }

        byte[] bytes = address.GetAddressBytes();
        return bytes is [Ipv4LinkLocalFirstOctet, Ipv4LinkLocalSecondOctet, _, _];
    }

    private static bool IsMulticast(IPAddress address)
    {
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6Multicast;
        }

        byte[] bytes = address.GetAddressBytes();
        return bytes[0] is >= Ipv4MulticastMinimumFirstOctet and <= Ipv4MulticastMaximumFirstOctet;
    }

    private static bool IsBroadcast(IPAddress address)
    {
        return address.Equals(IPAddress.Broadcast);
    }

    private static bool IsUnspecified(IPAddress address)
    {
        return address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
    }
}

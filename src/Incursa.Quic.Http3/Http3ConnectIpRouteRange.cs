// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9484 ROUTE_ADVERTISEMENT IP Address Range entry.
/// </summary>
public sealed class Http3ConnectIpRouteRange
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ConnectIpRouteRange" /> class.
    /// </summary>
    public Http3ConnectIpRouteRange(IPAddress startAddress, IPAddress endAddress, int ipProtocol)
    {
        ArgumentNullException.ThrowIfNull(startAddress);
        ArgumentNullException.ThrowIfNull(endAddress);
        if (ipProtocol is < 0 or > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(ipProtocol), "CONNECT-IP route protocol must fit in an unsigned 8-bit integer.");
        }

        int ipVersion = Http3ConnectIpScopePolicy.GetIpVersion(startAddress);
        if (Http3ConnectIpScopePolicy.GetIpVersion(endAddress) != ipVersion)
        {
            throw new ArgumentException("CONNECT-IP route start and end addresses must use the same IP version.", nameof(endAddress));
        }

        if (CompareAddressBytes(startAddress.GetAddressBytes(), endAddress.GetAddressBytes()) > 0)
        {
            throw new ArgumentException("CONNECT-IP route start address must be less than or equal to the end address.", nameof(startAddress));
        }

        StartAddress = startAddress;
        EndAddress = endAddress;
        IpVersion = ipVersion;
        IpProtocol = ipProtocol;
    }

    /// <summary>
    /// Gets the route IP version.
    /// </summary>
    public int IpVersion { get; }

    /// <summary>
    /// Gets the route start address.
    /// </summary>
    public IPAddress StartAddress { get; }

    /// <summary>
    /// Gets the route end address.
    /// </summary>
    public IPAddress EndAddress { get; }

    /// <summary>
    /// Gets the routed IP protocol, or zero for all protocols.
    /// </summary>
    public int IpProtocol { get; }

    /// <summary>
    /// Returns true when this range allows the packet protocol.
    /// </summary>
    public bool AllowsProtocol(int protocolNumber)
    {
        return IpProtocol == 0
            || IpProtocol == protocolNumber
            || protocolNumber is Http3ConnectIpProtocolScope.IcmpV4ProtocolNumber or Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber;
    }

    internal static int CompareAddressBytes(byte[] left, byte[] right)
    {
        for (int index = 0; index < left.Length; index++)
        {
            int comparison = left[index].CompareTo(right[index]);
            if (comparison != 0)
            {
                return comparison;
            }
        }

        return 0;
    }
}

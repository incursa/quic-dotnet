// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9484 CONNECT-IP Assigned Address entry.
/// </summary>
public sealed class Http3ConnectIpAssignedAddress
{
    private const int Ipv4BitLength = 32;
    private const int Ipv6BitLength = 128;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ConnectIpAssignedAddress" /> class.
    /// </summary>
    public Http3ConnectIpAssignedAddress(ulong requestId, IPAddress address, int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(address);

        int ipVersion = Http3ConnectIpScopePolicy.GetIpVersion(address);
        int bitLength = GetBitLength(ipVersion);
        if (prefixLength < 0 || prefixLength > bitLength)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength), "CONNECT-IP prefix length must fit the IP address length.");
        }

        if (!HasZeroHostBits(address, prefixLength))
        {
            throw new ArgumentException("CONNECT-IP assigned address host bits outside the prefix must be zero.", nameof(address));
        }

        RequestId = requestId;
        Address = address;
        PrefixLength = prefixLength;
        IpVersion = ipVersion;
    }

    /// <summary>
    /// Gets the ADDRESS_REQUEST request ID, or zero for unprompted assignments.
    /// </summary>
    public ulong RequestId { get; }

    /// <summary>
    /// Gets the assigned IP address.
    /// </summary>
    public IPAddress Address { get; }

    /// <summary>
    /// Gets the assigned IP version.
    /// </summary>
    public int IpVersion { get; }

    /// <summary>
    /// Gets the assigned IP prefix length.
    /// </summary>
    public int PrefixLength { get; }

    /// <summary>
    /// Returns true when this entry assigns exactly one source address.
    /// </summary>
    public bool AllowsSingleSourceAddress => PrefixLength == GetBitLength(IpVersion);

    /// <summary>
    /// Returns true when the source address falls within the assigned prefix.
    /// </summary>
    public bool AllowsSourceAddress(IPAddress sourceAddress)
    {
        ArgumentNullException.ThrowIfNull(sourceAddress);
        if (Http3ConnectIpScopePolicy.GetIpVersion(sourceAddress) != IpVersion)
        {
            return false;
        }

        byte[] prefixBytes = Address.GetAddressBytes();
        byte[] sourceBytes = sourceAddress.GetAddressBytes();
        int fullBytes = PrefixLength / 8;
        int remainingBits = PrefixLength % 8;

        for (int index = 0; index < fullBytes; index++)
        {
            if (prefixBytes[index] != sourceBytes[index])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        int mask = 0xFF << (8 - remainingBits) & 0xFF;
        return (prefixBytes[fullBytes] & mask) == (sourceBytes[fullBytes] & mask);
    }

    internal static int GetBitLength(int ipVersion)
    {
        return ipVersion switch
        {
            Http3ConnectIpScopePolicy.Ipv4Version => Ipv4BitLength,
            Http3ConnectIpScopePolicy.Ipv6Version => Ipv6BitLength,
            _ => throw new ArgumentOutOfRangeException(nameof(ipVersion), "CONNECT-IP IP version must be 4 or 6."),
        };
    }

    internal static bool HasZeroHostBits(IPAddress address, int prefixLength)
    {
        byte[] bytes = address.GetAddressBytes();
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        if (remainingBits > 0 && fullBytes < bytes.Length)
        {
            int mask = 0xFF << (8 - remainingBits) & 0xFF;
            if ((bytes[fullBytes] & ~mask) != 0)
            {
                return false;
            }

            fullBytes++;
        }

        for (int index = fullBytes; index < bytes.Length; index++)
        {
            if (bytes[index] != 0)
            {
                return false;
            }
        }

        return true;
    }
}

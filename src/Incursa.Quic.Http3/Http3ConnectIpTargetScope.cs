// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents the RFC 9484 target tunnel scope.
/// </summary>
public sealed class Http3ConnectIpTargetScope
{
    private Http3ConnectIpTargetScope(string? hostName, IPAddress? address, int? prefixLength, bool wildcard)
    {
        HostName = hostName;
        Address = address;
        PrefixLength = prefixLength;
        IsWildcard = wildcard;
    }

    /// <summary>
    /// Gets the wildcard target scope.
    /// </summary>
    public static Http3ConnectIpTargetScope Any { get; } = new(null, null, null, wildcard: true);

    /// <summary>
    /// Gets the DNS host name when the target is a reg-name.
    /// </summary>
    public string? HostName { get; }

    /// <summary>
    /// Gets the IP address when the target is an address or prefix.
    /// </summary>
    public IPAddress? Address { get; }

    /// <summary>
    /// Gets the prefix length when the target is an IP prefix.
    /// </summary>
    public int? PrefixLength { get; }

    /// <summary>
    /// Gets a value indicating whether the target allows any destination.
    /// </summary>
    public bool IsWildcard { get; }

    /// <summary>
    /// Gets a value indicating whether DNS resolution is required before replying.
    /// </summary>
    public bool RequiresDnsResolution => HostName is not null;

    /// <summary>
    /// Parses a decoded RFC 9484 target value.
    /// </summary>
    public static bool TryParse(string? value, out Http3ConnectIpTargetScope scope)
    {
        if (string.IsNullOrEmpty(value) || value == "*")
        {
            scope = Any;
            return true;
        }

        string addressText = value;
        int? prefixLength = null;
        int slashIndex = value.IndexOf('/', StringComparison.Ordinal);
        if (slashIndex >= 0)
        {
            addressText = value[..slashIndex];
            if (!int.TryParse(value[(slashIndex + 1)..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int parsedPrefix))
            {
                scope = Any;
                return false;
            }

            prefixLength = parsedPrefix;
        }

        if (IPAddress.TryParse(addressText, out IPAddress? address))
        {
            int bitLength = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            int effectivePrefix = prefixLength ?? bitLength;
            if (effectivePrefix < 0 || effectivePrefix > bitLength || !HasZeroHostBits(address, effectivePrefix))
            {
                scope = Any;
                return false;
            }

            scope = new Http3ConnectIpTargetScope(null, address, prefixLength, wildcard: false);
            return true;
        }

        if (prefixLength.HasValue || !IsRegName(value))
        {
            scope = Any;
            return false;
        }

        scope = new Http3ConnectIpTargetScope(value, null, null, wildcard: false);
        return true;
    }

    private static bool IsRegName(string host)
    {
        if (host.Length == 0)
        {
            return false;
        }

        for (int index = 0; index < host.Length; index++)
        {
            char character = host[index];
            if (character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-'
                or '.'
                or '_'
                or '~')
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static bool HasZeroHostBits(IPAddress address, int prefixLength)
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

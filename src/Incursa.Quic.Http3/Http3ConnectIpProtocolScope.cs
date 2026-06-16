// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Globalization;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents the RFC 9484 ipproto tunnel scope.
/// </summary>
public sealed class Http3ConnectIpProtocolScope
{
    private const int MaximumProtocolNumber = 255;

    private Http3ConnectIpProtocolScope(int? protocolNumber)
    {
        ProtocolNumber = protocolNumber;
    }

    /// <summary>
    /// Gets the wildcard protocol scope.
    /// </summary>
    public static Http3ConnectIpProtocolScope Any { get; } = new(null);

    /// <summary>
    /// Gets the ICMPv4 protocol number.
    /// </summary>
    public const int IcmpV4ProtocolNumber = 1;

    /// <summary>
    /// Gets the ICMPv6 protocol number.
    /// </summary>
    public const int IcmpV6ProtocolNumber = 58;

    /// <summary>
    /// Gets the selected protocol number, or null for wildcard scope.
    /// </summary>
    public int? ProtocolNumber { get; }

    /// <summary>
    /// Gets a value indicating whether the scope allows any IP protocol.
    /// </summary>
    public bool AllowsAnyProtocol => !ProtocolNumber.HasValue;

    /// <summary>
    /// Parses a decoded RFC 9484 ipproto value.
    /// </summary>
    public static bool TryParse(string? value, out Http3ConnectIpProtocolScope scope)
    {
        if (string.IsNullOrEmpty(value) || value == "*")
        {
            scope = Any;
            return true;
        }

        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int protocol)
            || protocol is < 0 or > MaximumProtocolNumber)
        {
            scope = Any;
            return false;
        }

        scope = new Http3ConnectIpProtocolScope(protocol);
        return true;
    }

    /// <summary>
    /// Returns true when the protocol scope allows the packet protocol.
    /// </summary>
    public bool AllowsProtocol(int protocolNumber)
    {
        return AllowsAnyProtocol
            || protocolNumber == ProtocolNumber
            || protocolNumber is IcmpV4ProtocolNumber or IcmpV6ProtocolNumber;
    }
}

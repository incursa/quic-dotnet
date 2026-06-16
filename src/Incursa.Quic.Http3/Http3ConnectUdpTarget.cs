// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9298 CONNECT-UDP target.
/// </summary>
public sealed class Http3ConnectUdpTarget
{
    private const int MinimumPort = 1;
    private const int MaximumPort = 65535;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ConnectUdpTarget" /> class.
    /// </summary>
    public Http3ConnectUdpTarget(string host, int port)
    {
        if (!IsValidTargetHost(host))
        {
            throw new ArgumentException("CONNECT-UDP target_host must be a non-empty IPv6address, IPv4address, or reg-name without scoped zone identifiers.", nameof(host));
        }

        if (port is < MinimumPort or > MaximumPort)
        {
            throw new ArgumentOutOfRangeException(nameof(port), "CONNECT-UDP target_port must be between 1 and 65535.");
        }

        Host = host;
        Port = port;
    }

    /// <summary>
    /// Gets the target host.
    /// </summary>
    public string Host { get; }

    /// <summary>
    /// Gets the target UDP port.
    /// </summary>
    public int Port { get; }

    /// <summary>
    /// Gets the target host value encoded for URI-template expansion.
    /// </summary>
    public string EncodedHost => EncodeTargetHost(Host);

    /// <summary>
    /// Returns true when the host is a legal CONNECT-UDP target_host value.
    /// </summary>
    public static bool IsValidTargetHost(string? host)
    {
        if (string.IsNullOrEmpty(host) || host.Contains('%', StringComparison.Ordinal))
        {
            return false;
        }

        if (IPAddress.TryParse(host, out IPAddress? address))
        {
            return address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 || address.ScopeId == 0;
        }

        return IsRegName(host);
    }

    /// <summary>
    /// Encodes target_host for path/query use, including IPv6 literal colon escaping.
    /// </summary>
    public static string EncodeTargetHost(string host)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        return IPAddress.TryParse(host, out IPAddress? address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? host.Replace(":", "%3A", StringComparison.Ordinal)
            : host;
    }

    private static bool IsRegName(string host)
    {
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
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// RFC 9461 DNS service binding naming and default-port helpers.
/// </summary>
public static class DnsServiceBindingDefaults
{
    private const int MaximumDnsNameLength = 253;
    private const int MaximumDnsLabelLength = 63;

    /// <summary>
    /// The SVCB mapping scheme for DNS services.
    /// </summary>
    public const string Scheme = "dns";

    /// <summary>
    /// The DNS service node name registered for SVCB Port Prefix Naming.
    /// </summary>
    public const string NodeName = "_dns";

    /// <summary>
    /// The default port for cleartext DNS over UDP and TCP.
    /// </summary>
    public const int CleartextDnsDefaultPort = 53;

    /// <summary>
    /// The default port for DNS over TLS.
    /// </summary>
    public const int DnsOverTlsDefaultPort = 853;

    /// <summary>
    /// The default port for DNS over QUIC.
    /// </summary>
    public const int DnsOverQuicDefaultPort = DoqDefaults.DefaultPort;

    /// <summary>
    /// The default port for DNS over HTTPS.
    /// </summary>
    public const int DnsOverHttpsDefaultPort = 443;

    /// <summary>
    /// Gets the RFC 9461 default port for the given DNS service transport.
    /// </summary>
    public static int GetDefaultPort(DnsServiceTransport transport)
        => transport switch
        {
            DnsServiceTransport.CleartextUdp => CleartextDnsDefaultPort,
            DnsServiceTransport.CleartextTcp => CleartextDnsDefaultPort,
            DnsServiceTransport.DnsOverTls => DnsOverTlsDefaultPort,
            DnsServiceTransport.DnsOverQuic => DnsOverQuicDefaultPort,
            DnsServiceTransport.DnsOverHttps => DnsOverHttpsDefaultPort,
            _ => throw new ArgumentOutOfRangeException(nameof(transport), transport, "Unknown DNS service transport."),
        };

    /// <summary>
    /// Creates the RFC 9461 Port Prefix Naming prefix for a DNS service port.
    /// </summary>
    public static string CreateServicePrefix(int port)
    {
        ValidatePort(port, nameof(port));
        return port == CleartextDnsDefaultPort
            ? NodeName
            : $"_{port}.{NodeName}";
    }

    /// <summary>
    /// Creates the SVCB record name for a DNS service authentication hostname.
    /// </summary>
    public static string CreateServiceName(
        string authenticationName,
        DnsServiceTransport transport,
        int? port = null)
    {
        string normalizedName = NormalizeDnsHostname(authenticationName, nameof(authenticationName));
        int effectivePort = port ?? GetDefaultPort(transport);
        return $"{CreateServicePrefix(effectivePort)}.{normalizedName}";
    }

    /// <summary>
    /// Returns a value indicating whether the name is an RFC 9461 authentication name.
    /// </summary>
    public static bool IsValidAuthenticationName(string? authenticationName)
        => TryNormalizeAuthenticationName(authenticationName, out _);

    /// <summary>
    /// Normalizes an RFC 9461 authentication name when it is a DNS hostname or literal IP address.
    /// </summary>
    public static bool TryNormalizeAuthenticationName(string? authenticationName, out string normalizedName)
    {
        normalizedName = string.Empty;
        if (string.IsNullOrWhiteSpace(authenticationName))
        {
            return false;
        }

        string candidate = authenticationName.Trim();
        string unbracketed = candidate is ['[', .., ']']
            ? candidate[1..^1]
            : candidate;

        if (IPAddress.TryParse(unbracketed, out _))
        {
            normalizedName = unbracketed.ToLowerInvariant();
            return true;
        }

        return TryNormalizeDnsHostname(candidate, out normalizedName);
    }

    private static string NormalizeDnsHostname(string authenticationName, string argumentName)
    {
        if (!TryNormalizeDnsHostname(authenticationName, out string normalizedName))
        {
            throw new ArgumentException("The authentication name must be a DNS hostname.", argumentName);
        }

        return normalizedName;
    }

    private static bool TryNormalizeDnsHostname(string? authenticationName, out string normalizedName)
    {
        normalizedName = string.Empty;
        if (string.IsNullOrWhiteSpace(authenticationName))
        {
            return false;
        }

        string candidate = authenticationName.Trim();
        bool absolute = candidate.EndsWith(".", StringComparison.Ordinal);
        string host = absolute ? candidate[..^1] : candidate;
        if (host.Length == 0 || host.Length > MaximumDnsNameLength)
        {
            return false;
        }

        string[] labels = host.Split('.');
        foreach (string label in labels)
        {
            if (!IsValidDnsLabel(label))
            {
                return false;
            }
        }

        normalizedName = string.Join(".", labels).ToLowerInvariant();
        if (absolute)
        {
            normalizedName += ".";
        }

        return true;
    }

    private static bool IsValidDnsLabel(string label)
    {
        if (label.Length is 0 or > MaximumDnsLabelLength || label[0] == '-' || label[^1] == '-')
        {
            return false;
        }

        foreach (char c in label)
        {
            bool valid = c is >= 'a' and <= 'z'
                || c is >= 'A' and <= 'Z'
                || c is >= '0' and <= '9'
                || c == '-';
            if (!valid)
            {
                return false;
            }
        }

        return true;
    }

    private static void ValidatePort(int port, string argumentName)
    {
        if (port is < IPEndPoint.MinPort or > IPEndPoint.MaxPort)
        {
            throw new ArgumentOutOfRangeException(argumentName, port, "A DNS service port must be a valid TCP or UDP port.");
        }
    }
}

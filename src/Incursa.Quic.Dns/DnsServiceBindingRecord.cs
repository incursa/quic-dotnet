// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Scalar RFC 9461 SVCB record data needed for DNS service endpoint selection.
/// </summary>
public sealed class DnsServiceBindingRecord
{
    private const string DnsUriTemplateVariable = "{dns}";
    private const string DnsUriTemplateQueryVariable = "{?dns}";
    private const string ExpandedDnsQueryPrefix = "?dns=";
    private const char PathSeparator = '/';

    private DnsServiceBindingRecord(
        string authenticationName,
        ReadOnlyCollection<string> alpnProtocols,
        string? dohPathTemplate,
        int? port,
        bool hasEquivalentSupportedProtocolKey,
        IReadOnlyDictionary<string, string> httpsServiceParameters)
    {
        AuthenticationName = authenticationName;
        AlpnProtocols = alpnProtocols;
        DohPathTemplate = dohPathTemplate;
        Port = port;
        HasEquivalentSupportedProtocolKey = hasEquivalentSupportedProtocolKey;
        HttpsServiceParameters = new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(httpsServiceParameters, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Gets the SvcParamKey assigned to <c>dohpath</c>.
    /// </summary>
    public const ushort DohPathSvcParamKey = 7;

    /// <summary>
    /// Gets the SVCB RR type value.
    /// </summary>
    public const ushort SvcbResourceRecordType = 64;

    /// <summary>
    /// Gets the SvcParamKey assigned to <c>port</c>.
    /// </summary>
    public const ushort PortSvcParamKey = 3;

    /// <summary>
    /// Gets a value indicating whether the <c>port</c> key is automatically mandatory for DNS service binding.
    /// </summary>
    public static bool IsPortKeyAutomaticallyMandatory => true;

    /// <summary>
    /// Gets the authentication name for this SVCB mapping.
    /// </summary>
    public string AuthenticationName { get; }

    /// <summary>
    /// Gets the ALPN protocols carried by the SVCB <c>alpn</c> key.
    /// </summary>
    public IReadOnlyList<string> AlpnProtocols { get; }

    /// <summary>
    /// Gets the single <c>dohpath</c> URI template value, when present.
    /// </summary>
    public string? DohPathTemplate { get; }

    /// <summary>
    /// Gets the SVCB <c>port</c> value, when present.
    /// </summary>
    public int? Port { get; }

    /// <summary>
    /// Gets a value indicating whether a recognized non-ALPN key can select a supported protocol.
    /// </summary>
    public bool HasEquivalentSupportedProtocolKey { get; }

    /// <summary>
    /// Gets HTTPS SvcParam values that apply to HTTP-based DNS connections.
    /// </summary>
    public IReadOnlyDictionary<string, string> HttpsServiceParameters { get; }

    /// <summary>
    /// Creates scalar SVCB data for DNS service endpoint selection.
    /// </summary>
    public static DnsServiceBindingRecord Create(
        string authenticationName,
        IEnumerable<string>? alpnProtocols = null,
        string? dohPathTemplate = null,
        int? port = null,
        bool hasEquivalentSupportedProtocolKey = false,
        IReadOnlyDictionary<string, string>? httpsServiceParameters = null)
    {
        if (!DnsServiceBindingDefaults.TryNormalizeAuthenticationName(authenticationName, out string normalizedName))
        {
            throw new ArgumentException("The authentication name must be a DNS hostname or literal IP address.", nameof(authenticationName));
        }

        if (port is < IPEndPoint.MinPort + 1 or > IPEndPoint.MaxPort)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "The SVCB port must be a valid non-zero TCP or UDP port.");
        }

        ReadOnlyCollection<string> normalizedAlpn = NormalizeAlpnProtocols(alpnProtocols);
        string? normalizedDohPath = NormalizeDohPathTemplate(dohPathTemplate);
        return new DnsServiceBindingRecord(
            normalizedName,
            normalizedAlpn,
            normalizedDohPath,
            port,
            hasEquivalentSupportedProtocolKey,
            httpsServiceParameters ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
    }

    internal static string ExpandDohPath(string dohPathTemplate, ReadOnlySpan<byte> dnsMessage)
    {
        string encoded = Convert.ToBase64String(dnsMessage)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        return dohPathTemplate
            .Replace(DnsUriTemplateQueryVariable, ExpandedDnsQueryPrefix + encoded, StringComparison.Ordinal)
            .Replace(DnsUriTemplateVariable, encoded, StringComparison.Ordinal);
    }

    internal static string? NormalizeDohPathTemplate(string? dohPathTemplate)
    {
        if (dohPathTemplate is null)
        {
            return null;
        }

        if (!IsValidDohPathTemplate(dohPathTemplate))
        {
            throw new ArgumentException("The dohpath value must be a UTF-8 relative URI template path containing the {dns} variable.", nameof(dohPathTemplate));
        }

        return dohPathTemplate;
    }

    internal static bool IsHttpAlpn(string alpnProtocol)
    {
        return string.Equals(alpnProtocol, "h2", StringComparison.Ordinal)
            || string.Equals(alpnProtocol, "h3", StringComparison.Ordinal);
    }

    internal static bool TryMapAlpn(string alpnProtocol, out DnsServiceBindingProtocol protocol)
    {
        protocol = alpnProtocol switch
        {
            "dot" => DnsServiceBindingProtocol.DnsOverTls,
            "doq" => DnsServiceBindingProtocol.DnsOverQuic,
            "h2" => DnsServiceBindingProtocol.DnsOverHttps2,
            "h3" => DnsServiceBindingProtocol.DnsOverHttps3,
            _ => default,
        };
        return alpnProtocol is "dot" or "doq" or "h2" or "h3";
    }

    internal static int GetDefaultPort(DnsServiceBindingProtocol protocol)
    {
        return protocol switch
        {
            DnsServiceBindingProtocol.DnsOverTls => DnsServiceBindingDefaults.DnsOverTlsDefaultPort,
            DnsServiceBindingProtocol.DnsOverQuic => DnsServiceBindingDefaults.DnsOverQuicDefaultPort,
            DnsServiceBindingProtocol.DnsOverHttps2 => DnsServiceBindingDefaults.DnsOverHttpsDefaultPort,
            DnsServiceBindingProtocol.DnsOverHttps3 => DnsServiceBindingDefaults.DnsOverHttpsDefaultPort,
            _ => throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "Unknown DNS service binding protocol."),
        };
    }

    private static ReadOnlyCollection<string> NormalizeAlpnProtocols(IEnumerable<string>? alpnProtocols)
    {
        if (alpnProtocols is null)
        {
            return new ReadOnlyCollection<string>([]);
        }

        List<string> normalized = [];
        foreach (string? protocol in alpnProtocols)
        {
            if (string.IsNullOrWhiteSpace(protocol))
            {
                throw new ArgumentException("ALPN protocol identifiers must not be empty.", nameof(alpnProtocols));
            }

            normalized.Add(protocol.Trim().ToLowerInvariant());
        }

        return new ReadOnlyCollection<string>(normalized);
    }

    private static bool IsValidDohPathTemplate(string dohPathTemplate)
    {
        if (string.IsNullOrEmpty(dohPathTemplate)
            || dohPathTemplate[0] != PathSeparator
            || dohPathTemplate.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }

        return dohPathTemplate.Contains(DnsUriTemplateVariable, StringComparison.Ordinal)
            || dohPathTemplate.Contains(DnsUriTemplateQueryVariable, StringComparison.Ordinal);
    }
}

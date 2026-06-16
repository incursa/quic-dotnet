// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// A DNS service endpoint selected from an RFC 9461 SVCB record.
/// </summary>
public sealed class DnsServiceBindingEndpoint
{
    internal DnsServiceBindingEndpoint(
        DnsServiceBindingProtocol protocol,
        string alpnProtocol,
        string authenticationName,
        int port,
        string? dohPathTemplate,
        IReadOnlyDictionary<string, string> httpsServiceParameters)
    {
        Protocol = protocol;
        AlpnProtocol = alpnProtocol;
        AuthenticationName = authenticationName;
        Port = port;
        DohPathTemplate = dohPathTemplate;
        HttpsServiceParameters = new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(httpsServiceParameters, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Gets the selected DNS service protocol.
    /// </summary>
    public DnsServiceBindingProtocol Protocol { get; }

    /// <summary>
    /// Gets the ALPN protocol identifier that selected this endpoint.
    /// </summary>
    public string AlpnProtocol { get; }

    /// <summary>
    /// Gets the authentication name used for secure transport establishment.
    /// </summary>
    public string AuthenticationName { get; }

    /// <summary>
    /// Gets the effective port for the selected protocol.
    /// </summary>
    public int Port { get; }

    /// <summary>
    /// Gets the DoH path template for HTTP-based DNS endpoints.
    /// </summary>
    public string? DohPathTemplate { get; }

    /// <summary>
    /// Gets HTTPS SvcParam values that apply to the resulting HTTP connection.
    /// </summary>
    public IReadOnlyDictionary<string, string> HttpsServiceParameters { get; }

    /// <summary>
    /// Expands the DoH path template with the supplied DNS message for GET-style DoH requests.
    /// </summary>
    public string ExpandDohPath(ReadOnlySpan<byte> dnsMessage)
    {
        if (DohPathTemplate is null)
        {
            throw new InvalidOperationException("Only DNS-over-HTTPS endpoints carry a dohpath template.");
        }

        if (dnsMessage.IsEmpty)
        {
            throw new ArgumentException("The DNS message must not be empty.", nameof(dnsMessage));
        }

        return DnsServiceBindingRecord.ExpandDohPath(DohPathTemplate, dnsMessage);
    }
}

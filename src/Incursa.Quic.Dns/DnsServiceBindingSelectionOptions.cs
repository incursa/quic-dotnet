// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Client capabilities used while selecting RFC 9461 DNS SVCB endpoints.
/// </summary>
public sealed class DnsServiceBindingSelectionOptions
{
    private DnsServiceBindingSelectionOptions(ReadOnlyCollection<string> supportedAlpnProtocols, bool respectPortKey)
    {
        SupportedAlpnProtocols = supportedAlpnProtocols;
        RespectPortKey = respectPortKey;
    }

    /// <summary>
    /// Gets the ALPN protocols supported by the client.
    /// </summary>
    public IReadOnlyCollection<string> SupportedAlpnProtocols { get; }

    /// <summary>
    /// Gets a value indicating whether the client respects the SVCB <c>port</c> key.
    /// </summary>
    public bool RespectPortKey { get; }

    /// <summary>
    /// Creates client selection options.
    /// </summary>
    public static DnsServiceBindingSelectionOptions Create(
        IEnumerable<string> supportedAlpnProtocols,
        bool respectPortKey = true)
    {
        if (supportedAlpnProtocols is null)
        {
            throw new ArgumentNullException(nameof(supportedAlpnProtocols));
        }

        List<string> normalized = [];
        foreach (string? protocol in supportedAlpnProtocols)
        {
            if (string.IsNullOrWhiteSpace(protocol))
            {
                throw new ArgumentException("Supported ALPN protocol identifiers must not be empty.", nameof(supportedAlpnProtocols));
            }

            normalized.Add(protocol.Trim().ToLowerInvariant());
        }

        return new DnsServiceBindingSelectionOptions(new ReadOnlyCollection<string>(normalized), respectPortKey);
    }
}

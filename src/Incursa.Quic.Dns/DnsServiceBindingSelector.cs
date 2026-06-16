// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Selects usable DNS endpoints from RFC 9461 SVCB records.
/// </summary>
public static class DnsServiceBindingSelector
{
    /// <summary>
    /// Selects endpoints compatible with the supplied client capabilities.
    /// </summary>
    public static IReadOnlyList<DnsServiceBindingEndpoint> SelectEndpoints(
        DnsServiceBindingRecord record,
        DnsServiceBindingSelectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(options);

        if (record.AlpnProtocols.Count == 0 && !record.HasEquivalentSupportedProtocolKey)
        {
            return new ReadOnlyCollection<DnsServiceBindingEndpoint>([]);
        }

        if (record.Port.HasValue && !options.RespectPortKey)
        {
            return new ReadOnlyCollection<DnsServiceBindingEndpoint>([]);
        }

        HashSet<string> supported = new(options.SupportedAlpnProtocols, StringComparer.Ordinal);
        List<DnsServiceBindingEndpoint> endpoints = [];
        foreach (string alpnProtocol in record.AlpnProtocols)
        {
            if (!supported.Contains(alpnProtocol) || !DnsServiceBindingRecord.TryMapAlpn(alpnProtocol, out DnsServiceBindingProtocol protocol))
            {
                continue;
            }

            if (DnsServiceBindingRecord.IsHttpAlpn(alpnProtocol) && record.DohPathTemplate is null)
            {
                continue;
            }

            int port = record.Port ?? DnsServiceBindingRecord.GetDefaultPort(protocol);
            endpoints.Add(new DnsServiceBindingEndpoint(
                protocol,
                alpnProtocol,
                record.AuthenticationName,
                port,
                DnsServiceBindingRecord.IsHttpAlpn(alpnProtocol) ? record.DohPathTemplate : null,
                DnsServiceBindingRecord.IsHttpAlpn(alpnProtocol)
                    ? record.HttpsServiceParameters
                    : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)));
        }

        return new ReadOnlyCollection<DnsServiceBindingEndpoint>(endpoints);
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Applies deterministic RFC 9461 publication plans through an explicit DNS provider adapter.
/// </summary>
public static class DnsServiceBindingPublicationExecutor
{
    /// <summary>
    /// Publishes a service binding plan through the supplied provider adapter.
    /// </summary>
    public static EncryptedDnsAdapterResult Publish(
        DnsServiceBindingPublicationPlan plan,
        IDnsServiceBindingPublicationAdapter adapter,
        bool requiresDnssecSigning = false)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(adapter);
        if (plan.Records.Count == 0)
        {
            return EncryptedDnsAdapterResult.CreateBlocked("The DNS service binding publication plan contains no records.");
        }

        return adapter.Publish(new DnsServiceBindingPublicationAdapterRequest(plan, requiresDnssecSigning));
    }
}

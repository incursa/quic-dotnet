// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents a deterministic DNS provider publication request for RFC 9461 service binding records.
/// </summary>
public sealed class DnsServiceBindingPublicationAdapterRequest
{
    internal DnsServiceBindingPublicationAdapterRequest(
        DnsServiceBindingPublicationPlan plan,
        bool requiresDnssecSigning)
    {
        Plan = plan;
        RequiresDnssecSigning = requiresDnssecSigning;
    }

    /// <summary>
    /// Gets the publication plan to apply through a DNS provider adapter.
    /// </summary>
    public DnsServiceBindingPublicationPlan Plan { get; }

    /// <summary>
    /// Gets a value indicating whether the operator requires the provider to publish signed DNSSEC data.
    /// </summary>
    public bool RequiresDnssecSigning { get; }
}

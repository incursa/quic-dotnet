// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Adapter contract for applying RFC 9461 DNS service binding publication plans to a DNS provider.
/// </summary>
public interface IDnsServiceBindingPublicationAdapter
{
    /// <summary>
    /// Applies the publication request through a provider-specific implementation.
    /// </summary>
    EncryptedDnsAdapterResult Publish(DnsServiceBindingPublicationAdapterRequest request);
}

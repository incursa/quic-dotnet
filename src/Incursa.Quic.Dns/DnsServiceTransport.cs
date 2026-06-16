// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// DNS service transports that participate in RFC 9461 SVCB port mapping.
/// </summary>
public enum DnsServiceTransport
{
    /// <summary>
    /// Cleartext DNS over UDP.
    /// </summary>
    CleartextUdp,

    /// <summary>
    /// Cleartext DNS over TCP.
    /// </summary>
    CleartextTcp,

    /// <summary>
    /// DNS over TLS.
    /// </summary>
    DnsOverTls,

    /// <summary>
    /// DNS over QUIC.
    /// </summary>
    DnsOverQuic,

    /// <summary>
    /// DNS over HTTPS.
    /// </summary>
    DnsOverHttps,
}

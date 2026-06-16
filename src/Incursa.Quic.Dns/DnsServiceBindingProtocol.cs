// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// DNS service protocols advertised through RFC 9461 SVCB service parameters.
/// </summary>
public enum DnsServiceBindingProtocol
{
    /// <summary>
    /// DNS over TLS.
    /// </summary>
    DnsOverTls,

    /// <summary>
    /// DNS over QUIC.
    /// </summary>
    DnsOverQuic,

    /// <summary>
    /// DNS over HTTPS using HTTP/2.
    /// </summary>
    DnsOverHttps2,

    /// <summary>
    /// DNS over HTTPS using HTTP/3.
    /// </summary>
    DnsOverHttps3,
}

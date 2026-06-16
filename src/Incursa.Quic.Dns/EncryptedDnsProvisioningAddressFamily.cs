// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// ENCDNS_IP* address families defined by RFC 9464.
/// </summary>
public enum EncryptedDnsProvisioningAddressFamily
{
    /// <summary>
    /// ENCDNS_IP4.
    /// </summary>
    Ip4,

    /// <summary>
    /// ENCDNS_IP6.
    /// </summary>
    Ip6,
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Source that supplied RFC 9463 encrypted DNS discovery information.
/// </summary>
public enum EncryptedDnsDiscoverySource
{
    /// <summary>
    /// Discovery information came from DHCPv4 or DHCPv6.
    /// </summary>
    Dhcp,

    /// <summary>
    /// Discovery information came from an IPv6 Router Advertisement option.
    /// </summary>
    RouterAdvertisement,
}

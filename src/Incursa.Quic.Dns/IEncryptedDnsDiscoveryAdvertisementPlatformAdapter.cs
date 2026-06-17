// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Adapter contract for emitting RFC 9463 encrypted DNS discovery payloads through platform DHCP or Router Advertisement surfaces.
/// </summary>
public interface IEncryptedDnsDiscoveryAdvertisementPlatformAdapter
{
    /// <summary>
    /// Applies a ready advertisement plan.
    /// </summary>
    EncryptedDnsAdapterResult Apply(EncryptedDnsDiscoveryAdvertisementPlan plan);
}

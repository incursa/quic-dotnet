// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Applies RFC 9463 advertisement plans through an explicit platform adapter.
/// </summary>
public static class EncryptedDnsDiscoveryAdvertisementExecutor
{
    /// <summary>
    /// Applies a ready advertisement plan or returns a blocked result without invoking the adapter.
    /// </summary>
    public static EncryptedDnsAdapterResult Apply(
        EncryptedDnsDiscoveryAdvertisementPlan plan,
        IEncryptedDnsDiscoveryAdvertisementPlatformAdapter adapter)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(adapter);
        if (!plan.RequiresPlatformAdvertisementAdapter)
        {
            return EncryptedDnsAdapterResult.CreateBlocked("The encrypted DNS advertisement plan is not ready for platform emission.");
        }

        return adapter.Apply(plan);
    }
}

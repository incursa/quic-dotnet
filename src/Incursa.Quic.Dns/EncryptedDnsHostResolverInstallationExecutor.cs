// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Applies host resolver installation plans through an explicit platform adapter.
/// </summary>
public static class EncryptedDnsHostResolverInstallationExecutor
{
    /// <summary>
    /// Applies a ready installation plan or returns a blocked result without invoking the adapter.
    /// </summary>
    public static EncryptedDnsAdapterResult Apply(
        EncryptedDnsHostResolverInstallationPlan plan,
        IEncryptedDnsHostResolverPlatformAdapter adapter)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(adapter);
        if (!plan.RequiresPlatformResolverAdapter)
        {
            return EncryptedDnsAdapterResult.CreateBlocked("The host resolver installation plan is not ready for platform application.");
        }

        return adapter.Apply(plan);
    }
}

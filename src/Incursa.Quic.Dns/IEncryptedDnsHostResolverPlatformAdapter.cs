// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Adapter contract for applying encrypted DNS host resolver installation plans to a platform resolver.
/// </summary>
public interface IEncryptedDnsHostResolverPlatformAdapter
{
    /// <summary>
    /// Applies a ready host resolver installation plan.
    /// </summary>
    EncryptedDnsAdapterResult Apply(EncryptedDnsHostResolverInstallationPlan plan);
}

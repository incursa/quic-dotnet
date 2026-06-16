// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Local RFC 9463 policy result for ADN-only SVCB resolution.
/// </summary>
public enum EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus
{
    /// <summary>
    /// The SVCB-derived resolver parameters may be used.
    /// </summary>
    Accepted = 0,

    /// <summary>
    /// The SVCB-derived resolver parameters must not be used.
    /// </summary>
    Rejected = 1
}

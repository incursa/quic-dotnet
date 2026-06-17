// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Local status for planning encrypted DNS resolver installation into a host resolver.
/// </summary>
public enum EncryptedDnsHostResolverInstallationStatus
{
    /// <summary>
    /// The plan contains encrypted DNS session attempts that a platform adapter can install.
    /// </summary>
    Ready,

    /// <summary>
    /// The source plan did not contain encrypted resolver targets.
    /// </summary>
    NoEncryptedResolvers,

    /// <summary>
    /// Local policy prevents installing encrypted resolver targets.
    /// </summary>
    BlockedByPolicy,
}

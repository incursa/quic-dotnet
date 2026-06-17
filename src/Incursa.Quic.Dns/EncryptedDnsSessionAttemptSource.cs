// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Identifies the local encrypted DNS planning surface that produced a session attempt.
/// </summary>
public enum EncryptedDnsSessionAttemptSource
{
    /// <summary>
    /// The attempt was produced from an RFC 9461 selected DNS service binding endpoint.
    /// </summary>
    ServiceBinding,

    /// <summary>
    /// The attempt was produced from an RFC 9463 encrypted DNS discovery client plan.
    /// </summary>
    Discovery,

    /// <summary>
    /// The attempt was produced from an RFC 9464 encrypted DNS provisioning client plan.
    /// </summary>
    Provisioning,
}

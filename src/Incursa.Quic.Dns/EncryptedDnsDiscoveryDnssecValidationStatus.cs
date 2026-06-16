// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// DNSSEC validation status for RFC 9463 ADN-only SVCB resolution.
/// </summary>
public enum EncryptedDnsDiscoveryDnssecValidationStatus
{
    /// <summary>
    /// DNSSEC validation was not evaluated.
    /// </summary>
    NotEvaluated = 0,

    /// <summary>
    /// The SVCB response validated as secure.
    /// </summary>
    Secure = 1,

    /// <summary>
    /// The SVCB response is in an unsigned DNSSEC island.
    /// </summary>
    Insecure = 2,

    /// <summary>
    /// The SVCB response failed DNSSEC validation.
    /// </summary>
    Bogus = 3,

    /// <summary>
    /// DNSSEC validation did not produce a usable answer.
    /// </summary>
    Indeterminate = 4
}

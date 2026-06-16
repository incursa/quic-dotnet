// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// RFC 9463 encrypted DNS resolver certificate validation result.
/// </summary>
public enum EncryptedDnsDiscoveryCertificateValidationStatus
{
    /// <summary>
    /// PKIX validation succeeded and the certificate matched the conveyed ADN.
    /// </summary>
    Validated,

    /// <summary>
    /// PKIX validation or ADN matching failed.
    /// </summary>
    Failed,
}

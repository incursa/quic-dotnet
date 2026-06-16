// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// RFC 9464 encrypted DNS resolver certificate validation result.
/// </summary>
public enum EncryptedDnsProvisioningCertificateValidationStatus
{
    /// <summary>
    /// The resolver certificate was accepted by authenticating the conveyed ADN.
    /// </summary>
    ValidatedByAuthenticationDomainName,

    /// <summary>
    /// The resolver certificate was accepted by matching the conveyed SubjectPublicKeyInfo digest.
    /// </summary>
    ValidatedBySubjectPublicKeyInfoDigest,

    /// <summary>
    /// Resolver certificate validation failed and the encrypted DNS resolver must not be used.
    /// </summary>
    NonRecoverableFailure,
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Pure DNSSEC policy for RFC 9463 encrypted DNS discovery.
/// </summary>
public static class EncryptedDnsDiscoveryDnssecPolicy
{
    /// <summary>
    /// Evaluates whether ADN-only SVCB resolution can be used as an active-attack mitigation.
    /// </summary>
    public static EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus EvaluateAdnOnlySvcbResolution(
        EncryptedDnsDiscoveryDnssecValidationStatus dnssecValidationStatus)
        => dnssecValidationStatus == EncryptedDnsDiscoveryDnssecValidationStatus.Secure
            ? EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus.Accepted
            : EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus.Rejected;
}

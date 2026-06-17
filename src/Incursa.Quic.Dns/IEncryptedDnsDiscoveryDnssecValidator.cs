// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Adapter contract for supplying DNSSEC validation status to RFC 9463 ADN-only SVCB policy.
/// </summary>
public interface IEncryptedDnsDiscoveryDnssecValidator
{
    /// <summary>
    /// Validates the DNSSEC status of an ADN-only SVCB resolution result.
    /// </summary>
    EncryptedDnsDiscoveryDnssecValidationStatus ValidateAdnOnlySvcbResolution(string authenticationDomainName);
}

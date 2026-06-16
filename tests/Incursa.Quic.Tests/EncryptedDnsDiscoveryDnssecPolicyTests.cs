// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsDiscoveryDnssecPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0117")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdnOnlySvcbResolutionAcceptsSecureDnssecValidation()
    {
        EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus status =
            EncryptedDnsDiscoveryDnssecPolicy.EvaluateAdnOnlySvcbResolution(
                EncryptedDnsDiscoveryDnssecValidationStatus.Secure);

        Assert.Equal(EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus.Accepted, status);
    }

    [Theory]
    [InlineData(EncryptedDnsDiscoveryDnssecValidationStatus.Insecure)]
    [InlineData(EncryptedDnsDiscoveryDnssecValidationStatus.Bogus)]
    [InlineData(EncryptedDnsDiscoveryDnssecValidationStatus.Indeterminate)]
    [Requirement("REQ-QUIC-RFC9463-0117")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AdnOnlySvcbResolutionRejectsNonSecureDnssecValidation(
        EncryptedDnsDiscoveryDnssecValidationStatus validationStatus)
    {
        EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus status =
            EncryptedDnsDiscoveryDnssecPolicy.EvaluateAdnOnlySvcbResolution(validationStatus);

        Assert.Equal(EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus.Rejected, status);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0117")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void AdnOnlySvcbResolutionRejectsMissingDnssecValidation()
    {
        EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus status =
            EncryptedDnsDiscoveryDnssecPolicy.EvaluateAdnOnlySvcbResolution(
                EncryptedDnsDiscoveryDnssecValidationStatus.NotEvaluated);

        Assert.Equal(EncryptedDnsDiscoveryAdnOnlySvcbResolutionStatus.Rejected, status);
    }
}

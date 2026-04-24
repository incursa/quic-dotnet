namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9-0004")]
public sealed class REQ_QUIC_RFC9000_S9_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ChangedPeerAddressStartsPathValidationBeforePromotion()
    {
        QuicPathMigrationRecoveryTestSupport.AssertChangedPeerAddressStartsPathValidationBeforePromotion(
            activePath: new("203.0.113.140", RemotePort: 443),
            changedPeerAddressPath: new("203.0.113.141", RemotePort: 443),
            observedAtTicks: 20);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PreviouslyValidatedPeerAddressBypassesAnotherValidationChallenge()
    {
        QuicPathMigrationRecoveryTestSupport.AssertPreviouslyValidatedPeerAddressBypassesAnotherValidationChallenge(
            activePath: new("203.0.113.142", RemotePort: 443),
            firstValidatedPath: new("203.0.113.143", RemotePort: 443),
            secondValidatedPath: new("203.0.113.144", RemotePort: 443));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzChangedPeerAddresses_StartValidationAcrossSampledAddresses()
    {
        for (int index = 0; index < 6; index++)
        {
            QuicPathMigrationRecoveryTestSupport.AssertChangedPeerAddressStartsPathValidationBeforePromotion(
                activePath: new($"198.51.100.{20 + index}", RemotePort: 443),
                changedPeerAddressPath: new($"203.0.113.{20 + index}", RemotePort: 443 + index),
                observedAtTicks: 20 + index);
        }
    }
}

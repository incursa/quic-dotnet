namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2-0003")]
public sealed class REQ_QUIC_RFC9000_S13P4P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0003")]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_TracksMatchingEcnCountsForEct0Packets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 2,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(2, 0, 0),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0003")]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenECT0CountsAreMissingForAcknowledgedPackets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0);
    }
}

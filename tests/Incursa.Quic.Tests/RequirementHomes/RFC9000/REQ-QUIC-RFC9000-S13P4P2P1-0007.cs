namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P1_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenReportedEct0CountExceedsSentEct0Packets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 1);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(2, 1, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenReportedEct1CountExceedsSentEct1Packets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 1);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(1, 2, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1);
    }
}

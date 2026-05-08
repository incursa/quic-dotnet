namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2-0006")]
public sealed class REQ_QUIC_RFC9000_S13P4P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_UsesReportedEct1CountsForEct1MarkedPackets()
    {
        QuicEcnValidationState acceptedState = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 0,
            sentEct1Count: 2);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            acceptedState,
            reportedCounts: new QuicEcnCounts(0, 2, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2);

        QuicEcnValidationState rejectedState = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 0,
            sentEct1Count: 2);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            rejectedState,
            reportedCounts: new QuicEcnCounts(2, 0, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2);
    }
}

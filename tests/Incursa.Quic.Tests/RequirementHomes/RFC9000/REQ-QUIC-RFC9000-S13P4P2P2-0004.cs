namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0004")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P2_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_AllowsSubsequentEctUseAfterSuccessfulValidation()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0);

        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect1);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(1, 1, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 1);
    }
}

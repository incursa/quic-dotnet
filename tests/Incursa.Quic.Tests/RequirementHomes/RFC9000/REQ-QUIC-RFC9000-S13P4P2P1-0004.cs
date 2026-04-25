namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0004")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P1_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenEct0AndCeIncreaseIsTooSmall()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 2,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryValidateAcknowledgedEcnCounts_AcceptsEct0PacketsReportedAsCe()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 2,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(1, 0, 1),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0);
    }
}

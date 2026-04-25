namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0005")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P1_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenEct1AndCeIncreaseIsTooSmall()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 0,
            sentEct1Count: 2);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(0, 1, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryValidateAcknowledgedEcnCounts_AcceptsEct1PacketsReportedAsCe()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 0,
            sentEct1Count: 2);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(0, 1, 1),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2);
    }
}

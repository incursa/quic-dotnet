namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0002">Provisional registrations MUST undergo Expert Review, as defined in Section 4.5 of [RFC8126].</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0002")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ProvisionalRegistrations_UseRfc8126ExpertReview()
    {
        Assert.Equal(
            QuicIanaRegistrationReviewPolicy.ExpertReview,
            QuicIanaRegistrationPolicy.ProvisionalReviewPolicy);
        Assert.Equal("RFC8126 Section 4.5", QuicIanaRegistrationPolicy.Rfc8126ExpertReviewReference);
    }
}

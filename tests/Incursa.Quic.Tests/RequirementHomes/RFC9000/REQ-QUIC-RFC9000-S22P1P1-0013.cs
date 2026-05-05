namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0013">Provisional registrations MAY omit the Specification and Notes fields, plus any additional fields that might be required for a permanent registration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0013")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ProvisionalRegistrations_MayOmitSpecificationAndNotesFields()
    {
        Assert.Equal(
            [QuicIanaRegistrationFieldKind.Specification, QuicIanaRegistrationFieldKind.Notes],
            QuicIanaRegistrationPolicy.ProvisionalOmissibleFields);

        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Value,
            QuicIanaRegistrationPolicy.ProvisionalOmissibleFields);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Contact,
            QuicIanaRegistrationPolicy.ProvisionalOmissibleFields);
    }
}

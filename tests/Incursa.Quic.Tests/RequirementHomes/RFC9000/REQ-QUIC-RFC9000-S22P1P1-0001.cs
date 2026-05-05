namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0001">Provisional registration requests MUST require only the codepoint value and contact information.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0001")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ProvisionalRegistrationRequests_RequireOnlyCodepointValueAndContactInformation()
    {
        Assert.Equal(
            [QuicIanaRegistrationFieldKind.Value, QuicIanaRegistrationFieldKind.Contact],
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);

        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Date,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Specification,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Notes,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
    }
}

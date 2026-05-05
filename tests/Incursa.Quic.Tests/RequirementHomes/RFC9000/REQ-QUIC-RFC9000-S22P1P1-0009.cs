namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0009">The Date field MUST be the date of the last update to the registration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0009")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void DateField_IdentifiesLastUpdateDate()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.Date);

        Assert.Equal("Date", field.Name);
        Assert.Equal("The date of the last update to the registration.", field.Definition);
        Assert.True(field.RequiredForProvisionalRegistryEntry);
        Assert.False(field.RequiredForProvisionalRequest);
    }
}

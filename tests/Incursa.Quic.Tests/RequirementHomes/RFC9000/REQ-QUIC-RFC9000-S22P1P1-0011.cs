namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0011">The Contact field MUST be contact details for the registrant.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0011")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ContactField_IdentifiesRegistrantContactDetails()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.Contact);

        Assert.Equal("Contact", field.Name);
        Assert.Equal("Contact details for the registrant.", field.Definition);
        Assert.True(field.RequiredForProvisionalRequest);
        Assert.True(field.RequiredForProvisionalRegistryEntry);
    }
}

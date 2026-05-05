namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0012">The Notes field MUST be supplementary notes about the registration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0012")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void NotesField_CarriesSupplementaryRegistrationNotes()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.Notes);

        Assert.Equal("Notes", field.Name);
        Assert.Equal("Supplementary notes about the registration.", field.Definition);
        Assert.True(field.RequiredForPermanentRegistration);
        Assert.True(field.OmissibleFromProvisionalRegistration);
    }
}

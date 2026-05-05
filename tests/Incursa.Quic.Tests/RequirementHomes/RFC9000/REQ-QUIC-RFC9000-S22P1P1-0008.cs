namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0008">The Specification field MUST be a reference to a publicly available specification for the value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0008")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void SpecificationField_ReferencesPublicSpecification()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.Specification);

        Assert.Equal("Specification", field.Name);
        Assert.Equal("A reference to a publicly available specification for the value.", field.Definition);
        Assert.True(field.RequiredForPermanentRegistration);
        Assert.True(field.OmissibleFromProvisionalRegistration);
    }
}

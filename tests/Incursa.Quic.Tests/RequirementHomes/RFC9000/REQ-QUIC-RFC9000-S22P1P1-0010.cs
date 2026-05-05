namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0010">The Change Controller field MUST be the entity responsible for the definition of the registration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0010")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ChangeControllerField_IdentifiesResponsibleEntity()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.ChangeController);

        Assert.Equal("Change Controller", field.Name);
        Assert.Equal("The entity responsible for the definition of the registration.", field.Definition);
        Assert.True(field.RequiredForPermanentRegistration);
    }
}

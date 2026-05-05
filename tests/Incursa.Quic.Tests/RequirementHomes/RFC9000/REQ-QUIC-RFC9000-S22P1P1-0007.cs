namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0007">The Status field MUST be "permanent" or "provisional".</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0007")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void StatusField_AllowsOnlyPermanentOrProvisionalText()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.Status);

        Assert.Equal("Status", field.Name);
        Assert.Equal("\"permanent\" or \"provisional\".", field.Definition);
        Assert.True(QuicIanaRegistrationPolicy.IsValidStatusText("permanent"));
        Assert.True(QuicIanaRegistrationPolicy.IsValidStatusText("provisional"));
        Assert.False(QuicIanaRegistrationPolicy.IsValidStatusText("temporary"));
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0006">The Value field MUST be the assigned codepoint.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0006")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ValueField_IdentifiesTheAssignedCodepoint()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.Value);

        Assert.Equal("Value", field.Name);
        Assert.Equal("The assigned codepoint.", field.Definition);
        Assert.True(field.RequiredForPermanentRegistration);
        Assert.True(field.RequiredForProvisionalRequest);
    }
}

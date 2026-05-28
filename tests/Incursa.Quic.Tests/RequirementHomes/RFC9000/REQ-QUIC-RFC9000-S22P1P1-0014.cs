// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0014">The Date field MUST NOT be required as part of requesting a registration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0014")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void RegistrationRequests_DoNotRequireDateField()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.Date);

        Assert.False(field.RequiredForProvisionalRequest);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Date,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
    }
}

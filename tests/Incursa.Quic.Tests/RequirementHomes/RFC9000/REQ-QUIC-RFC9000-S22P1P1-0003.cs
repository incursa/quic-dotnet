// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0003">Provisional registrations MUST include a Date field that indicates when the registration was last updated.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0003")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ProvisionalRegistryEntries_IncludeDateOfLastUpdate()
    {
        QuicIanaRegistrationFieldDefinition field =
            QuicIanaRegistrationPolicy.GetRegistryField(QuicIanaRegistrationFieldKind.Date);

        Assert.Contains(
            QuicIanaRegistrationFieldKind.Date,
            QuicIanaRegistrationPolicy.ProvisionalRegistryEntryRequiredFields);
        Assert.Equal("Date", field.Name);
        Assert.Equal("The date of the last update to the registration.", field.Definition);
    }
}

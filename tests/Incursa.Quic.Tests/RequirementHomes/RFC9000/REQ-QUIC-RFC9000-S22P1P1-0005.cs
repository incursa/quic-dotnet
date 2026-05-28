// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P1-0005">All QUIC registries MUST include the following fields to support provisional registration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P1-0005")]
public sealed class REQ_QUIC_RFC9000_S22P1P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void QuicRegistries_IncludeAllProvisionalSupportFields()
    {
        Assert.Equal(
            [
                QuicIanaRegistrationFieldKind.Value,
                QuicIanaRegistrationFieldKind.Status,
                QuicIanaRegistrationFieldKind.Specification,
                QuicIanaRegistrationFieldKind.Date,
                QuicIanaRegistrationFieldKind.ChangeController,
                QuicIanaRegistrationFieldKind.Contact,
                QuicIanaRegistrationFieldKind.Notes,
            ],
            QuicIanaRegistrationPolicy.RegistryFields.Select(field => field.Kind));
    }
}

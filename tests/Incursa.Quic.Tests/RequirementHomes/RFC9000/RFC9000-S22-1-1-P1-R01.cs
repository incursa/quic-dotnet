// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S22-1-1-P1-R01">Provisional registration requests MUST require only the codepoint value and contact information.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S22-1-1-P1-R01")]
public sealed class RFC9000_S22_1_1_P1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ProvisionalRegistrationRequests_RequireOnlyCodepointValueAndContactInformation()
    {
        Assert.Equal(
            [QuicIanaRegistrationFieldKind.Value, QuicIanaRegistrationFieldKind.Contact],
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);

        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Date,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Specification,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Notes,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
    }
}

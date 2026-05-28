// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1488">Provisional registrations MAY omit the Specification and Notes fields, plus any additional fields that might be required for a permanent registration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1488")]
public sealed class REQ_QUIC_RFC9000_1488
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-1488")]
    public void ProvisionalRegistrations_DoNotOmitValueOrContactFields()
    {
        Assert.Contains(
            QuicIanaRegistrationFieldKind.Value,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
        Assert.Contains(
            QuicIanaRegistrationFieldKind.Contact,
            QuicIanaRegistrationPolicy.ProvisionalRequestRequiredFields);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Value,
            QuicIanaRegistrationPolicy.ProvisionalOmissibleFields);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Contact,
            QuicIanaRegistrationPolicy.ProvisionalOmissibleFields);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ProvisionalRegistrations_MayOmitSpecificationAndNotesFields()
    {
        Assert.Equal(
            [QuicIanaRegistrationFieldKind.Specification, QuicIanaRegistrationFieldKind.Notes],
            QuicIanaRegistrationPolicy.ProvisionalOmissibleFields);

        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Value,
            QuicIanaRegistrationPolicy.ProvisionalOmissibleFields);
        Assert.DoesNotContain(
            QuicIanaRegistrationFieldKind.Contact,
            QuicIanaRegistrationPolicy.ProvisionalOmissibleFields);
    }
}

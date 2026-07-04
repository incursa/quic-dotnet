// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S13-4-2-2-P2-S1-R01")]
public sealed class RFC9000_S13_4_2_2_P2_S1_R01
{
    [Fact]
    [Requirement("RFC9000-S13-4-2-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_CanReenableValidationAfterAFailure()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0);

        state.ReenableEcn();

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0);
    }
}

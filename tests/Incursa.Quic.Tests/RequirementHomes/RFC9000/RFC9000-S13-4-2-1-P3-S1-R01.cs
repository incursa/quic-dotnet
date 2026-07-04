// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S13-4-2-1-P3-S1-R01")]
public sealed class RFC9000_S13_4_2_1_P3_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_AcceptsEct0IncreaseThatCoversNewlyAcknowledgedEct0Packets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 2,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(2, 0, 0),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0);
    }

    [Fact]
    [Requirement("RFC9000-S13-4-2-1-P3-S1-R01")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenEct0AndCeIncreaseIsTooSmall()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 2,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0);
    }

    [Fact]
    [Requirement("RFC9000-S13-4-2-1-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryValidateAcknowledgedEcnCounts_AcceptsEct0PacketsReportedAsCe()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 2,
            sentEct1Count: 0);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(1, 0, 1),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0);
    }
}

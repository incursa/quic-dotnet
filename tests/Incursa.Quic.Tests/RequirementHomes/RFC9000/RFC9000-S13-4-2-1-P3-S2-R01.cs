// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S13-4-2-1-P3-S2-R01")]
public sealed class RFC9000_S13_4_2_1_P3_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_AcceptsEct1IncreaseThatCoversNewlyAcknowledgedEct1Packets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 0,
            sentEct1Count: 2);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(0, 2, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2);
    }

    [Fact]
    [Requirement("RFC9000-S13-4-2-1-P3-S2-R01")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenEct1AndCeIncreaseIsTooSmall()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 0,
            sentEct1Count: 2);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(0, 1, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2);
    }

    [Fact]
    [Requirement("RFC9000-S13-4-2-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryValidateAcknowledgedEcnCounts_AcceptsEct1PacketsReportedAsCe()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 0,
            sentEct1Count: 2);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(0, 1, 1),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2);
    }
}

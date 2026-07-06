// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_AllowsMatchingCountsWithinSentTotals()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 1);

        QuicEcnValidationTestSupport.AssertValidationSuccess(
            state,
            new QuicEcnCounts(1, 1, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenReportedEct0CountExceedsSentEct0Packets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 1);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(2, 1, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenReportedEct1CountExceedsSentEct1Packets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 1);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(1, 2, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryValidateAcknowledgedEcnCounts_FuzzFailsWhenReportedCountsExceedSentTotals()
    {
        for (ulong sentEct0Count = 1; sentEct0Count <= 3; sentEct0Count++)
        {
            QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
                sentEct0Count,
                sentEct1Count: 1);

            QuicEcnValidationTestSupport.AssertValidationFailure(
                state,
                new QuicEcnCounts(sentEct0Count + 1, 1, 0),
                newlyAcknowledgedEct0Packets: sentEct0Count,
                newlyAcknowledgedEct1Packets: 1);
        }
    }
}

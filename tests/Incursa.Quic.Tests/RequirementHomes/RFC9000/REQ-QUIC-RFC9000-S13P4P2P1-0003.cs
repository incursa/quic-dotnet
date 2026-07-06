// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0003")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P1_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_FailsWhenReportedCountsStayZeroForAckedEctPackets()
    {
        QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
            sentEct0Count: 1,
            sentEct1Count: 1);

        QuicEcnValidationTestSupport.AssertValidationFailure(
            state,
            new QuicEcnCounts(0, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0003")]
    [Requirement("RFC9000-S13-4-2-2-P2-S1-R01")]
    [Requirement("RFC9000-S13-4-2-2-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void EcnValidationFuzz_DetectsZeroedOrMissingReportsAndAllowsLaterRevalidation()
    {
        foreach (QuicEcnCounts? invalidReportedCounts in new QuicEcnCounts?[]
        {
            null,
            new QuicEcnCounts(0, 0, 0),
            new QuicEcnCounts(1, 0, 0),
            new QuicEcnCounts(0, 1, 0),
        })
        {
            QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
                sentEct0Count: 1,
                sentEct1Count: 1);

            QuicEcnValidationTestSupport.AssertValidationFailure(
                state,
                invalidReportedCounts,
                newlyAcknowledgedEct0Packets: 1,
                newlyAcknowledgedEct1Packets: 1);

            state.ReenableEcn();

            QuicEcnValidationTestSupport.AssertValidationSuccess(
                state,
                new QuicEcnCounts(1, 1, 0),
                newlyAcknowledgedEct0Packets: 1,
                newlyAcknowledgedEct1Packets: 1);

            state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);

            QuicEcnValidationTestSupport.AssertValidationFailure(
                state,
                new QuicEcnCounts(1, 1, 0),
                newlyAcknowledgedEct0Packets: 1,
                newlyAcknowledgedEct1Packets: 0);
        }
    }
}

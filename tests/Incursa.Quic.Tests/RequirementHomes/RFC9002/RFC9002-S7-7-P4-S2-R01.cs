// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S7-7-P4-S2-R01">Packets containing only ACK frames SHOULD therefore not be paced.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S7-7-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9002_S7P7_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryComputePacingIntervalMicros_DoesNotPaceAckOnlyPackets()
    {
        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: true,
            out ulong pacingIntervalMicros));

        Assert.Equal(0UL, pacingIntervalMicros);
    }
}

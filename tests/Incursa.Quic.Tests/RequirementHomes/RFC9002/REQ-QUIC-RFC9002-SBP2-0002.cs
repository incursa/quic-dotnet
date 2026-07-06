// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP2-0002">bytes_in_flight MUST count sent packets that contain at least one ack-eliciting or PADDING frame and have not been acknowledged or declared lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP2-0002")]
public sealed class REQ_QUIC_RFC9002_SBP2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RegisterPacketSent_CountsEligiblePacketsTowardBytesInFlight()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200);

        Assert.Equal(1_200UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RegisterPacketSent_DoesNotCountAckOnlyPacketsTowardBytesInFlight()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200, isAckOnlyPacket: true);

        Assert.Equal(0UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryRegisterAcknowledgedPacket_RemovesEligiblePacketsFromBytesInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            applicationLimited: true));

        Assert.Equal(0UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryRegisterLoss_RemovesEligiblePacketsFromBytesInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.Equal(0UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_BytesInFlightTracksOnlyUnresolvedEligiblePacketsAcrossMixedSequences()
    {
        foreach ((ulong firstEligibleBytes, ulong ackOnlyBytes, ulong secondEligibleBytes, bool resolveFirstByAck) in new[]
        {
            (400UL, 91UL, 250UL, true),
            (1_200UL, 64UL, 300UL, false),
            (2_048UL, 512UL, 1_024UL, true),
            (3_000UL, 1UL, 700UL, false),
        })
        {
            QuicCongestionControlState state = new();

            state.RegisterPacketSent(firstEligibleBytes);
            Assert.Equal(firstEligibleBytes, state.BytesInFlightBytes);

            state.RegisterPacketSent(ackOnlyBytes, isAckOnlyPacket: true);
            Assert.Equal(firstEligibleBytes, state.BytesInFlightBytes);

            state.RegisterPacketSent(secondEligibleBytes);
            Assert.Equal(firstEligibleBytes + secondEligibleBytes, state.BytesInFlightBytes);

            if (resolveFirstByAck)
            {
                Assert.True(state.TryRegisterAcknowledgedPacket(
                    firstEligibleBytes,
                    sentAtMicros: 1_000,
                    packetInFlight: true,
                    applicationLimited: true));
            }
            else
            {
                Assert.True(state.TryRegisterLoss(
                    firstEligibleBytes,
                    sentAtMicros: 1_000,
                    packetInFlight: true));
            }

            Assert.Equal(secondEligibleBytes, state.BytesInFlightBytes);

            Assert.True(state.TryRegisterLoss(
                secondEligibleBytes,
                sentAtMicros: 2_000,
                packetInFlight: true));
            Assert.Equal(0UL, state.BytesInFlightBytes);
        }
    }
}

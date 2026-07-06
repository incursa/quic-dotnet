// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S6_4_S7_2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S6-4-P1-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DiscardingInitialOrHandshakePacketsRemovesThemFromBytesInFlight()
    {
        foreach ((QuicPacketNumberSpace discardedSpace, QuicTlsEncryptionLevel encryptionLevel, ulong discardedPacketNumber, ulong discardedPayloadBytes) in new[]
        {
            (QuicPacketNumberSpace.Initial, QuicTlsEncryptionLevel.Initial, 1UL, 1UL),
            (QuicPacketNumberSpace.Initial, QuicTlsEncryptionLevel.Initial, 2UL, 1_200UL),
            (QuicPacketNumberSpace.Handshake, QuicTlsEncryptionLevel.Handshake, 3UL, 1_472UL),
            (QuicPacketNumberSpace.Handshake, QuicTlsEncryptionLevel.Handshake, 4UL, 3_000UL),
        })
        {
            QuicConnectionSendRuntime runtime = new();
            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                discardedSpace,
                discardedPacketNumber,
                PayloadBytes: discardedPayloadBytes,
                SentAtMicros: 100,
                AckEliciting: true,
                CryptoMetadata: new QuicConnectionCryptoSendMetadata(encryptionLevel),
                PacketBytes: new byte[] { 0x01 }));
            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                PacketNumber: 99,
                PayloadBytes: 1_200,
                SentAtMicros: 200,
                AckEliciting: true,
                PacketBytes: new byte[] { 0x02 }));

            Assert.Equal(discardedPayloadBytes + 1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);

            Assert.True(runtime.TryDiscardPacketNumberSpace(discardedSpace));

            Assert.Equal(1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
            Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == discardedSpace);
            Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DatagramSizeChangeCanRecomputeInitialCongestionWindow()
    {
        foreach (ulong maxDatagramSizeBytes in new[]
        {
            1UL,
            1_200UL,
            1_471UL,
            1_472UL,
            1_473UL,
            3_000UL,
            7_360UL,
            7_361UL,
        })
        {
            QuicCongestionControlState state = new(1_200);
            state.RegisterPacketSent(1_200);

            state.UpdateMaxDatagramSize(maxDatagramSizeBytes, resetToInitialWindow: true);

            Assert.Equal(maxDatagramSizeBytes, state.MaxDatagramSizeBytes);
            Assert.Equal(
                QuicCongestionControlState.ComputeInitialCongestionWindowBytes(maxDatagramSizeBytes),
                state.CongestionWindowBytes);
            Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
            Assert.False(state.HasRecoveryStartTime);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-2-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeMtuReductionResetsToTheNewInitialCongestionWindow()
    {
        foreach (ulong reducedMaxDatagramSizeBytes in new[]
        {
            1UL,
            1_200UL,
            1_471UL,
            1_472UL,
        })
        {
            QuicCongestionControlState state = new(3_000);
            state.RegisterPacketSent(3_000);

            state.UpdateMaxDatagramSize(reducedMaxDatagramSizeBytes, resetToInitialWindow: true);

            Assert.Equal(reducedMaxDatagramSizeBytes, state.MaxDatagramSizeBytes);
            Assert.Equal(
                QuicCongestionControlState.ComputeInitialCongestionWindowBytes(reducedMaxDatagramSizeBytes),
                state.CongestionWindowBytes);
            Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
            Assert.False(state.HasRecoveryStartTime);
        }
    }

    [Fact]
    [Requirement("RFC9002-S7-2-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MinimumCongestionWindowUsesTwoNormalizedDatagrams()
    {
        foreach ((ulong maxDatagramSizeBytes, ulong expectedMinimumCongestionWindowBytes) in new[]
        {
            (1UL, 2_400UL),
            (1_199UL, 2_400UL),
            (1_200UL, 2_400UL),
            (1_471UL, 2_942UL),
            (1_472UL, 2_944UL),
            (3_000UL, 6_000UL),
            (ulong.MaxValue / 2UL, ulong.MaxValue - 1UL),
            (ulong.MaxValue, ulong.MaxValue),
        })
        {
            Assert.Equal(
                expectedMinimumCongestionWindowBytes,
                QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(maxDatagramSizeBytes));
        }
    }
}

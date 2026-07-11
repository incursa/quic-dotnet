// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP5_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP5-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TrackSentPacketStoresRepresentativePacketMetadata()
    {
        foreach (QuicConnectionSentPacket packet in RepresentativeSentPackets())
        {
            QuicConnectionSendRuntime runtime = new();

            runtime.TrackSentPacket(packet);

            if (packet.AckOnlyPacket)
            {
                Assert.Empty(runtime.SentPackets);
                Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
                continue;
            }

            QuicConnectionSentPacket stored = Assert.Single(runtime.SentPackets).Value;
            Assert.Equal(packet.PacketNumberSpace, stored.PacketNumberSpace);
            Assert.Equal(packet.PacketNumber, stored.PacketNumber);
            Assert.Equal(packet.PayloadBytes, stored.PayloadBytes);
            Assert.Equal(packet.SentAtMicros, stored.SentAtMicros);
            Assert.Equal(packet.AckEliciting, stored.AckEliciting);
            Assert.Equal(packet.AckOnlyPacket, stored.AckOnlyPacket);

            Assert.Equal(packet.PayloadBytes, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP5-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckElicitingSendsRefreshTheFirstPostPeerActivitySendTime()
    {
        foreach ((ulong timeoutMicros, ulong peerPacketAtMicros, ulong firstSendAtMicros, ulong secondSendAtMicros) in new[]
        {
            (100UL, 10UL, 20UL, 30UL),
            (1_000UL, 250UL, 375UL, 999UL),
            (10_000UL, 8_000UL, 9_000UL, 9_500UL),
        })
        {
            QuicIdleTimeoutState state = new(timeoutMicros);
            state.RecordPeerPacketProcessed(peerPacketAtMicros);

            state.RecordAckElicitingPacketSent(firstSendAtMicros);

            Assert.Equal(firstSendAtMicros, state.IdleTimerRestartAtMicros);
            Assert.Equal(firstSendAtMicros + timeoutMicros, state.IdleTimeoutDeadlineMicros);
            Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

            state.RecordAckElicitingPacketSent(secondSendAtMicros);

            Assert.Equal(firstSendAtMicros, state.IdleTimerRestartAtMicros);
            Assert.Equal(firstSendAtMicros + timeoutMicros, state.IdleTimeoutDeadlineMicros);
            Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

            ulong nextPeerPacketAtMicros = secondSendAtMicros + 1;
            ulong nextSendAtMicros = nextPeerPacketAtMicros + 1;
            state.RecordPeerPacketProcessed(nextPeerPacketAtMicros);
            state.RecordAckElicitingPacketSent(nextSendAtMicros);

            Assert.Equal(nextSendAtMicros, state.IdleTimerRestartAtMicros);
            Assert.Equal(nextSendAtMicros + timeoutMicros, state.IdleTimeoutDeadlineMicros);
            Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP5-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InFlightAckElicitingSendsAccountBytesAndRefreshLossDetectionTimer()
    {
        foreach ((QuicPacketNumberSpace packetNumberSpace, ulong sentBytes, ulong sentAtMicros) in new[]
        {
            (QuicPacketNumberSpace.Initial, 1_200UL, 1_000UL),
            (QuicPacketNumberSpace.Handshake, 1_350UL, 2_000UL),
            (QuicPacketNumberSpace.ApplicationData, 4_096UL, 3_000UL),
        })
        {
            QuicConnectionSendRuntime runtime = new();
            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                packetNumberSpace,
                PacketNumber: 1,
                PayloadBytes: sentBytes,
                SentAtMicros: sentAtMicros,
                AckEliciting: true));

            Assert.Equal(sentBytes, runtime.FlowController.CongestionControlState.BytesInFlightBytes);

            Assert.True(runtime.TryArmProbeTimeout(
                packetNumberSpace,
                nowMicros: sentAtMicros,
                smoothedRttMicros: 2_500,
                rttVarMicros: 1_250,
                maxAckDelayMicros: 25,
                handshakeConfirmed: true));
            Assert.True(runtime.TryArmProbeTimeout(
                packetNumberSpace,
                nowMicros: sentAtMicros,
                smoothedRttMicros: 2_500,
                rttVarMicros: 1_250,
                maxAckDelayMicros: 25,
                handshakeConfirmed: true));
            Assert.Equal(2, runtime.ProbeTimeoutCount);
            Assert.NotNull(runtime.LossDetectionDeadlineMicros);

            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                packetNumberSpace,
                PacketNumber: 2,
                PayloadBytes: sentBytes + 1,
                SentAtMicros: sentAtMicros + 1,
                AckEliciting: true));

            Assert.Equal((sentBytes * 2) + 1, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
            Assert.Equal(0, runtime.ProbeTimeoutCount);
            Assert.Null(runtime.LossDetectionDeadlineMicros);
            Assert.True(runtime.TryArmProbeTimeout(
                packetNumberSpace,
                nowMicros: sentAtMicros + 1,
                smoothedRttMicros: 2_500,
                rttVarMicros: 1_250,
                maxAckDelayMicros: 25,
                handshakeConfirmed: true));
            Assert.Equal(1, runtime.ProbeTimeoutCount);
            Assert.NotNull(runtime.LossDetectionDeadlineMicros);
        }
    }

    private static QuicConnectionSentPacket[] RepresentativeSentPackets()
    {
        return
        [
            new QuicConnectionSentPacket(
                QuicPacketNumberSpace.Initial,
                PacketNumber: 1,
                PayloadBytes: 1_200,
                SentAtMicros: 1_000,
                AckEliciting: true),
            new QuicConnectionSentPacket(
                QuicPacketNumberSpace.Handshake,
                PacketNumber: 9,
                PayloadBytes: 0,
                SentAtMicros: 2_000,
                AckEliciting: false,
                AckOnlyPacket: true),
            new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                PacketNumber: 255,
                PayloadBytes: 4_096,
                SentAtMicros: 3_000,
                AckEliciting: true),
        ];
    }
}

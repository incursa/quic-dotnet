// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-2-1-P8-S1-R01">A sender SHOULD restart its PTO timer every time an ack-eliciting packet is sent or acknowledged, or when Initial or Handshake keys are discarded.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-2-1-P8-S1-R01")]
public sealed class RFC9002_S6_2_1_P8_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryArmProbeTimeout_RestartsThePtoAfterAnAckElicitingSend()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.Equal(15_000UL, runtime.LossDetectionDeadlineMicros);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcknowledgePacket_RestartsThePtoAfterAnAcknowledgment()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));
        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.Equal(15_000UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_RestartsThePtoAfterInitialKeysAreDiscarded()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial)));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.Equal(15_000UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RestartsProbeTimeoutBackoffAfterSendAcknowledgmentAndKeyDiscardTriggers()
    {
        foreach ((string trigger, QuicPacketNumberSpace packetNumberSpace, ulong smoothedRttMicros, ulong rttVarMicros, ulong maxAckDelayMicros, bool handshakeConfirmed) in new[]
        {
            ("send", QuicPacketNumberSpace.ApplicationData, 1_000UL, 250UL, 0UL, true),
            ("ack", QuicPacketNumberSpace.ApplicationData, 2_500UL, 1_250UL, 25_000UL, true),
            ("discard", QuicPacketNumberSpace.Initial, 3_000UL, 500UL, 0UL, false),
            ("discard", QuicPacketNumberSpace.Handshake, 4_000UL, 1_000UL, 0UL, false),
        })
        {
            QuicConnectionSendRuntime runtime = new();
            QuicTlsEncryptionLevel? cryptoLevel = packetNumberSpace switch
            {
                QuicPacketNumberSpace.Initial => QuicTlsEncryptionLevel.Initial,
                QuicPacketNumberSpace.Handshake => QuicTlsEncryptionLevel.Handshake,
                _ => null,
            };

            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                packetNumberSpace,
                PacketNumber: 7,
                PayloadBytes: 1_200,
                SentAtMicros: 0,
                AckEliciting: true,
                CryptoMetadata: cryptoLevel.HasValue
                    ? new QuicConnectionCryptoSendMetadata(cryptoLevel.Value)
                    : null));
            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                packetNumberSpace,
                PacketNumber: 8,
                PayloadBytes: 1_200,
                SentAtMicros: 0,
                AckEliciting: true,
                CryptoMetadata: cryptoLevel.HasValue
                    ? new QuicConnectionCryptoSendMetadata(cryptoLevel.Value)
                    : null));

            Assert.True(runtime.TryArmProbeTimeout(
                packetNumberSpace,
                nowMicros: 10,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                handshakeConfirmed));
            Assert.True(runtime.TryArmProbeTimeout(
                packetNumberSpace,
                nowMicros: 10,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                handshakeConfirmed));
            Assert.Equal(2, runtime.ProbeTimeoutCount);
            Assert.NotNull(runtime.LossDetectionDeadlineMicros);

            switch (trigger)
            {
                case "send":
                    runtime.TrackSentPacket(new QuicConnectionSentPacket(
                        packetNumberSpace,
                        PacketNumber: 9,
                        PayloadBytes: 1_200,
                        SentAtMicros: 11,
                        AckEliciting: true));
                    break;
                case "ack":
                    Assert.True(runtime.TryAcknowledgePacket(
                        packetNumberSpace,
                        packetNumber: 7,
                        handshakeConfirmed));
                    break;
                case "discard":
                    Assert.True(runtime.TryDiscardPacketNumberSpace(packetNumberSpace));
                    break;
            }

            Assert.Equal(0, runtime.ProbeTimeoutCount);
            Assert.Null(runtime.LossDetectionDeadlineMicros);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrackSentPacket_DoesNotRestartThePtoForNonAckElicitingPackets()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));
        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.Equal(15_000UL, runtime.LossDetectionDeadlineMicros);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 64,
            SentAtMicros: 0,
            AckEliciting: false));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.Equal(15_000UL, runtime.LossDetectionDeadlineMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryArmProbeTimeout_PreservesAZeroBackoffWhenRestarted()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
    }
}

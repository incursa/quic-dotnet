// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P3-0001")]
public sealed class REQ_QUIC_RFC9000_S14P3_0001
{
    [Theory]
    [InlineData("203.0.113.10", 65_527UL, 1_472UL)]
    [InlineData("2001:db8::10", 65_527UL, 1_452UL)]
    [InlineData("quic.example", 65_527UL, 1_452UL)]
    [InlineData("203.0.113.10", 1_300UL, 1_300UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void GetPathMtuProbeSize_UsesAddressFamilySafeEthernetPayloads(
        string remoteAddress,
        ulong peerMaximumUdpPayloadSize,
        ulong expectedProbeSizeBytes)
    {
        QuicConnectionPathIdentity path = new(remoteAddress, RemotePort: 443);

        Assert.Equal(
            expectedProbeSizeBytes,
            QuicConnectionRuntime.GetPathMtuProbeSize(path, peerMaximumUdpPayloadSize));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandshakeCompletion_DoesNotProbeBeforeApplicationStreamDataIsAcknowledged()
    {
        using QuicConnectionRuntime runtime =
            QuicS19P20HandshakeDoneTestSupport.CreateServerRuntimeReadyToEvaluateHandshakeDoneSend();

        _ = QuicS19P20HandshakeDoneTestSupport.CompletePeerHandshakeTranscript(
            runtime,
            observedAtTicks: 1);
        QuicConnectionTransitionResult second = QuicS19P20HandshakeDoneTestSupport.CompletePeerHandshakeTranscript(
            runtime,
            observedAtTicks: 2);

        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket);
        Assert.Equal(
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes,
            runtime.ActivePath?.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.DoesNotContain(second.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AcknowledgedPathMtuProbe_RaisesTheActivePathOrdinaryCeiling()
    {
        using QuicConnectionRuntime runtime =
            QuicS19P20HandshakeDoneTestSupport.CreateServerRuntimeReadyToEvaluateHandshakeDoneSend();
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: QuicS9P3TokenEmissionTestSupport.CreateOneRttMaterial())));
        _ = QuicS19P20HandshakeDoneTestSupport.CompletePeerHandshakeTranscript(runtime, observedAtTicks: 1);

        runtime.TrackApplicationPacket(
            packetNumber: 10,
            protectedPacket: new byte[100],
            streamId: 0);

        byte[] destinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        QuicHandshakeFlowCoordinator peerCoordinator = new(destinationConnectionId);
        Assert.True(peerCoordinator.TrySetDestinationConnectionId(destinationConnectionId));
        byte[] streamAckPayload = QuicFrameTestData.BuildAckFrame(
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(packetNumber: 10));
        byte[] protectedStreamAck = CreateProtectedPeerPacket(runtime, peerCoordinator, streamAckPayload);
        QuicConnectionTransitionResult probeResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                QuicS19P20HandshakeDoneTestSupport.PacketPathIdentity,
                protectedStreamAck),
            nowTicks: 2);

        Assert.True(probeResult.StateChanged);
        Assert.DoesNotContain(
            probeResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => effect.Datagram.Length == 1_472);
        AcknowledgeOutstandingApplicationPackets(runtime, peerCoordinator, startingObservedAtTicks: 3);
        long probeDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathMtuProbe)!.Value;
        ulong probeTimerGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathMtuProbe);
        QuicConnectionTransitionResult probeSendResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                probeDueTicks,
                QuicConnectionTimerKind.PathMtuProbe,
                probeTimerGeneration),
            nowTicks: probeDueTicks);
        QuicConnectionSendDatagramEffect probeSendEffect = Assert.Single(
            probeSendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(1_472, probeSendEffect.Datagram.Length);
        byte[] openedProbePayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(
            runtime,
            probeSendEffect);
        Assert.True(QuicFrameCodec.TryParsePingFrame(openedProbePayload, out int pingBytesConsumed));
        Assert.All(openedProbePayload[pingBytesConsumed..], paddingByte => Assert.Equal(0, paddingByte));
        QuicConnectionSentPacket probe = Assert.Single(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket && packet.PacketBytes.Length == 1_472);
        Assert.True(probe.AckEliciting);
        Assert.False(probe.Retransmittable);
        Assert.Equal(
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes,
            runtime.ActivePath?.MaximumDatagramSizeState.MaximumDatagramSizeBytes);

        byte[] ackPayload = QuicFrameTestData.BuildAckFrame(
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(probe.PacketNumber));
        byte[] protectedAck = CreateProtectedPeerPacket(runtime, peerCoordinator, ackPayload);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 4,
                QuicS19P20HandshakeDoneTestSupport.PacketPathIdentity,
                protectedAck),
            nowTicks: 4);

        Assert.True(result.StateChanged);
        Assert.Equal(1_472UL, runtime.ActivePath?.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumber == probe.PacketNumber);
    }

    private static byte[] CreateProtectedPeerPacket(
        QuicConnectionRuntime runtime,
        QuicHandshakeFlowCoordinator peerCoordinator,
        ReadOnlySpan<byte> payload)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    private static void AcknowledgeOutstandingApplicationPackets(
        QuicConnectionRuntime runtime,
        QuicHandshakeFlowCoordinator peerCoordinator,
        long startingObservedAtTicks)
    {
        long observedAtTicks = startingObservedAtTicks;
        for (int iteration = 0; iteration < 16; iteration++)
        {
            KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket>[] outstandingPackets = runtime
                .SendRuntime
                .SentPackets
                .Where(entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                    && entry.Value.AckEliciting)
                .ToArray();
            if (outstandingPackets.Length == 0)
            {
                return;
            }

            foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> outstandingPacket in outstandingPackets)
            {
                byte[] ackPayload = QuicFrameTestData.BuildAckFrame(
                    QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(outstandingPacket.Key.PacketNumber));
                byte[] protectedAck = CreateProtectedPeerPacket(runtime, peerCoordinator, ackPayload);
                _ = runtime.Transition(
                    new QuicConnectionPacketReceivedEvent(
                        observedAtTicks,
                        QuicS19P20HandshakeDoneTestSupport.PacketPathIdentity,
                        protectedAck),
                    nowTicks: observedAtTicks);
                observedAtTicks++;
            }
        }

        Assert.Fail("The runtime did not drain its outstanding application packets before the PMTU probe timer test.");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterProbeAcknowledged_RaisesTheDplpmtudMaximumPacketSize()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.10", "192.0.2.10", 443, 55555);

        Assert.True(state.TryTrackProbe(path, packetNumber: 10, probeSizeBytes: 1_300));
        Assert.True(state.TryRegisterProbeAcknowledged(path, packetNumber: 10));

        QuicDplpmtudPathSnapshot snapshot = state.GetPathSnapshot(path);
        Assert.Equal(1_300UL, snapshot.MaximumPacketSizeBytes);
        Assert.Equal(QuicDplpmtudProbeOutcome.Acknowledged, snapshot.LastProbeOutcome);
        Assert.Equal(10UL, snapshot.LastProbePacketNumber);
        Assert.Equal(0, snapshot.OutstandingProbeCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterProbeLost_TracksLossWithoutRaisingTheMaximumPacketSize()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.10", "192.0.2.10", 443, 55555);

        Assert.True(state.TryTrackProbe(path, packetNumber: 10, probeSizeBytes: 1_300));
        Assert.True(state.TryRegisterProbeLost(path, packetNumber: 10));

        QuicDplpmtudPathSnapshot snapshot = state.GetPathSnapshot(path);
        Assert.Equal(QuicDplpmtudState.BasePlpmtuBytes, snapshot.MaximumPacketSizeBytes);
        Assert.Equal(QuicDplpmtudProbeOutcome.Lost, snapshot.LastProbeOutcome);
        Assert.Equal(10UL, snapshot.LastProbePacketNumber);
        Assert.Equal(0, snapshot.OutstandingProbeCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterProbeAcknowledged_IgnoresUntrackedPacketNumbers()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.10", "192.0.2.10", 443, 55555);

        Assert.False(state.TryRegisterProbeAcknowledged(path, packetNumber: 10));

        QuicDplpmtudPathSnapshot snapshot = state.GetPathSnapshot(path);
        Assert.Equal(QuicDplpmtudState.BasePlpmtuBytes, snapshot.MaximumPacketSizeBytes);
        Assert.Equal(QuicDplpmtudProbeOutcome.None, snapshot.LastProbeOutcome);
    }
}

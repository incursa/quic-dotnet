using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P2-0004">An endpoint MAY treat an acknowledgment carried in an old-key packet that acknowledges a newer-key packet as a connection error of type KEY_UPDATE_ERROR.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P2-0004")]
public sealed class REQ_QUIC_RFC9001_S6P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeRejectsOldKeyAckPacketsThatAcknowledgeNewerKeyPackets()
    {
        AssertRuntimeRejectsOldKeyAckPacketsThatAcknowledgeNewerKeyPackets(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeRejectsOldKeyAckPacketsThatAcknowledgeNewerKeyPackets()
    {
        AssertRuntimeRejectsOldKeyAckPacketsThatAcknowledgeNewerKeyPackets(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeAllowsOldKeyAckPacketsThatOnlyAcknowledgeOldKeyPackets()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> oldKeyPacket = ReceiveApplicationPacketAndGetTrackedResponsePacket(
            runtime,
            peerCoordinator,
            currentOpenMaterial,
            keyPhase: false,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            observedAtTicks: 1);
        Assert.Equal(0U, oldKeyPacket.Value.OneRttKeyPhase);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicTlsPacketProtectionMaterial retainedOldOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> newerKeyPacket = ReceiveApplicationPacketAndGetTrackedResponsePacket(
            runtime,
            peerCoordinator,
            retainedOldOpenMaterial,
            keyPhase: false,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            observedAtTicks: 10);
        Assert.Equal(1U, newerKeyPacket.Value.OneRttKeyPhase);

        byte[] oldKeyAckPacket = BuildProtectedApplicationPacket(
            retainedOldOpenMaterial,
            keyPhase: false,
            CreateAckPayload(oldKeyPacket.Key.PacketNumber));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                oldKeyAckPacket),
            nowTicks: 20);

        Assert.False(result.Effects.OfType<QuicConnectionNotifyStreamsOfTerminalStateEffect>().Any());
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
        Assert.False(runtime.SendRuntime.SentPackets.ContainsKey(oldKeyPacket.Key));
        Assert.True(runtime.SendRuntime.SentPackets.ContainsKey(newerKeyPacket.Key));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeRejectsOldPhaseTwoAckPacketsThatAcknowledgePhaseThreePackets()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

        QuicConnectionSentPacketKey currentPhasePacketKey = new(
            QuicPacketNumberSpace.ApplicationData,
            90);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            currentPhasePacketKey.PacketNumber,
            sentAtMicros: 900,
            keyPhase: runtime.TlsState.CurrentOneRttKeyPhase);

        QuicTlsPacketProtectionMaterial retainedPhaseTwoOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        byte[] oldKeyAckPacket = BuildProtectedApplicationPacket(
            retainedPhaseTwoOpenMaterial,
            keyPhase: false,
            CreateAckPayload(currentPhasePacketKey.PacketNumber));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 70_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                oldKeyAckPacket),
            nowTicks: 70_000);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(
            "The peer acknowledged a newer-key packet in an old-key packet.",
            runtime.TerminalState?.Close.ReasonPhrase);
        Assert.True(runtime.SendRuntime.SentPackets.ContainsKey(currentPhasePacketKey));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeAllowsOldPhaseTwoAckPacketsThatOnlyAcknowledgePhaseTwoPackets()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

        QuicConnectionSentPacketKey oldPhasePacketKey = new(
            QuicPacketNumberSpace.ApplicationData,
            91);
        QuicConnectionSentPacketKey currentPhasePacketKey = new(
            QuicPacketNumberSpace.ApplicationData,
            92);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            oldPhasePacketKey.PacketNumber,
            sentAtMicros: 910,
            keyPhase: 2);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            currentPhasePacketKey.PacketNumber,
            sentAtMicros: 920,
            keyPhase: runtime.TlsState.CurrentOneRttKeyPhase);

        QuicTlsPacketProtectionMaterial retainedPhaseTwoOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        byte[] oldKeyAckPacket = BuildProtectedApplicationPacket(
            retainedPhaseTwoOpenMaterial,
            keyPhase: false,
            CreateAckPayload(oldPhasePacketKey.PacketNumber));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 80_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                oldKeyAckPacket),
            nowTicks: 80_000);

        Assert.False(result.Effects.OfType<QuicConnectionNotifyStreamsOfTerminalStateEffect>().Any());
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
        Assert.False(runtime.SendRuntime.SentPackets.ContainsKey(oldPhasePacketKey));
        Assert.True(runtime.SendRuntime.SentPackets.ContainsKey(currentPhasePacketKey));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzOldKeyAckPacketsThatAcknowledgeNewerKeyPackets_RaiseKeyUpdateErrorAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6204));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
            QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

            QuicTlsPacketProtectionMaterial currentOpenMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
            _ = ReceiveApplicationPacketAndGetTrackedResponsePacket(
                runtime,
                peerCoordinator,
                currentOpenMaterial,
                keyPhase: false,
                CreateAckElicitingPayload(random.Next(1, 96)),
                observedAtTicks: iteration * 30 + 1);

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
            QuicTlsPacketProtectionMaterial retainedOldOpenMaterial =
                runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
            KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> newerKeyPacket = ReceiveApplicationPacketAndGetTrackedResponsePacket(
                runtime,
                peerCoordinator,
                retainedOldOpenMaterial,
                keyPhase: false,
                CreateAckElicitingPayload(random.Next(1, 96)),
                observedAtTicks: iteration * 30 + 10);

            byte[] oldKeyAckPacket = BuildProtectedApplicationPacket(
                retainedOldOpenMaterial,
                keyPhase: false,
                CreateAckPayload(
                    newerKeyPacket.Key.PacketNumber,
                    ackDelay: (ulong)random.Next(0, 64)));

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: iteration * 30 + 20,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    oldKeyAckPacket),
                nowTicks: iteration * 30 + 20);

            Assert.True(result.StateChanged);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TerminalState?.Close.TransportErrorCode);
            Assert.Equal(
                "The peer acknowledged a newer-key packet in an old-key packet.",
                runtime.TerminalState?.Close.ReasonPhrase);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzOldPhaseTwoAckPacketsThatAcknowledgePhaseThreePackets_RaiseKeyUpdateErrorAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6234));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

            ulong currentPhasePacketNumber = (ulong)(120 + iteration);
            QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                runtime,
                currentPhasePacketNumber,
                sentAtMicros: (ulong)(1_200 + iteration),
                keyPhase: runtime.TlsState.CurrentOneRttKeyPhase);

            QuicTlsPacketProtectionMaterial retainedPhaseTwoOpenMaterial =
                runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
            byte[] oldKeyAckPacket = BuildProtectedApplicationPacket(
                retainedPhaseTwoOpenMaterial,
                keyPhase: false,
                CreateAckPayload(
                    currentPhasePacketNumber,
                    ackDelay: (ulong)random.Next(0, 64)));

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 90_000 + iteration,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    oldKeyAckPacket),
                nowTicks: 90_000 + iteration);

            Assert.True(result.StateChanged);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TerminalState?.Close.TransportErrorCode);
            Assert.Equal(
                "The peer acknowledged a newer-key packet in an old-key packet.",
                runtime.TerminalState?.Close.ReasonPhrase);
        }
    }

    private static void AssertRuntimeRejectsOldKeyAckPacketsThatAcknowledgeNewerKeyPackets(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);
        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicTlsPacketProtectionMaterial retainedOldOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> newerKeyPacket = ReceiveApplicationPacketAndGetTrackedResponsePacket(
            runtime,
            peerCoordinator,
            retainedOldOpenMaterial,
            keyPhase: false,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            observedAtTicks: 1);

        Assert.Equal(QuicPacketNumberSpace.ApplicationData, newerKeyPacket.Key.PacketNumberSpace);
        Assert.Equal(1U, newerKeyPacket.Value.OneRttKeyPhase);

        byte[] oldKeyAckPacket = BuildProtectedApplicationPacket(
            retainedOldOpenMaterial,
            keyPhase: false,
            CreateAckPayload(newerKeyPacket.Key.PacketNumber));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                oldKeyAckPacket),
            nowTicks: 2);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(
            "The peer acknowledged a newer-key packet in an old-key packet.",
            runtime.TerminalState?.Close.ReasonPhrase);
        Assert.Contains(result.Effects, static effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
    }

    private static KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> ReceiveApplicationPacketAndGetTrackedResponsePacket(
        QuicConnectionRuntime runtime,
        QuicHandshakeFlowCoordinator peerCoordinator,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        byte[] payload,
        long observedAtTicks)
    {
        List<QuicConnectionSendDatagramEffect> sendEffects = [];
        for (int packetIndex = 0; packetIndex < 4; packetIndex++)
        {
            byte[] protectedPacket = BuildProtectedApplicationPacket(peerCoordinator, material, keyPhase, payload);
            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: observedAtTicks + packetIndex,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: observedAtTicks + packetIndex);

            sendEffects.AddRange(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        }

        Assert.NotEmpty(sendEffects);
        QuicConnectionSendDatagramEffect responseEffect = sendEffects[^1];
        return Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(responseEffect.Datagram.Span));
    }

    private static byte[] BuildProtectedApplicationPacket(
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        byte[] payload)
    {
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            keyPhase,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    private static byte[] BuildProtectedApplicationPacket(
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        byte[] payload)
    {
        return BuildProtectedApplicationPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator(),
            material,
            keyPhase,
            payload);
    }

    private static byte[] CreateAckPayload(ulong largestAcknowledged, ulong ackDelay = 0)
    {
        byte[] payload = new byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(
            new QuicAckFrame
            {
                FrameType = 0x02,
                LargestAcknowledged = largestAcknowledged,
                AckDelay = ackDelay,
                FirstAckRange = 0,
                AdditionalRanges = [],
            },
            payload,
            out int bytesWritten));
        Assert.True(bytesWritten > 0);
        if (bytesWritten < payload.Length)
        {
            payload.AsSpan(bytesWritten).Fill(0);
        }

        return payload;
    }

    private static byte[] CreateAckElicitingPayload(int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }

    private static void MarkServerHandshakeDoneAsAlreadySent(QuicConnectionRuntime runtime)
    {
        if (runtime.TlsState.Role != QuicTlsRole.Server)
        {
            return;
        }

        FieldInfo handshakeDonePacketSentField = typeof(QuicConnectionRuntime).GetField(
            "handshakeDonePacketSent",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        handshakeDonePacketSentField.SetValue(runtime, true);
    }
}

using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P3-0002">Endpoints MUST be able to retain two sets of receive packet protection keys: the current keys and the next keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P3-0002")]
public sealed class REQ_QUIC_RFC9001_S6P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeRetainsCurrentAndNextReceiveKeysForApparentPeerUpdate()
    {
        AssertRuntimeRetainsCurrentAndNextReceiveKeysForApparentPeerUpdate(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeRetainsCurrentAndNextReceiveKeysForApparentPeerUpdate()
    {
        AssertRuntimeRetainsCurrentAndNextReceiveKeysForApparentPeerUpdate(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeClearsRetainedNextReceiveKeysAfterInstallingPeerUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] tamperedPacket = BuildProtectedApplicationPacket(
            successorOpenMaterial,
            keyPhase: true,
            payload: QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());
        tamperedPacket[^1] ^= 0x40;

        QuicConnectionTransitionResult tamperedResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                tamperedPacket),
            nowTicks: 1);

        Assert.True(tamperedResult.StateChanged);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.True(successorOpenMaterial.Matches(
            runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));

        byte[] validPacket = BuildProtectedApplicationPacket(
            successorOpenMaterial,
            keyPhase: true,
            payload: QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        QuicConnectionTransitionResult validResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                validPacket),
            nowTicks: 2);

        Assert.True(validResult.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Null(runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial);
        Assert.True(successorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeRetainsPhaseOneAndSecondSuccessorReceiveKeysForApparentRepeatedPeerUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out _);

        QuicTlsPacketProtectionMaterial currentPhaseOneMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        byte[] tamperedPacket = BuildProtectedApplicationPacket(
            secondSuccessorOpenMaterial,
            keyPhase: false,
            payload: QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());
        tamperedPacket[^1] ^= 0x40;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                tamperedPacket),
            nowTicks: 30_000);

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(currentPhaseOneMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(secondSuccessorOpenMaterial.Matches(
            runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));
        Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EstablishingClientRuntimeDoesNotRetainNextReceiveKeysBeforeOneRttKeysExist()
    {
        using QuicConnectionRuntime runtime = QuicRfc9001KeyPhaseTestSupport.CreateEstablishingClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.False(TryEnsureNextOneRttOpenPacketProtectionMaterial(
            runtime,
            out _,
            out bool retainedNewMaterial));
        Assert.False(retainedNewMaterial);
        Assert.Null(runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzApparentPeerUpdates_RandomizedTamperedPayloadsRetainNextReceiveKeysWithoutInstalling()
    {
        Random random = new(unchecked((int)0x9001_6302));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

            QuicTlsPacketProtectionMaterial currentOpenMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
                runtime,
                out QuicTlsPacketProtectionMaterial successorOpenMaterial,
                out _));

            byte[] protectedPacket = BuildProtectedApplicationPacket(
                successorOpenMaterial,
                keyPhase: true,
                payload: CreateAckElicitingPayload(random.Next(1, 96)));
            protectedPacket[^1] ^= checked((byte)(1 + (iteration % 0x7F)));

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: iteration + 1,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: iteration + 1);

            Assert.True(result.StateChanged);
            Assert.False(runtime.TlsState.KeyUpdateInstalled);
            Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.True(currentOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
            Assert.True(successorOpenMaterial.Matches(
                runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));
            Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
        }
    }

    private static void AssertRuntimeRetainsCurrentAndNextReceiveKeysForApparentPeerUpdate(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = BuildProtectedApplicationPacket(
            successorOpenMaterial,
            keyPhase: true,
            payload: QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());
        protectedPacket[^1] ^= 0x80;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(currentOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(successorOpenMaterial.Matches(
            runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));
        Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
    }

    private static byte[] BuildProtectedApplicationPacket(
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        byte[] payload)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            keyPhase,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static byte[] CreateAckElicitingPayload(int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }

    private static bool TryEnsureNextOneRttOpenPacketProtectionMaterial(
        QuicConnectionRuntime runtime,
        out QuicTlsPacketProtectionMaterial openMaterial,
        out bool retainedNewMaterial)
    {
        FieldInfo runtimeBridgeDriverField = typeof(QuicConnectionRuntime).GetField(
            "tlsBridgeDriver",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicTlsTransportBridgeDriver runtimeBridgeDriver =
            (QuicTlsTransportBridgeDriver)runtimeBridgeDriverField.GetValue(runtime)!;

        MethodInfo ensureMethod = typeof(QuicTlsTransportBridgeDriver).GetMethod(
            "TryEnsureNextOneRttOpenPacketProtectionMaterial",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        object?[] arguments =
        [
            default(QuicTlsPacketProtectionMaterial),
            default(bool),
        ];

        if (!(bool)ensureMethod.Invoke(runtimeBridgeDriver, arguments)!)
        {
            openMaterial = default;
            retainedNewMaterial = (bool)arguments[1]!;
            return false;
        }

        openMaterial = (QuicTlsPacketProtectionMaterial)arguments[0]!;
        retainedNewMaterial = (bool)arguments[1]!;
        return true;
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

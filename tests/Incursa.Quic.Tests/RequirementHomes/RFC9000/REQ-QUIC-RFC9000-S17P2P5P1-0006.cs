namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0006">A server MAY either discard or buffer 0-RTT packets that it receives.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0006")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRuntimeBuffersAllowedZeroRttStreamPayloadWithoutClosingTheConnection()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        using QuicConnectionRuntime runtime = CreateServerRuntimeWithZeroRttOpenMaterial(zeroRttMaterial);
        byte[] streamPayload = [0x51, 0x52, 0x53, 0x54];
        byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
            QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask,
            streamId: 0,
            streamPayload);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            streamFrame,
            zeroRttMaterial,
            out byte[] protectedPacket));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                QuicS17P2P3TestSupport.BootstrapPath,
                protectedPacket),
            nowTicks: 2);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal((ulong)streamPayload.Length, snapshot.UniqueBytesReceived);
        Assert.Equal(streamPayload.Length, snapshot.BufferedReadableBytes);
    }

    private static QuicConnectionRuntime CreateServerRuntimeWithZeroRttOpenMaterial(
        QuicTlsPacketProtectionMaterial zeroRttMaterial)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionReceiveLimit: 256,
                incomingBidirectionalStreamLimit: 4,
                localBidirectionalReceiveLimit: 64,
                peerBidirectionalReceiveLimit: 64),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TrySetHandshakeSourceConnectionId(QuicS17P2P3TestSupport.PacketSourceConnectionId));
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(QuicS17P2P3TestSupport.PacketConnectionId));
        Assert.True(InitializeRuntimeActivePath(runtime, QuicS17P2P3TestSupport.BootstrapPath, 1200, observedAtTicks: 0));
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: zeroRttMaterial)),
            nowTicks: 1).StateChanged);
        Assert.True(runtime.IsEarlyDataAdmissionOpen);
        return runtime;
    }

    private static bool InitializeRuntimeActivePath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long observedAtTicks)
    {
        System.Reflection.MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "InitializeActivePath",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        return (bool)method.Invoke(runtime, [pathIdentity, payloadBytes, observedAtTicks])!;
    }
}

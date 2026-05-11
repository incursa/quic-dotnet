namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P5-0007">A server MAY treat receipt of these frames in 0-RTT packets as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P5-0007")]
public sealed class REQ_QUIC_RFC9000_S12P5_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointCanDiscardZeroRttPacketsContainingForbiddenFramesByLeavingThemUnrouted()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreateBootstrapPacketCoordinator();

        byte[] zeroRttPayload =
        [
            .. QuicFrameTestData.BuildAckFrame(new QuicAckFrame
            {
                FrameType = 0x02,
                LargestAcknowledged = 0,
                AckDelay = 0,
                FirstAckRange = 0,
            }),
            .. QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA])),
            .. QuicFrameTestData.BuildHandshakeDoneFrame(),
            .. QuicFrameTestData.BuildNewTokenFrame(new QuicNewTokenFrame([0xBB])),
            .. QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame([1, 2, 3, 4, 5, 6, 7, 8])),
            .. QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(7)),
        ];

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            zeroRttPayload,
            zeroRttMaterial,
            out byte[] zeroRttPacket));
        Assert.True(QuicPacketParser.TryParseLongHeader(zeroRttPacket, out QuicLongHeaderPacket longHeader));
        Assert.Equal(QuicLongPacketTypeBits.ZeroRtt, longHeader.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            zeroRttPacket,
            out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);

        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            zeroRttPacket,
            new QuicConnectionPathIdentity("203.0.113.10", "198.51.100.20", 443, 12345));

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRuntimeProcessesAllowedZeroRttStreamPayloadWithoutClosingTheConnection()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        using QuicConnectionRuntime runtime = CreateServerRuntimeWithZeroRttOpenMaterial(zeroRttMaterial);
        byte[] streamPayload = [0x41, 0x42, 0x43, 0x44];
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

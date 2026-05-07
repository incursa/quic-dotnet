namespace Incursa.Quic.Tests;

internal static class QuicS17P4SpinBitTestSupport
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    private static readonly QuicConnectionPathIdentity ActivePath =
        new("203.0.113.177", RemotePort: 443);

    internal static QuicConnectionRuntime CreateActiveOneRttRuntime(QuicTlsRole role)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: role,
            enableRandomizedSpinBitSelection: true);

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(PacketConnectionId));
        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                ActivePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 2).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(ActivePath, runtime.ActivePath.Value.Identity);

        SeedOneRttPacketProtectionMaterial(runtime);
        return runtime;
    }

    internal static QuicConnectionTransitionResult ReceivePeerPingPacket(
        QuicConnectionRuntime runtime,
        bool spinBit,
        ulong packetNumber,
        long observedAtTicks)
    {
        Assert.True(runtime.ActivePath.HasValue);
        byte[] protectedPacket = BuildPeerPingPacket(runtime, spinBit, packetNumber);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                observedAtTicks,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            observedAtTicks);
    }

    internal static void AssertLocalOneRttCloseSpinBit(
        QuicConnectionRuntime runtime,
        bool expectedSpinBit,
        long observedAtTicks)
    {
        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                observedAtTicks,
                QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
            observedAtTicks);

        bool observedOneRttClose = false;
        bool observedSpinBit = false;
        foreach (QuicConnectionSendDatagramEffect effect in closeResult.Effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            if (!TryOpenOneRttPacket(runtime, effect.Datagram.Span, out bool spinBit))
            {
                continue;
            }

            Assert.False(observedOneRttClose);
            observedOneRttClose = true;
            observedSpinBit = spinBit;
        }

        Assert.True(observedOneRttClose);
        Assert.Equal(expectedSpinBit, observedSpinBit);
    }

    private static void SeedOneRttPacketProtectionMaterial(QuicConnectionRuntime runtime)
    {
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            new QuicTransportParameters
            {
                InitialMaxData = 64,
                InitialMaxStreamDataBidiLocal = 64,
                InitialMaxStreamDataBidiRemote = 64,
                InitialMaxStreamDataUni = 64,
                ActiveConnectionIdLimit = 2,
            });
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    private static byte[] BuildPeerPingPacket(
        QuicConnectionRuntime runtime,
        bool spinBit,
        ulong packetNumber)
    {
        QuicHandshakeFlowCoordinator coordinator = new(
            PacketConnectionId,
            enableRandomizedSpinBitSelection: true);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();
        byte[] protectedPacket = [];

        for (ulong currentPacketNumber = 0; currentPacketNumber <= packetNumber; currentPacketNumber++)
        {
            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                payload,
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
                keyPhase: false,
                spinBit,
                out ulong builtPacketNumber,
                out protectedPacket));
            Assert.Equal(currentPacketNumber, builtPacketNumber);
        }

        return protectedPacket;
    }

    private static bool TryOpenOneRttPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> protectedPacket,
        out bool spinBit)
    {
        spinBit = default;
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        if (!coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out _,
                out _)
            || !QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header))
        {
            return false;
        }

        spinBit = header.SpinBit;
        return true;
    }
}

namespace Incursa.Quic.Tests;

internal static class QuicS7P2FirstFlightConnectionIdTestSupport
{
    internal static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    internal static readonly byte[] InitialSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    private static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    internal static bool IsAllZero(ReadOnlySpan<byte> bytes)
    {
        foreach (byte value in bytes)
        {
            if (value != 0)
            {
                return false;
            }
        }

        return true;
    }

    internal static QuicConnectionRuntime CreateClientRuntime()
    {
        byte[] localHandshakePrivateKey = new byte[32];
        localHandshakePrivateKey[^1] = 0x11;

        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.True(runtime.TryConfigureInitialPacketProtection(InitialDestinationConnectionId));
        Assert.True(runtime.TrySetBootstrapOutboundPath(BootstrapPath));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(InitialSourceConnectionId));

        return runtime;
    }

    internal static QuicConnectionTransitionResult BootstrapClientHandshake(QuicConnectionRuntime runtime)
    {
        QuicTransportParameters transportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 1,
                LocalTransportParameters: transportParameters),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        return result;
    }

    internal static QuicConnectionTransitionResult ExpireRecoveryTimer(QuicConnectionRuntime runtime)
    {
        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        return runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            recoveryDueTicks.Value);
    }

    internal static void AssertLongHeaderConnectionIds(
        ReadOnlySpan<byte> datagram,
        ReadOnlySpan<byte> expectedDestinationConnectionId,
        ReadOnlySpan<byte> expectedSourceConnectionId)
    {
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket header));
        Assert.True(header.DestinationConnectionId.SequenceEqual(expectedDestinationConnectionId));
        Assert.True(header.SourceConnectionId.SequenceEqual(expectedSourceConnectionId));
    }

    internal static (byte[] InitialPacket, byte[] ZeroRttPacket) BuildInitialAndZeroRttPackets(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection));

        QuicHandshakeFlowCoordinator coordinator = new(initialDestinationConnectionId.ToArray(), sourceConnectionId.ToArray());
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            QuicS17P2P3TestSupport.CreateSequentialBytes(0x40, 24),
            cryptoPayloadOffset: 0,
            initialProtection,
            out byte[] initialPacket));

        QuicTlsPacketProtectionMaterial zeroRttMaterial =
            QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt);
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out _,
            out byte[] zeroRttPacket));

        return (initialPacket, zeroRttPacket);
    }

    private sealed class FakeMonotonicClock(long ticks) : IMonotonicClock
    {
        public long Ticks { get; } = ticks;

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}

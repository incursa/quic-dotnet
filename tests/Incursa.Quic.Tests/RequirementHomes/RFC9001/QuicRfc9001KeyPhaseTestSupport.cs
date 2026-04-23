using System.Reflection;

namespace Incursa.Quic.Tests;

internal static class QuicRfc9001KeyPhaseTestSupport
{
    private static readonly byte[] KeyPhaseDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    internal static readonly QuicConnectionPathIdentity PacketPathIdentity =
        new("203.0.113.10", RemotePort: 443);

    internal static void ConfigureKeyPhaseDestinationConnectionId(QuicConnectionRuntime runtime)
    {
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(KeyPhaseDestinationConnectionId));
    }

    internal static QuicHandshakeFlowCoordinator CreatePacketCoordinator()
    {
        QuicHandshakeFlowCoordinator coordinator = new(KeyPhaseDestinationConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(KeyPhaseDestinationConnectionId));
        return coordinator;
    }

    internal static QuicConnectionRuntime CreateEstablishingClientRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client);
    }

    internal static bool TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
        QuicConnectionRuntime runtime,
        out QuicTlsPacketProtectionMaterial openMaterial,
        out QuicTlsPacketProtectionMaterial protectMaterial)
    {
        FieldInfo runtimeBridgeDriverField = typeof(QuicConnectionRuntime).GetField(
            "tlsBridgeDriver",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicTlsTransportBridgeDriver runtimeBridgeDriver =
            (QuicTlsTransportBridgeDriver)runtimeBridgeDriverField.GetValue(runtime)!;

        MethodInfo deriveMethod = typeof(QuicTlsTransportBridgeDriver).GetMethod(
            "TryDeriveOneRttSuccessorPacketProtectionMaterial",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        object?[] arguments =
        [
            default(QuicTlsPacketProtectionMaterial),
            default(QuicTlsPacketProtectionMaterial),
        ];

        if (!(bool)deriveMethod.Invoke(runtimeBridgeDriver, arguments)!)
        {
            openMaterial = default;
            protectMaterial = default;
            return false;
        }

        openMaterial = (QuicTlsPacketProtectionMaterial)arguments[0]!;
        protectMaterial = (QuicTlsPacketProtectionMaterial)arguments[1]!;
        return true;
    }

    internal static bool TryInstallRuntimeOneRttKeyUpdate(QuicConnectionRuntime runtime)
    {
        FieldInfo runtimeBridgeDriverField = typeof(QuicConnectionRuntime).GetField(
            "tlsBridgeDriver",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicTlsTransportBridgeDriver runtimeBridgeDriver =
            (QuicTlsTransportBridgeDriver)runtimeBridgeDriverField.GetValue(runtime)!;

        MethodInfo installMethod = typeof(QuicTlsTransportBridgeDriver).GetMethod(
            "TryInstallOneRttKeyUpdate",
            BindingFlags.NonPublic | BindingFlags.Instance)!;

        return (bool)installMethod.Invoke(runtimeBridgeDriver, [])!;
    }

    internal static byte[] CreateSuccessorPhaseOneApplicationPacket(QuicTlsPacketProtectionMaterial openMaterial)
    {
        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            CreatePingPayload(),
            openMaterial,
            keyPhase: true,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    internal static byte[] CreateTamperedSuccessorPhaseOneApplicationPacket(QuicTlsPacketProtectionMaterial openMaterial)
    {
        byte[] protectedPacket = CreateSuccessorPhaseOneApplicationPacket(openMaterial);

        protectedPacket[^1] ^= 0x80;
        return protectedPacket;
    }

    internal static byte[] CreatePingPayload()
    {
        byte[] payload = new byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}

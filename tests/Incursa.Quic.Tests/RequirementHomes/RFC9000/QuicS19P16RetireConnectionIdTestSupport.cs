namespace Incursa.Quic.Tests;

internal static class QuicS19P16RetireConnectionIdTestSupport
{
    internal static QuicConnectionTransitionResult TransitionOneRttPacket(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> payload,
        long observedAtTicks)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator coordinator = new(
            destinationConnectionId.ToArray(),
            QuicS17P2P3TestSupport.PacketSourceConnectionId);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                pathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }
}

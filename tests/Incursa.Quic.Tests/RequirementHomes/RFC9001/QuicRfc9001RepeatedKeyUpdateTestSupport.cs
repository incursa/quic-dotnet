namespace Incursa.Quic.Tests;

internal static class QuicRfc9001RepeatedKeyUpdateTestSupport
{
    internal static void ConfigureRuntime(QuicConnectionRuntime runtime)
    {
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
    }

    internal static QuicConnectionTransitionResult ReceiveCurrentPhaseAck(
        QuicConnectionRuntime runtime,
        ulong largestAcknowledged,
        long observedAtTicks,
        ulong ackDelay = 0)
    {
        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            CreateAckPayload(largestAcknowledged, ackDelay),
            currentOpenMaterial,
            keyPhase: (runtime.TlsState.CurrentOneRttKeyPhase & 1U) == 1U,
            out _,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    private static byte[] CreateAckPayload(ulong largestAcknowledged, ulong ackDelay)
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
}

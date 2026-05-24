namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S5P2-0002">A lost DATAGRAM frame MUST NOT be retransmitted unless requested by application-specific policy outside QUIC transport.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S5P2-0002")]
public sealed class REQ_QUIC_RFC9221_S5P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SentDatagramPacket_IsTrackedAsNonRetransmittable()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1, 0xD2 });

        Assert.NotNull(result.TrackedPacket);
        QuicConnectionSentPacket trackedPacket = result.TrackedPacket.Value;
        Assert.True(trackedPacket.AckEliciting);
        Assert.False(trackedPacket.Retransmittable);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            trackedPacket.PacketNumberSpace,
            trackedPacket.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task LostDatagramPacket_IsNotQueuedForTransportRetransmission()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1 });

        Assert.NotNull(result.TrackedPacket);
        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            result.TrackedPacket.Value.PacketNumberSpace,
            result.TrackedPacket.Value.PacketNumber,
            handshakeConfirmed: true));
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task AcknowledgedDatagramPacket_IsRemovedWithoutAnyRetransmissionPayload()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1 });

        Assert.NotNull(result.TrackedPacket);
        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            result.TrackedPacket.Value.PacketNumberSpace,
            result.TrackedPacket.Value.PacketNumber,
            handshakeConfirmed: true));
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }
}

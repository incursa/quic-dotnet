namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S3-0004">An endpoint MUST NOT send DATAGRAM frames until it has received a non-zero max_datagram_frame_size transport parameter from its peer during the handshake or from a previous handshake when 0-RTT is used.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S3-0004")]
public sealed class REQ_QUIC_RFC9221_S3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SendDatagramAsync_RejectsWhenPeerDidNotAdvertiseSupport()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200);
        int sentPacketCount = runtime.SendRuntime.SentPackets.Count;

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
                runtime,
                new byte[] { 0xD1, 0xD2 }));

        Assert.Contains("did not advertise QUIC DATAGRAM support", exception.Message, StringComparison.Ordinal);
        Assert.Equal(sentPacketCount, runtime.SendRuntime.SentPackets.Count);
    }
}

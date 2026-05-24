namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S3-0005">An endpoint MUST NOT send a DATAGRAM frame larger than the max_datagram_frame_size value it received from its peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S3-0005")]
public sealed class REQ_QUIC_RFC9221_S3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SendDatagramAsync_RejectsFramesLargerThanPeerLimit()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 3);
        int sentPacketCount = runtime.SendRuntime.SentPackets.Count;

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
                runtime,
                new byte[] { 0xD1, 0xD2 }));

        Assert.Contains("exceeds the peer max_datagram_frame_size", exception.Message, StringComparison.Ordinal);
        Assert.Equal(sentPacketCount, runtime.SendRuntime.SentPackets.Count);
    }
}

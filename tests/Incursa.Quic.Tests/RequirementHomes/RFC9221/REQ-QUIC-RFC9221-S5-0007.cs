namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S5-0007">DATAGRAM frames MUST NOT be fragmented across QUIC packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S5-0007")]
public sealed class REQ_QUIC_RFC9221_S5_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SendDatagramAsync_RejectsInsteadOfFragmentingOversizedFrame()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 3);
        int sentPacketCount = runtime.SendRuntime.SentPackets.Count;

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
                runtime,
                new byte[] { 0xD1, 0xD2 }));

        Assert.Equal(sentPacketCount, runtime.SendRuntime.SentPackets.Count);
    }
}

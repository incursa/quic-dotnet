namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S5-0005">An endpoint MAY send a DATAGRAM frame immediately in a 1-RTT packet when the frame fits the selected packet and congestion controller state permits sending.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S5-0005")]
public sealed class REQ_QUIC_RFC9221_S5_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SendDatagramAsync_EmitsProtectedOneRttDatagramFrame()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);
        byte[] datagramData = [0xD1, 0xD2, 0xD3];

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            datagramData);

        Assert.NotNull(result.SendEffect);
        QuicDatagramFrame frame = QuicDatagramRuntimeTestSupport.ParseFirstOutgoingDatagramFrame(
            runtime,
            result.SendEffect);
        Assert.Equal(QuicFrameCodec.DatagramWithLengthFrameType, frame.FrameType);
        Assert.Equal(datagramData, frame.DatagramData);
    }
}

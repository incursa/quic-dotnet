namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S5-0001")]
public sealed class REQ_QUIC_RFC9221_S5_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5-0001")]
    [Requirement("REQ-QUIC-RFC9221-S5-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtectedOneRttDatagramFrame_DeliversConnectionScopedApplicationDatagram()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200);
        Assert.True(runtime.ActivePath.HasValue);
        QuicConnectionPathIdentity activePath = runtime.ActivePath.Value.Identity;
        byte[] datagramData = [0x41, 0x42, 0x43];

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = datagramData,
            });

        QuicConnectionDeliverDatagramEffect deliver =
            Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.Equal(activePath, deliver.PathIdentity);
        Assert.Equal(QuicFrameCodec.DatagramWithLengthFrameType, deliver.FrameType);
        Assert.True(datagramData.AsSpan().SequenceEqual(deliver.Datagram.Span));
        Assert.Null(runtime.TerminalState);
    }
}

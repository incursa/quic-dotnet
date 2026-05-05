namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0001")]
public sealed class REQ_QUIC_RFC9000_S19P15_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewConnectionIdFrame_ProvidesAnAlternativeConnectionIdWithType18()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(8);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        Span<byte> destination = stackalloc byte[64];

        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, destination, out int bytesWritten));
        Assert.True(bytesWritten > connectionId.Length + statelessResetToken.Length);
        Assert.Equal(QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType, destination[0]);

        ReadOnlySpan<byte> encoded = destination[..bytesWritten];
        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            frame.SequenceNumber,
            frame.RetirePriorTo,
            connectionId,
            statelessResetToken);
    }
}

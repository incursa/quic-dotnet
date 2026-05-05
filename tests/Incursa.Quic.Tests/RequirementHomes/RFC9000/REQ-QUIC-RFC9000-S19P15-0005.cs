namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
public sealed class REQ_QUIC_RFC9000_S19P15_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewConnectionIdFrame_WritesLengthAsASingleOctet()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        Span<byte> destination = stackalloc byte[64];

        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, destination, out int bytesWritten));
        int lengthIndex = QuicVarintTestData.EncodeMinimal(frame.SequenceNumber).Length
            + QuicVarintTestData.EncodeMinimal(frame.RetirePriorTo).Length
            + 1;

        Assert.True(bytesWritten > lengthIndex);
        Assert.Equal((byte)connectionId.Length, destination[lengthIndex]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsFramesMissingTheLengthOctet()
    {
        byte[] encoded = [
            QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType,
            .. QuicVarintTestData.EncodeMinimal(0x06),
            .. QuicVarintTestData.EncodeMinimal(0x04)];

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewConnectionIdFrame_RejectsVarintEncodedLengthField()
    {
        byte[] connectionId = [0xAA];
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrameWithLengthBytes(
            [QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType],
            QuicVarintTestData.EncodeMinimal(0x06),
            QuicVarintTestData.EncodeMinimal(0x04),
            QuicVarintTestData.EncodeWithLength(1, 2),
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }
}

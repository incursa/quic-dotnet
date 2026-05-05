namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0011")]
public sealed class REQ_QUIC_RFC9000_S19P15_0011
{
    [Theory]
    [InlineData(1)]
    [InlineData(20)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_AcceptsBoundaryConnectionIdLengths(int connectionIdLength)
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(connectionIdLength);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            0x09,
            0x01,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            expectedSequenceNumber: 0x09,
            expectedRetirePriorTo: 0x01,
            connectionId,
            statelessResetToken);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(21)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsInvalidConnectionIdLengthValues(int connectionIdLength)
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(connectionIdLength);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrameWithLengthBytes(
            [QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType],
            QuicVarintTestData.EncodeMinimal(0x09),
            QuicVarintTestData.EncodeMinimal(0x01),
            [(byte)connectionIdLength],
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatNewConnectionIdFrame_RejectsInvalidConnectionIdLengthValues()
    {
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        QuicNewConnectionIdFrame zeroLengthFrame = new(0x09, 0x01, [], statelessResetToken);
        QuicNewConnectionIdFrame longLengthFrame = new(
            0x09,
            0x01,
            QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(21),
            statelessResetToken);

        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(zeroLengthFrame, stackalloc byte[64], out _));
        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(longLengthFrame, stackalloc byte[64], out _));
    }
}

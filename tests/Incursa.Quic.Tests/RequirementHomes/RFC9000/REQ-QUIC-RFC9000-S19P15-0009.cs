namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0009")]
public sealed class REQ_QUIC_RFC9000_S19P15_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_ParsesRetirePriorToAsConnectionIdRetirementFloor()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrameWithEncodedRetirePriorTo(
            sequenceNumber: 0x1234,
            retirePriorTo: 0x1200,
            encodedRetirePriorToLength: 2,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            expectedSequenceNumber: 0x1234,
            expectedRetirePriorTo: 0x1200,
            connectionId,
            statelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsTruncatedRetirePriorToRetirementFloor()
    {
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrameWithLengthBytes(
            [QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType],
            QuicVarintTestData.EncodeMinimal(0x1234),
            QuicVarintTestData.EncodeWithLength(0x1200, 2)[..1],
            [0x01],
            [0xAA],
            QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken());

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewConnectionIdFrame_AcceptsZeroRetirePriorTo()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            sequenceNumber: 0x1234,
            retirePriorTo: 0,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            expectedSequenceNumber: 0x1234,
            expectedRetirePriorTo: 0,
            connectionId,
            statelessResetToken);
    }
}

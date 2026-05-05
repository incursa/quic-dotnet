namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0007")]
public sealed class REQ_QUIC_RFC9000_S19P15_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_PreservesSixteenByteStatelessResetToken()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            0x06,
            0x04,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            expectedSequenceNumber: 0x06,
            expectedRetirePriorTo: 0x04,
            connectionId,
            statelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsTruncatedStatelessResetToken()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken()[..15];
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            0x06,
            0x04,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewConnectionIdFrame_ConsumesExactlyTheSixteenByteStatelessResetToken()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = [..
            QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
                0x06,
                0x04,
                connectionId,
                statelessResetToken),
            0x01];

        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            expectedSequenceNumber: 0x06,
            expectedRetirePriorTo: 0x04,
            connectionId,
            statelessResetToken,
            expectedBytesConsumed: encoded.Length - 1);
    }
}

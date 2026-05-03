namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0005">Additional connection IDs MUST be communicated to the peer using NEW_CONNECTION_ID frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1P1-0005")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_CommunicatesAnAdditionalConnectionIdToThePeer()
    {
        byte[] connectionId = [0x41, 0x42, 0x43, 0x44];
        byte[] statelessResetToken = QuicS17P2P3TestSupport.CreateSequentialBytes(
            0x50,
            QuicStatelessReset.StatelessResetTokenLength);
        QuicNewConnectionIdFrame frame = new(2, 0, connectionId, statelessResetToken);

        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(
            encoded,
            out QuicNewConnectionIdFrame parsed,
            out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(2UL, parsed.SequenceNumber);
        Assert.Equal(0UL, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
    }
}

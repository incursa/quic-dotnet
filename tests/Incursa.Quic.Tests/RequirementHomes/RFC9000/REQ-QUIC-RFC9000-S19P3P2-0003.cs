namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_EncodesEct1CountAsVariableLengthInteger()
    {
        byte[] encoded = QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
            QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                ect0Count: 1,
                ect1Count: 0x40,
                ecnCeCount: 2));

        (ulong value, int bytesConsumed) = QuicAckEcnFrameCodecTestSupport.ParseEcnCountField(encoded, fieldIndex: 1);

        Assert.Equal(0x40UL, value);
        Assert.Equal(2, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsMissingEct1CountField()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x03],
                QuicS19P3AckFrameTestSupport.Varint(4),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_PreservesZeroEct1CountField()
    {
        QuicAckFrame parsed = QuicAckEcnFrameCodecTestSupport.ParseAckFrame(
            QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
                QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                    ect0Count: 1,
                    ect1Count: 0,
                    ecnCeCount: 2)));

        Assert.Equal(0UL, parsed.EcnCounts!.Value.Ect1Count);
    }
}

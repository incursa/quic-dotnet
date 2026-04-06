namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0001">Each connection MUST possess a set of connection IDs, each of which can identify the connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1-0001")]
public sealed class REQ_QUIC_RFC9000_S5P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0001">Each connection MUST possess a set of connection IDs, each of which can identify the connection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0001")]
    public void TryParseNewConnectionIdFrame_ExposesMultipleConnectionIdsForTheSameConnection()
    {
        byte[] statelessResetToken = [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F];

        QuicNewConnectionIdFrame firstFrame = new(0x01, 0x00, [0x10, 0x11], statelessResetToken);
        QuicNewConnectionIdFrame secondFrame = new(0x02, 0x01, [0x20, 0x21, 0x22], statelessResetToken);

        byte[] firstEncoded = QuicFrameTestData.BuildNewConnectionIdFrame(firstFrame);
        byte[] secondEncoded = QuicFrameTestData.BuildNewConnectionIdFrame(secondFrame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(firstEncoded, out QuicNewConnectionIdFrame firstParsed, out int firstBytesConsumed));
        Assert.Equal(firstEncoded.Length, firstBytesConsumed);
        Assert.Equal(firstFrame.SequenceNumber, firstParsed.SequenceNumber);
        Assert.Equal(firstFrame.RetirePriorTo, firstParsed.RetirePriorTo);
        Assert.True(firstFrame.ConnectionId.SequenceEqual(firstParsed.ConnectionId));
        Assert.True(firstFrame.StatelessResetToken.SequenceEqual(firstParsed.StatelessResetToken));

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(secondEncoded, out QuicNewConnectionIdFrame secondParsed, out int secondBytesConsumed));
        Assert.Equal(secondEncoded.Length, secondBytesConsumed);
        Assert.Equal(secondFrame.SequenceNumber, secondParsed.SequenceNumber);
        Assert.Equal(secondFrame.RetirePriorTo, secondParsed.RetirePriorTo);
        Assert.True(secondFrame.ConnectionId.SequenceEqual(secondParsed.ConnectionId));
        Assert.True(secondFrame.StatelessResetToken.SequenceEqual(secondParsed.StatelessResetToken));
        Assert.NotEqual(firstParsed.SequenceNumber, secondParsed.SequenceNumber);
        Assert.NotEqual(firstParsed.ConnectionId.Length, secondParsed.ConnectionId.Length);
    }
}

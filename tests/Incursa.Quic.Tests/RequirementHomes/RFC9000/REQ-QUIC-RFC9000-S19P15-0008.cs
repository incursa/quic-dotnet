namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
public sealed class REQ_QUIC_RFC9000_S19P15_0008
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0002">The Type field MUST be encoded as a variable-length integer with value 0x18.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0003">The Sequence Number field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0004">The Retire Prior To field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0005">The Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0006">The Connection ID field MUST be between 8 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0007">The Stateless Reset Token field MUST be 128 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0008">NEW_CONNECTION_ID frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0009">The Retire Prior To field MUST be a variable-length integer indicating which connection IDs should be retired; see Section 5.1.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0010">The Length field MUST be 8-bit unsigned integer containing the length of the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0019">The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0020">Receiving a value in the Retire Prior To field that is greater than that in the Sequence Number field MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0003">A stateless reset token MUST be 16 bytes long and difficult to guess.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0017">An endpoint MUST issue a stateless reset token by including the value in the Stateless Reset Token field of a NEW_CONNECTION_ID frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0008">An endpoint MAY cause its peer to retire connection IDs by sending a NEW_CONNECTION_ID frame with an increased Retire Prior To field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0005">Additional connection IDs MUST be communicated to the peer using NEW_CONNECTION_ID frames.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0020")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseNewConnectionIdFrame_ParsesAndFormatsTheEncodedFields()
    {
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];

        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(18)]
    [InlineData(19)]
    [InlineData(20)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0008">NEW_CONNECTION_ID frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewConnectionIdFrame_RejectsTruncatedInput(int truncateBy)
    {
        byte[] connectionId = [0x10];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded[..Math.Max(0, encoded.Length - truncateBy)], out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_NewConnectionIdFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecPart4FuzzSupport.FuzzNewConnectionIdFrame();
    }
}

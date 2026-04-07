namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0011")]
public sealed class REQ_QUIC_RFC9000_S19P15_0011
{
    [Theory]
    [InlineData(1)]
    [InlineData(20)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0008">An endpoint MAY cause its peer to retire connection IDs by sending a NEW_CONNECTION_ID frame with an increased Retire Prior To field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0005">The Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0006">The Connection ID field MUST be between 8 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0010">The Length field MUST be 8-bit unsigned integer containing the length of the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0011">Values less than 1 and greater than 20 are invalid and MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0003">A stateless reset token MUST be 16 bytes long and difficult to guess.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0017">An endpoint MUST issue a stateless reset token by including the value in the Stateless Reset Token field of a NEW_CONNECTION_ID frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0005">Additional connection IDs MUST be communicated to the peer using NEW_CONNECTION_ID frames.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseNewConnectionIdFrame_AcceptsBoundaryConnectionIdLengths(int connectionIdLength)
    {
        byte[] connectionId = Enumerable.Repeat((byte)0xDA, connectionIdLength).ToArray();
        byte[] statelessResetToken = Enumerable.Repeat((byte)0x5C, 16).ToArray();
        QuicNewConnectionIdFrame frame = new(0x09, 0x01, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.Equal(connectionIdLength, parsed.ConnectionId.Length);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0010">The Length field MUST be 8-bit unsigned integer containing the length of the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0011">Values less than 1 and greater than 20 are invalid and MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0003">A stateless reset token MUST be 16 bytes long and difficult to guess.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewConnectionIdFrame_RejectsInvalidConnectionIdLengthValues()
    {
        byte[] statelessResetToken = Enumerable.Repeat((byte)0x5C, 16).ToArray();

        QuicNewConnectionIdFrame zeroLengthFrame = new(0x01, 0x00, Array.Empty<byte>(), statelessResetToken);
        byte[] zeroLengthEncoded = QuicFrameTestData.BuildNewConnectionIdFrame(zeroLengthFrame);
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(zeroLengthEncoded, out _, out _));

        QuicNewConnectionIdFrame longLengthFrame = new(0x02, 0x01, Enumerable.Repeat((byte)0xDA, 21).ToArray(), statelessResetToken);
        byte[] longLengthEncoded = QuicFrameTestData.BuildNewConnectionIdFrame(longLengthFrame);
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(longLengthEncoded, out _, out _));

        QuicNewConnectionIdFrame invalidTokenFrame = new(0x03, 0x01, [0xAA], Enumerable.Repeat((byte)0xCC, 15).ToArray());
        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(invalidTokenFrame, stackalloc byte[64], out _));
    }
}

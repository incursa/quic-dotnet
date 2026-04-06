namespace Incursa.Quic.Tests;

public sealed class QuicAddressValidationTests
{
    [Theory]
    [InlineData(true, 8, true)]
    [InlineData(true, 7, false)]
    [InlineData(false, 8, false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P1P1P1-0001">Address validation (Section 8) MUST be used to verify that an entity that claims a given address is able to receive packets at that address.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0001">Additionally, an endpoint MAY consider the peer address validated if the peer uses a connection ID chosen by the endpoint and the connection ID contains at least 64 bits of entropy.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S21P1P1P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanConsiderPeerAddressValidated_RequiresEndpointChosenAndAtLeast64BitsOfEntropy(
        bool chosenByEndpoint,
        int connectionIdLength,
        bool expected)
    {
        byte[] connectionId = Enumerable.Range(0, connectionIdLength).Select(index => (byte)index).ToArray();

        Assert.Equal(expected, QuicAddressValidation.CanConsiderPeerAddressValidated(connectionId, chosenByEndpoint));
    }

    [Theory]
    [InlineData(1187, 13)]
    [InlineData(1199, 1)]
    [InlineData(1200, 0)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0003">A server MUST expand the payload of all UDP datagrams carrying ack-eliciting Initial packets to at least the smallest allowed maximum datagram size of 1200 bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0004">Clients MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes, adding PADDING frames as necessary.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S14P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetVersion1InitialDatagramPaddingLength_ComputesTheRemainingPadding(
        int currentPayloadLength,
        int expectedPaddingLength)
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(
            currentPayloadLength,
            out int paddingLength));

        Assert.Equal(expectedPaddingLength, paddingLength);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0004">Clients MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes, adding PADDING frames as necessary.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGetVersion1InitialDatagramPaddingLength_RejectsNegativeCurrentPayloadLength()
    {
        Assert.False(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(-1, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0003">A server MUST expand the payload of all UDP datagrams carrying ack-eliciting Initial packets to at least the smallest allowed maximum datagram size of 1200 bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0004">Clients MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes, adding PADDING frames as necessary.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S14P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatVersion1InitialDatagramPadding_WritesRepeatedPaddingFrames()
    {
        Span<byte> destination = stackalloc byte[13];

        Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
            1187,
            destination,
            out int bytesWritten));

        Assert.Equal(13, bytesWritten);
        Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));

        for (int index = 0; index < bytesWritten; index++)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination[index..bytesWritten], out int bytesConsumed));
            Assert.Equal(1, bytesConsumed);
        }
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0004">Clients MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes, adding PADDING frames as necessary.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatVersion1InitialDatagramPadding_RejectsNegativeLengthsAndShortDestinations()
    {
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(-1, stackalloc byte[1], out _));
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(1199, stackalloc byte[0], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0001">The Type field MUST be encoded as a variable-length integer with value 0x07.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0002">The Token Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0003">NEW_TOKEN frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0004">The Token Length field MUST be variable-length integer specifying the length of the token in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0005">An opaque blob that the client MAY use with a future Initial packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P7-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseNewTokenFrame_ParsesAndFormatsAProvidedToken()
    {
        byte[] token = [0x10, 0x20, 0x30, 0x40];
        QuicNewTokenFrame frame = new(token);
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(encoded, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.True(token.AsSpan().SequenceEqual(parsed.Token));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0006">The token MUST NOT be empty.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0007">A client MUST treat receipt of a NEW_TOKEN frame with an empty Token field as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P7-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewTokenFrame_RejectsEmptyTokens()
    {
        QuicNewTokenFrame emptyFrame = new(Array.Empty<byte>());
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(emptyFrame);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryParseNewTokenFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatNewTokenFrame(emptyFrame, destination, out _));
    }
}

namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecErrorHandlingFuzzTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11-0001">An endpoint that detects an error SHOULD signal the existence of that error to its peer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11-0002">The most appropriate error code (Section 20) SHOULD be included in the frame that signals the error.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11-0003">An endpoint MAY use a generic error code such as PROTOCOL_VIOLATION or INTERNAL_ERROR in place of a specific error code.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11-0004">An endpoint MAY use any applicable error code when it detects an error condition.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0001">The CONNECTION_CLOSE frame with a type of 0x1c MUST be used to signal errors at only the QUIC layer, or the absence of errors (with the NO_ERROR code).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0002">The CONNECTION_CLOSE frame with a type of 0x1d MUST be used to signal an error with the application that uses QUIC.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0003">The Type field MUST be encoded as a variable-length integer with value 0x1c..0x1d.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0004">The Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0005">The Frame Type field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0006">The Reason Phrase Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0007">CONNECTION_CLOSE frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0008">A variable-length integer that MUST indicate the reason for closing this connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0009">A CONNECTION_CLOSE frame of type 0x1c MUST use codes from the space defined in Section 20.1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0010">A CONNECTION_CLOSE frame of type 0x1d MUST use codes defined by the application protocol; see Section 20.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0011">The Frame Type field MUST be variable-length integer encoding the type of frame that triggered the error.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0013">The application-specific variant of CONNECTION_CLOSE (type 0x1d) MUST NOT include this field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0014">The Reason Phrase Length field MUST be variable-length integer specifying the length of the reason phrase in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P2-0001">Application protocol error codes MUST be used for the RESET_STREAM frame (Section 19.4), the STOP_SENDING frame (Section 19.5), and the CONNECTION_CLOSE frame with a type of 0x1d (Section 19.19).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0001">Errors that result in the connection being unusable, such as an obvious violation of protocol semantics or corruption of state that affects an entire connection, MUST be signaled using a CONNECTION_CLOSE frame (Section 19.19).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0002">Application-specific protocol errors MUST be signaled using the CONNECTION_CLOSE frame with a frame type of 0x1d.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0003">Transport errors, including all those described in this document, MUST be carried in the CONNECTION_CLOSE frame with a frame type of 0x1c.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S11-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11-0002")]
    [Requirement("REQ-QUIC-RFC9000-S11-0003")]
    [Requirement("REQ-QUIC-RFC9000-S11-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0014")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_ConnectionCloseFrame_RoundTripsRepresentativeTransportAndApplicationShapes()
    {
        Random random = new(0x5160_2050);
        Span<byte> destination = stackalloc byte[64];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            bool isApplicationError = (iteration & 1) == 0;
            byte[] reasonPhrase = RandomBytes(random, random.Next(0, 32));
            ulong errorCode = (ulong)random.Next(0, 1 << 20);

            QuicConnectionCloseFrame frame = isApplicationError
                ? new QuicConnectionCloseFrame(errorCode, reasonPhrase)
                : new QuicConnectionCloseFrame(errorCode, (ulong)random.Next(0, 1 << 8), reasonPhrase);

            byte[] packet = QuicFrameTestData.BuildConnectionCloseFrame(frame);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(packet, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
            Assert.Equal(frame.IsApplicationError, parsed.IsApplicationError);
            Assert.Equal(frame.ErrorCode, parsed.ErrorCode);
            Assert.Equal(frame.HasTriggeringFrameType, parsed.HasTriggeringFrameType);
            Assert.Equal(frame.FrameType, parsed.FrameType);
            Assert.True(frame.ReasonPhrase.SequenceEqual(parsed.ReasonPhrase));

            if (!frame.IsApplicationError)
            {
                Assert.Equal(frame.TriggeringFrameType, parsed.TriggeringFrameType);
            }

            Assert.Equal(packet.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));

            if (packet.Length > 1)
            {
                Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(packet[..^1], out _, out _));
            }
        }
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }
}

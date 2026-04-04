namespace Incursa.Quic.Tests;

public sealed class QuicHandshakeDoneFrameTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P20-0001">The server MUST use a HANDSHAKE_DONE frame (type=0x1e) to signal confirmation of the handshake to the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P20-0002">HANDSHAKE_DONE frames are formatted as shown in Figure 44, which shows that HANDSHAKE_DONE frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P20-0003">The Type field MUST be encoded as a variable-length integer with value 0x1e.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P20-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseHandshakeDoneFrame_ParsesAndFormatsTheTypeOnlyFrame()
    {
        byte[] encoded = QuicFrameTestData.BuildHandshakeDoneFrame();
        byte[] encodedWithTrailingBytes = [0x1E, 0xAA, 0xBB];

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(encoded, out QuicHandshakeDoneFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(encodedWithTrailingBytes, out _, out int trailingBytesConsumed));
        Assert.Equal(1, trailingBytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatHandshakeDoneFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P20-0002">HANDSHAKE_DONE frames are formatted as shown in Figure 44, which shows that HANDSHAKE_DONE frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P20-0003">The Type field MUST be encoded as a variable-length integer with value 0x1e.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P20-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseHandshakeDoneFrame_RejectsEmptyAndMismatchedTypes()
    {
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([0x1D], out _, out _));
        Assert.False(QuicFrameCodec.TryFormatHandshakeDoneFrame(default, stackalloc byte[0], out _));
    }
}

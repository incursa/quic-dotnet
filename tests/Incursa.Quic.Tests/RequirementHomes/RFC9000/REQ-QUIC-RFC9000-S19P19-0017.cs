using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0017">This SHOULD be a UTF-8 encoded string [RFC3629], though the frame does not carry information, such as language tags, that would aid comprehension by any entity other than the one that created the text.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P19-0017")]
public sealed class REQ_QUIC_RFC9000_S19P19_0017
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesUtf8ReasonPhrases(bool isApplicationError)
    {
        byte[] reasonPhrase = Encoding.UTF8.GetBytes("café ☕");
        QuicConnectionCloseFrame frame = isApplicationError
            ? new QuicConnectionCloseFrame(0x1234, reasonPhrase)
            : new QuicConnectionCloseFrame(QuicTransportErrorCode.ProtocolViolation, 0x02, reasonPhrase);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsedFrame.ReasonPhrase));

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedFrame, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_AllowsMalformedUtf8ReasonPhraseBytes()
    {
        byte[] reasonPhrase = [0xC3, 0x28];
        QuicConnectionCloseFrame frame = new(QuicTransportErrorCode.ProtocolViolation, triggeringFrameType: 0x02, reasonPhrase);
        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsedFrame.ReasonPhrase));
    }
}

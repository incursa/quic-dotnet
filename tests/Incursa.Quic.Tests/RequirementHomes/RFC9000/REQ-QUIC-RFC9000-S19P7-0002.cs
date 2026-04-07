namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0002")]
public sealed class REQ_QUIC_RFC9000_S19P7_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewTokenFrame_EncodesTheTokenLengthAsAVariableLengthInteger()
    {
        byte[] token = new byte[64];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = (byte)index;
        }

        QuicNewTokenFrame frame = new(token);
        Span<byte> destination = stackalloc byte[128];

        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(frame, destination, out int bytesWritten));
        Assert.Equal(67, bytesWritten);
        Assert.Equal(0x07, destination[0]);
        Assert.Equal(0x40, destination[1]);
        Assert.Equal(0x40, destination[2]);
    }
}

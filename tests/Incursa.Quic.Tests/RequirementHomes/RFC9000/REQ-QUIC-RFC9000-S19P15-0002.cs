namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
public sealed class REQ_QUIC_RFC9000_S19P15_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewConnectionIdFrame_RejectsDifferentFrameType()
    {
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];

        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(
            new QuicNewConnectionIdFrame(0x06, 0x04, connectionId, statelessResetToken));
        encoded[0] = 0x19;

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out _, out _));
    }
}

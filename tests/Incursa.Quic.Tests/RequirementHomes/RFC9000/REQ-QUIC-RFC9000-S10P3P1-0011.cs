namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3P1-0011")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryHandlePotentialStatelessReset_TransitionsToDrainingWhenTheTokenMatches()
    {
        byte[] statelessResetToken =
        [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F,
        ];

        Span<byte> datagram = stackalloc byte[QuicStatelessReset.MinimumDatagramLength];
        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            QuicStatelessReset.MinimumDatagramLength,
            datagram,
            out int bytesWritten));

        QuicConnectionLifecycleState state = new();
        Assert.True(state.TryHandlePotentialStatelessReset(datagram[..bytesWritten], statelessResetToken));
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
        Assert.False(state.TryHandlePotentialStatelessReset(datagram[..bytesWritten], statelessResetToken));
    }
}

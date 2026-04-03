namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3P1-0001")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetTrailingStatelessResetToken_UsesTheTrailingSixteenBytes()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x30);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);

        Assert.True(QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram, out ReadOnlySpan<byte> trailingToken));
        Assert.True(token.AsSpan().SequenceEqual(trailingToken));
    }
}

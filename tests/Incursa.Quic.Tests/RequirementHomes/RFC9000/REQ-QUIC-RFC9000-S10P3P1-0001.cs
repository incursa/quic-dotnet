namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P1-0001">An endpoint MUST use the trailing 16 bytes of the UDP datagram to detect a potential Stateless Reset.</workbench-requirement>
/// </workbench-requirements>
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

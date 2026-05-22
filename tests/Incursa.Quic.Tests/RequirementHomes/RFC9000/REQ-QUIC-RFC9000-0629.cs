namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0629">An endpoint MUST detect a potential Stateless Reset using the trailing 16 bytes of the UDP datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0629")]
public sealed class REQ_QUIC_RFC9000_0629
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetTrailingStatelessResetToken_DetectsPotentialResetUsingTheTrailingSixteenBytes()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x40);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);

        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(datagram));
        Assert.True(QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram, out ReadOnlySpan<byte> trailingToken));
        Assert.True(token.AsSpan().SequenceEqual(trailingToken));
    }
}

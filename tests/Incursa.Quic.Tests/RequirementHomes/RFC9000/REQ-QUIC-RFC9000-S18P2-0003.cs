namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0003">A stateless reset token MUST be used in verifying a stateless reset; see Section 10.3.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S18P2-0003")]
public sealed class REQ_QUIC_RFC9000_S18P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0003">A stateless reset token MUST be used in verifying a stateless reset; see Section 10.3.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18P2-0003")]
    public void MatchesAnyStatelessResetToken_UsesTheTrailingSixteenBytes()
    {
        byte[] matchingToken = QuicStatelessResetRequirementTestData.CreateToken(0x30);
        byte[] nonMatchingToken = QuicStatelessResetRequirementTestData.CreateToken(0x50);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(matchingToken);

        Span<byte> candidateTokens = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength * 2];
        nonMatchingToken.AsSpan().CopyTo(candidateTokens);
        matchingToken.AsSpan().CopyTo(candidateTokens[QuicStatelessReset.StatelessResetTokenLength..]);

        Assert.True(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, candidateTokens));
        Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, nonMatchingToken));
    }
}

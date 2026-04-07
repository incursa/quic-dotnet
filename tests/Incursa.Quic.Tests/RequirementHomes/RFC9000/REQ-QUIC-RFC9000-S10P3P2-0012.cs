namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P2-0012">An endpoint that uses this design MUST NOT provide a zero-length connection ID.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P2-0012")]
public sealed class REQ_QUIC_RFC9000_S10P3P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGenerateStatelessResetToken_RejectsZeroLengthConnectionIds()
    {
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.False(QuicStatelessReset.TryGenerateStatelessResetToken([], [0xAA, 0xBB], token, out _));
    }
}

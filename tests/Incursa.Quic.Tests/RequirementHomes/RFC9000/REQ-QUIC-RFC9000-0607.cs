namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0607">A stateless reset token MUST be specific to a connection ID.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0607")]
public sealed class REQ_QUIC_RFC9000_0607
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGenerateStatelessResetToken_BindsEachConnectionIdToItsOwnToken()
    {
        byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret();
        byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(0x10);
        byte[] otherConnectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(0x20);

        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        Span<byte> repeatedToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        Span<byte> otherToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, repeatedToken, out int repeatedBytesWritten));
        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(otherConnectionId, secretKey, otherToken, out int otherBytesWritten));

        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, repeatedBytesWritten);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, otherBytesWritten);
        Assert.True(token.SequenceEqual(repeatedToken));
        Assert.False(token.SequenceEqual(otherToken));
    }
}

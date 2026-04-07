namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0016">The stateless reset token MUST be difficult to guess.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0016")]
public sealed class REQ_QUIC_RFC9000_S10P3_0016
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGenerateStatelessResetToken_BindsTheTokenToTheConnectionId()
    {
        byte[] secretKey = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] otherConnectionId = [0x20, 0x21, 0x22, 0x23];

        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        Span<byte> otherConnectionToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(otherConnectionId, secretKey, otherConnectionToken, out int otherConnectionBytesWritten));

        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, otherConnectionBytesWritten);
        Assert.False(token.SequenceEqual(otherConnectionToken));
    }
}

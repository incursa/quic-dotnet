using System.Security.Cryptography;

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

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGenerateStatelessResetToken_AcceptsNonZeroLengthConnectionIds()
    {
        byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(length: 4);
        byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret();

        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);

        using HMACSHA256 hmac = new(secretKey);
        byte[] expectedHash = hmac.ComputeHash(connectionId);
        Assert.True(expectedHash.AsSpan(..QuicStatelessReset.StatelessResetTokenLength).SequenceEqual(token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryGenerateStatelessResetToken_AcceptsMinimumNonZeroLengthConnectionIds()
    {
        byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(length: 1);
        byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(length: 1);

        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);

        using HMACSHA256 hmac = new(secretKey);
        byte[] expectedHash = hmac.ComputeHash(connectionId);
        Assert.True(expectedHash.AsSpan(..QuicStatelessReset.StatelessResetTokenLength).SequenceEqual(token));
    }
}

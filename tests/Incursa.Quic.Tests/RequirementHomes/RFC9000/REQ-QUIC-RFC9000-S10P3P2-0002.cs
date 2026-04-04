using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P2-0002">The output of this function MUST be truncated to 16 bytes to produce the stateless reset token for that connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P2-0002")]
public sealed class REQ_QUIC_RFC9000_S10P3P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGenerateStatelessResetToken_TruncatesTheHashToSixteenBytes()
    {
        byte[] secretKey =
        [
            0x90, 0x91, 0x92, 0x93,
            0x94, 0x95, 0x96, 0x97,
        ];

        byte[] connectionId =
        [
            0x10, 0x11, 0x12, 0x13,
        ];

        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);

        using HMACSHA256 hmac = new(secretKey);
        byte[] expectedHash = hmac.ComputeHash(connectionId);
        Assert.True(expectedHash.AsSpan(..QuicStatelessReset.StatelessResetTokenLength).SequenceEqual(token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGenerateStatelessResetToken_RejectsDestinationsThatCannotHoldSixteenBytes()
    {
        byte[] secretKey =
        [
            0x90, 0x91, 0x92, 0x93,
            0x94, 0x95, 0x96, 0x97,
        ];

        byte[] connectionId =
        [
            0x10, 0x11, 0x12, 0x13,
        ];

        Span<byte> tooShortDestination = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength - 1];

        Assert.False(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, tooShortDestination, out _));
    }
}

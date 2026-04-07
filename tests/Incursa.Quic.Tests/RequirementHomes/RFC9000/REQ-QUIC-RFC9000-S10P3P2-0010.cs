using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P2-0010">A single static key MAY be used across all connections to the same endpoint by generating the proof using a pseudorandom function that takes a static key and the connection ID chosen by the endpoint as input.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P2-0010")]
public sealed class REQ_QUIC_RFC9000_S10P3P2_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGenerateStatelessResetToken_UsesAStaticKeyAcrossConnections()
    {
        byte[] secretKey = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] otherConnectionId = [0x20, 0x21, 0x22, 0x23];

        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        Span<byte> otherToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, otherToken, out int otherBytesWritten));

        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, otherBytesWritten);
        Assert.True(token.SequenceEqual(otherToken));

        Span<byte> expected = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        using HMACSHA256 hmac = new(secretKey);
        byte[] expectedHash = hmac.ComputeHash(connectionId);
        expectedHash.AsSpan(..QuicStatelessReset.StatelessResetTokenLength).CopyTo(expected);
        Assert.True(expected.SequenceEqual(token));

        Span<byte> otherConnectionToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(otherConnectionId, secretKey, otherConnectionToken, out int otherConnectionBytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, otherConnectionBytesWritten);
        Assert.False(token.SequenceEqual(otherConnectionToken));
    }
}

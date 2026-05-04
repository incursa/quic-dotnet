namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P1P4-0001")]
public sealed class REQ_QUIC_RFC9000_S8P1P4_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IssueNewToken_ProducesUniqueHardToGuessTokensForTheSameAddress()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        byte[] first = protector.IssueNewToken("203.0.113.10", issuedAt);
        byte[] second = protector.IssueNewToken("203.0.113.10", issuedAt);

        Assert.Equal(QuicAddressValidationTokenProtector.TokenLength, first.Length);
        Assert.Equal(QuicAddressValidationTokenProtector.TokenLength, second.Length);
        Assert.False(first.AsSpan().SequenceEqual(second));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(first, "203.0.113.10", issuedAt.AddSeconds(1)));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(second, "203.0.113.10", issuedAt.AddSeconds(1)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidateNewToken_RejectsGuessedTokenBytes()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        byte[] guessedToken = new byte[QuicAddressValidationTokenProtector.TokenLength];

        Assert.NotEqual(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(guessedToken, "203.0.113.10", DateTimeOffset.FromUnixTimeSeconds(1_800_000_001)));
    }

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(5));
    }

    private static byte[] CreateSecret()
    {
        byte[] secret = new byte[QuicAddressValidationTokenProtector.SecretLength];
        for (int index = 0; index < secret.Length; index++)
        {
            secret[index] = unchecked((byte)(0x30 + index));
        }

        return secret;
    }
}

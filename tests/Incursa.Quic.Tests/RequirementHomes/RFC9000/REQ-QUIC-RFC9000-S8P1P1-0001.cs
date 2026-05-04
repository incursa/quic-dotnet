namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P1P1-0001")]
public sealed class REQ_QUIC_RFC9000_S8P1P1_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IssuedNewToken_CarriesNewTokenProvenance()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        byte[] token = protector.IssueNewToken(
            "203.0.113.10",
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

        Assert.True(QuicAddressValidationTokenProtector.TryIdentifyTokenSource(
            token,
            out QuicAddressValidationTokenSource source));
        Assert.Equal(QuicAddressValidationTokenSource.NewToken, source);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P1-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnknownTokenBytes_DoNotIdentifyAsNewTokenProvenance()
    {
        byte[] token = new byte[QuicAddressValidationTokenProtector.TokenLength];

        Assert.False(QuicAddressValidationTokenProtector.TryIdentifyTokenSource(
            token,
            out _));
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
            secret[index] = unchecked((byte)(0x20 + index));
        }

        return secret;
    }
}

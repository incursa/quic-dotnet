namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P4-0007">Retry tokens MUST be invalidated after a short period.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P4-0007")]
public sealed class REQ_QUIC_RFC9000_S8P1P4_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void PortBoundRetryTokenValidation_AcceptsTokenThroughExpirationBoundary()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", 4433, issuedAt, TimeSpan.FromMinutes(1));

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(token, "203.0.113.10", 4433, issuedAt.AddSeconds(30)));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(token, "203.0.113.10", 4433, issuedAt.AddMinutes(1)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PortBoundRetryTokenValidation_RejectsTokenAfterShortLifetime()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", 4433, issuedAt, TimeSpan.FromMinutes(1));

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Expired,
            protector.ValidateNewToken(token, "203.0.113.10", 4433, issuedAt.AddMinutes(1).AddSeconds(1)));
    }

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(10));
    }

    private static byte[] CreateSecret()
    {
        byte[] secret = new byte[QuicAddressValidationTokenProtector.SecretLength];
        for (int index = 0; index < secret.Length; index++)
        {
            secret[index] = unchecked((byte)(0xD0 + index));
        }

        return secret;
    }
}

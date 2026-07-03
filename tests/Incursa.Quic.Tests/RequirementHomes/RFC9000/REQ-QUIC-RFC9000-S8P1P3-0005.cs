// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-3-P3-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0005
{
    [Fact]
    [Requirement("RFC9000-S8-1-3-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidateNewToken_AcceptsTokenBeforeItsExpirationTime()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", issuedAt);

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(token, "203.0.113.10", issuedAt.AddSeconds(30)));
    }

    [Fact]
    [Requirement("RFC9000-S8-1-3-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ValidateNewToken_RejectsTokenAfterItsExpirationTime()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", issuedAt);

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Expired,
            protector.ValidateNewToken(token, "203.0.113.10", issuedAt.AddSeconds(61)));
    }

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(1));
    }

    private static byte[] CreateSecret()
    {
        byte[] secret = new byte[QuicAddressValidationTokenProtector.SecretLength];
        for (int index = 0; index < secret.Length; index++)
        {
            secret[index] = unchecked((byte)(0x60 + index));
        }

        return secret;
    }
}

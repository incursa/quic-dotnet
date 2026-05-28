// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P1P4-0010")]
public sealed class REQ_QUIC_RFC9000_S8P1P4_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IssueNewToken_CombinesRandomUniquenessWithIntegrityProtection()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        byte[] first = protector.IssueNewToken("203.0.113.10", issuedAt);
        byte[] second = protector.IssueNewToken("203.0.113.10", issuedAt);

        Assert.False(first.AsSpan().SequenceEqual(second));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(first, "203.0.113.10", issuedAt.AddSeconds(1)));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(second, "203.0.113.10", issuedAt.AddSeconds(1)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidateNewToken_RejectsFalsifiedHardToGuessToken()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", issuedAt);
        token[12] ^= 0x80;

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.IntegrityFailure,
            protector.ValidateNewToken(token, "203.0.113.10", issuedAt.AddSeconds(1)));
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
            secret[index] = unchecked((byte)(0x70 + index));
        }

        return secret;
    }
}

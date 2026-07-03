// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-4-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S8P1P4_0002
{
    [Fact]
    [Requirement("RFC9000-S8-1-4-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidateNewToken_AcceptsIntegrityProtectedToken()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", issuedAt);

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(token, "203.0.113.10", issuedAt.AddSeconds(1)));
    }

    [Fact]
    [Requirement("RFC9000-S8-1-4-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidateNewToken_RejectsModifiedTokenBytes()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", issuedAt);
        token[^1] ^= 0x01;

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.IntegrityFailure,
            protector.ValidateNewToken(token, "203.0.113.10", issuedAt.AddSeconds(1)));
    }

    [Fact]
    [Requirement("RFC9000-S8-1-4-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void FuzzNewTokenValidation_RejectsTruncationAndSingleByteMutation()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", issuedAt);

        for (int length = 0; length < token.Length; length++)
        {
            Assert.NotEqual(
                QuicAddressValidationTokenValidationResult.Valid,
                protector.ValidateNewToken(token.AsSpan(0, length), "203.0.113.10", issuedAt.AddSeconds(1)));
        }

        Random random = new(9000);
        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte[] mutated = token.ToArray();
            int offset = random.Next(mutated.Length);
            mutated[offset] ^= (byte)random.Next(1, 256);

            Assert.NotEqual(
                QuicAddressValidationTokenValidationResult.Valid,
                protector.ValidateNewToken(mutated, "203.0.113.10", issuedAt.AddSeconds(1)));
        }
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
            secret[index] = unchecked((byte)(0x40 + index));
        }

        return secret;
    }
}

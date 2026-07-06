// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-3-P4-S3-R01")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IssueNewToken_ProducesDistinctTokensForDifferentClients()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        byte[] first = protector.IssueNewToken("203.0.113.10", issuedAt);
        byte[] second = protector.IssueNewToken("203.0.113.11", issuedAt);

        Assert.False(first.AsSpan().SequenceEqual(second));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(first, "203.0.113.10", issuedAt.AddSeconds(1)));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(second, "203.0.113.11", issuedAt.AddSeconds(1)));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.IntegrityFailure,
            protector.ValidateNewToken(first, "203.0.113.11", issuedAt.AddSeconds(1)));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.IntegrityFailure,
            protector.ValidateNewToken(second, "203.0.113.10", issuedAt.AddSeconds(1)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewTokenIssuanceIsUniqueAcrossClientAddressVariants()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        string[] clientAddresses =
        [
            "203.0.113.10",
            "203.0.113.11",
            "198.51.100.20",
            "2001:db8::20",
        ];

        List<(string ClientAddress, byte[] Token)> issuedTokens = [];
        foreach (string clientAddress in clientAddresses)
        {
            issuedTokens.Add((clientAddress, protector.IssueNewToken(clientAddress, issuedAt)));
            issuedTokens.Add((clientAddress, protector.IssueNewToken(clientAddress, issuedAt)));
        }

        Assert.Equal(
            issuedTokens.Count,
            issuedTokens.Select(item => Convert.ToHexString(item.Token)).Distinct(StringComparer.Ordinal).Count());

        foreach ((string clientAddress, byte[] token) in issuedTokens)
        {
            Assert.Equal(
                QuicAddressValidationTokenValidationResult.Valid,
                protector.ValidateNewToken(token, clientAddress, issuedAt.AddSeconds(1)));

            foreach (string otherAddress in clientAddresses.Where(address => !StringComparer.Ordinal.Equals(address, clientAddress)))
            {
                Assert.Equal(
                    QuicAddressValidationTokenValidationResult.IntegrityFailure,
                    protector.ValidateNewToken(token, otherAddress, issuedAt.AddSeconds(1)));
            }
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
            secret[index] = unchecked((byte)(0x70 + index));
        }

        return secret;
    }
}

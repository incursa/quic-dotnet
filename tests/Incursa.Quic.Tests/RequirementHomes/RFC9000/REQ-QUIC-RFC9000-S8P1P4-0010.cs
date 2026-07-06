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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IssueNewTokenProducesUniqueIntegrityProtectedTokensForAddressContexts()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        (string RemoteAddress, int? RemotePort)[] contexts =
        [
            ("203.0.113.10", null),
            ("203.0.113.10", 443),
            ("2001:db8::1", null),
        ];

        foreach ((string remoteAddress, int? remotePort) in contexts)
        {
            byte[][] tokens =
            [
                IssueNewToken(protector, remoteAddress, remotePort, issuedAt),
                IssueNewToken(protector, remoteAddress, remotePort, issuedAt),
                IssueNewToken(protector, remoteAddress, remotePort, issuedAt.AddSeconds(1)),
            ];

            Assert.Equal(tokens.Length, tokens.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count());

            foreach (byte[] token in tokens)
            {
                Assert.Equal(
                    QuicAddressValidationTokenValidationResult.Valid,
                    ValidateNewToken(protector, token, remoteAddress, remotePort, issuedAt.AddSeconds(2)));

                foreach (int mutationOffset in new[] { 6, 12, 21, 38, 55, 69 })
                {
                    byte[] falsified = (byte[])token.Clone();
                    falsified[mutationOffset] ^= 0x5A;

                    Assert.Equal(
                        QuicAddressValidationTokenValidationResult.IntegrityFailure,
                        ValidateNewToken(protector, falsified, remoteAddress, remotePort, issuedAt.AddSeconds(2)));
                }
            }
        }
    }

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(5));
    }

    private static byte[] IssueNewToken(
        QuicAddressValidationTokenProtector protector,
        string remoteAddress,
        int? remotePort,
        DateTimeOffset issuedAt)
    {
        return remotePort.HasValue
            ? protector.IssueNewToken(remoteAddress, remotePort.Value, issuedAt)
            : protector.IssueNewToken(remoteAddress, issuedAt);
    }

    private static QuicAddressValidationTokenValidationResult ValidateNewToken(
        QuicAddressValidationTokenProtector protector,
        ReadOnlySpan<byte> token,
        string remoteAddress,
        int? remotePort,
        DateTimeOffset now)
    {
        return remotePort.HasValue
            ? protector.ValidateNewToken(token, remoteAddress, remotePort.Value, now)
            : protector.ValidateNewToken(token, remoteAddress, now);
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

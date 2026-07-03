// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-3-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0006
{
    [Fact]
    [Requirement("RFC9000-S8-1-3-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IssueNewToken_UsesAnOpaqueEnvelopeWithoutPlaintextConnectionMetadata()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        byte[] token = protector.IssueNewToken("203.0.113.10", 443, issuedAt);

        Assert.Equal(QuicAddressValidationTokenProtector.TokenLength, token.Length);
        Assert.True(QuicAddressValidationTokenProtector.TryIdentifyTokenSource(
            token,
            out QuicAddressValidationTokenSource source));
        Assert.Equal(QuicAddressValidationTokenSource.NewToken, source);
        Assert.True(QuicAddressValidationTokenProtector.TryGetNewTokenExpiration(
            token,
            out DateTimeOffset expiresAt));
        Assert.Equal(issuedAt.AddMinutes(1), expiresAt);

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(token, "203.0.113.10", 443, issuedAt.AddSeconds(1)));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.IntegrityFailure,
            protector.ValidateNewToken(token, "203.0.113.11", 444, issuedAt.AddSeconds(1)));

        Assert.True(token.AsSpan(0, 4).SequenceEqual("IQAT"u8));
        Assert.Equal(1, token[4]);
        Assert.Equal(1, token[5]);
        Assert.Equal(32, token.Length - 38);
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
            secret[index] = unchecked((byte)(0x50 + index));
        }

        return secret;
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-1-P1-R01")]
public sealed class REQ_QUIC_RFC9000_0381
{
    [Fact]
    [Requirement("RFC9000-S8-1-1-P1-R01")]
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
    [Requirement("RFC9000-S8-1-1-P1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnknownTokenBytes_DoNotIdentifyAsNewTokenProvenance()
    {
        byte[] token = new byte[QuicAddressValidationTokenProtector.TokenLength];

        Assert.False(QuicAddressValidationTokenProtector.TryIdentifyTokenSource(
            token,
            out _));
    }

    [Fact]
    [Requirement("RFC9000-S8-1-1-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewTokenSourceIdentificationDependsOnIssuedTokenEnvelope()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        foreach (string remoteAddress in new[] { "203.0.113.10", "198.51.100.20", "2001:db8::20" })
        {
            byte[] token = protector.IssueNewToken(remoteAddress, issuedAt);

            Assert.True(QuicAddressValidationTokenProtector.TryIdentifyTokenSource(
                token,
                out QuicAddressValidationTokenSource source));
            Assert.Equal(QuicAddressValidationTokenSource.NewToken, source);

            foreach (byte[] invalidEnvelope in CreateInvalidTokenEnvelopes(token))
            {
                Assert.False(QuicAddressValidationTokenProtector.TryIdentifyTokenSource(
                    invalidEnvelope,
                    out _));
            }
        }
    }

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(5));
    }

    private static byte[][] CreateInvalidTokenEnvelopes(byte[] validToken)
    {
        byte[] badMagic = (byte[])validToken.Clone();
        badMagic[0] ^= 0x80;

        byte[] badVersion = (byte[])validToken.Clone();
        badVersion[4] ^= 0x01;

        byte[] badSource = (byte[])validToken.Clone();
        badSource[5] ^= 0x01;

        byte[] shortToken = validToken[..(validToken.Length - 1)];

        byte[] longToken = new byte[validToken.Length + 1];
        validToken.CopyTo(longToken, 0);

        return [badMagic, badVersion, badSource, shortToken, longToken];
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

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S10P3P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StaticKeyTokenFuzz_TruncatesHmacOutputToSixteenBytes()
    {
        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(
                start: (byte)(0x10 + iteration),
                length: 1 + (iteration % QuicConnectionIdKey.MaximumLength));
            byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(
                start: (byte)(0x80 + iteration),
                length: 1 + (iteration % 32));
            byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] repeatedToken = new byte[QuicStatelessReset.StatelessResetTokenLength];

            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, repeatedToken, out int repeatedBytesWritten));
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, repeatedBytesWritten);
            Assert.True(token.SequenceEqual(repeatedToken));

            using HMACSHA256 hmac = new(secretKey);
            byte[] expectedHash = hmac.ComputeHash(connectionId);
            Assert.True(expectedHash.AsSpan(..QuicStatelessReset.StatelessResetTokenLength).SequenceEqual(token));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StaticKeyTokenFuzz_UsesConnectionIdAsPseudorandomFunctionInput()
    {
        byte[] staticKey = QuicStatelessResetRequirementTestData.CreateSecret(start: 0x90, length: 32);
        HashSet<string> generatedTokens = [];

        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(
                start: (byte)(0x20 + iteration),
                length: 4 + (iteration % 12));
            byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];

            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, staticKey, token, out int bytesWritten));
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
            Assert.True(generatedTokens.Add(Convert.ToHexString(token)));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StaticKeyTokenFuzz_RejectsZeroLengthConnectionIds()
    {
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        for (int secretLength = 1; secretLength <= 32; secretLength++)
        {
            byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(
                start: (byte)(0x40 + secretLength),
                length: secretLength);

            Assert.False(QuicStatelessReset.TryGenerateStatelessResetToken([], secretKey, token, out int bytesWritten));
            Assert.Equal(0, bytesWritten);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StaticKeyTokenFuzz_AcceptsEveryNonZeroConnectionIdLength()
    {
        byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(start: 0xA0, length: 32);

        for (int connectionIdLength = 1; connectionIdLength <= QuicConnectionIdKey.MaximumLength; connectionIdLength++)
        {
            byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(
                start: (byte)(0x60 + connectionIdLength),
                length: connectionIdLength);
            byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] zeroToken = new byte[QuicStatelessReset.StatelessResetTokenLength];

            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
            Assert.False(token.SequenceEqual(zeroToken));
        }
    }
}

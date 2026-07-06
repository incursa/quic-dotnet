// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S10-3-2-P5-S2-R01">This method for choosing the stateless reset token means that the combination of connection ID and static key MUST NOT be used for another connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-3-2-P5-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S10P3P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGenerateStatelessResetToken_ProducesAStableTokenForAConnectionIdAndStaticKey()
    {
        byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(start: 0x41);
        byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(start: 0x91);
        Span<byte> firstToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        Span<byte> secondToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, firstToken, out int bytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, secondToken, out int secondBytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, secondBytesWritten);
        Assert.True(firstToken.SequenceEqual(secondToken));

        using HMACSHA256 hmac = new(secretKey);
        byte[] expectedHash = hmac.ComputeHash(connectionId);
        Assert.True(expectedHash.AsSpan(..QuicStatelessReset.StatelessResetTokenLength).SequenceEqual(firstToken));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterStatelessResetToken_RejectsReusingTheSameConnectionIdAndStaticKeyCombinationForASecondConnection()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.146");
        byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(start: 0x42);
        byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(start: 0x92);
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out _));
        byte[] tokenBytes = token.ToArray();

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, pathIdentity));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, connectionId, statelessResetConnectionId: 901UL));
        Assert.True(endpoint.TryRegisterStatelessResetToken(firstHandle, 901UL, tokenBytes));

        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, pathIdentity));
        Assert.False(endpoint.TryRegisterConnectionId(secondHandle, connectionId, statelessResetConnectionId: 902UL));
        Assert.False(endpoint.TryRegisterStatelessResetToken(secondHandle, 902UL, tokenBytes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryGenerateStatelessResetToken_AcceptsMinimumLengthConnectionIdAndStaticKey()
    {
        byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(start: 0x11, length: 1);
        byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(start: 0xA1, length: 1);
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);

        using HMACSHA256 hmac = new(secretKey);
        byte[] expectedHash = hmac.ComputeHash(connectionId);
        Assert.True(expectedHash.AsSpan(..QuicStatelessReset.StatelessResetTokenLength).SequenceEqual(token));
    }

    [Fact]
    [Requirement("RFC9000-S10-3-2-P5-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGenerateStatelessResetToken_IsStableOnlyForTheSameConnectionIdAndStaticKey()
    {
        for (int index = 0; index < 5; index++)
        {
            byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(
                start: (byte)(0x50 + index),
                length: 1 + index);
            byte[] changedConnectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(
                start: (byte)(0x60 + index),
                length: 1 + index);
            byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(
                start: (byte)(0xA0 + index),
                length: 1 + index);
            byte[] changedSecretKey = QuicStatelessResetRequirementTestData.CreateSecret(
                start: (byte)(0xB0 + index),
                length: 1 + index);
            byte[] firstToken = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] repeatedToken = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] changedConnectionIdToken = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] changedSecretKeyToken = new byte[QuicStatelessReset.StatelessResetTokenLength];

            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, firstToken, out int bytesWritten));
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, repeatedToken, out _));
            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(changedConnectionId, secretKey, changedConnectionIdToken, out _));
            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, changedSecretKey, changedSecretKeyToken, out _));

            Assert.True(firstToken.SequenceEqual(repeatedToken));
            Assert.False(firstToken.SequenceEqual(changedConnectionIdToken));
            Assert.False(firstToken.SequenceEqual(changedSecretKeyToken));
        }
    }
}

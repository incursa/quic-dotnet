// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_StatelessReset_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0607")]
    [Requirement("REQ-QUIC-RFC9000-0644")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TokenGenerationFuzz_BindsAndRegeneratesTokensPerConnectionId()
    {
        foreach ((byte ConnectionIdStart, byte OtherConnectionIdStart, byte SecretStart) testCase in new (byte, byte, byte)[]
        {
            (0x10, 0x20, 0x90),
            (0x11, 0x31, 0x91),
            (0x12, 0x42, 0x92),
            (0x13, 0x53, 0x93),
        })
        {
            byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(testCase.SecretStart);
            byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(testCase.ConnectionIdStart);
            byte[] otherConnectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(testCase.OtherConnectionIdStart);
            byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] regeneratedToken = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] otherToken = new byte[QuicStatelessReset.StatelessResetTokenLength];

            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, regeneratedToken, out int regeneratedBytesWritten));
            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(otherConnectionId, secretKey, otherToken, out int otherBytesWritten));

            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, regeneratedBytesWritten);
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, otherBytesWritten);
            Assert.True(token.SequenceEqual(regeneratedToken));
            Assert.False(token.SequenceEqual(otherToken));

            byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
            Assert.True(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, token));
            Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, otherToken));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0610")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetiredTokenFuzz_RemovesOnlyTheRetiredStatelessResetToken()
    {
        foreach ((ulong RetiredSequence, ulong LiveSequence, byte RetiredTokenStart, byte LiveTokenStart) testCase in new (ulong, ulong, byte, byte)[]
        {
            (201UL, 202UL, 0x40, 0x50),
            (301UL, 302UL, 0x60, 0x70),
            (401UL, 402UL, 0x80, 0x90),
        })
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new($"203.0.113.{testCase.RetiredSequence % 100}");
            byte[] retiredToken = QuicStatelessResetRequirementTestData.CreateToken(testCase.RetiredTokenStart);
            byte[] liveToken = QuicStatelessResetRequirementTestData.CreateToken(testCase.LiveTokenStart);

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, testCase.RetiredSequence, retiredToken));
            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, testCase.LiveSequence, liveToken));
            Assert.True(endpoint.TryRetireStatelessResetToken(handle, testCase.RetiredSequence));

            QuicConnectionIngressResult retiredTokenResult = endpoint.ReceiveDatagram(
                QuicStatelessResetRequirementTestData.FormatDatagram(retiredToken),
                pathIdentity);
            QuicConnectionIngressResult liveTokenResult = endpoint.ReceiveDatagram(
                QuicStatelessResetRequirementTestData.FormatDatagram(liveToken),
                pathIdentity);

            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, retiredTokenResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, retiredTokenResult.HandlingKind);
            Assert.Null(retiredTokenResult.Handle);
            Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, liveTokenResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, liveTokenResult.HandlingKind);
            Assert.Equal(handle, liveTokenResult.Handle);
            Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
            Assert.Equal(0UL, runtime.TransitionSequence);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0622")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void LoopPreventionFuzz_RejectsStatelessResetDatagramsAtOrAboveThreeTimesTheTriggeringPacket()
    {
        foreach (int triggeringPacketLength in new[]
        {
            QuicStatelessReset.MinimumDatagramLength,
            22,
            63,
            100,
            1200,
        })
        {
            int justBelowLimit = (triggeringPacketLength * 3) - 1;
            int exactLimit = triggeringPacketLength * 3;

            Assert.True(QuicStatelessReset.CanSendStatelessReset(
                triggeringPacketLength,
                justBelowLimit,
                hasLoopPreventionState: true));
            Assert.False(QuicStatelessReset.CanSendStatelessReset(
                triggeringPacketLength,
                exactLimit,
                hasLoopPreventionState: true));
            Assert.False(QuicStatelessReset.CanSendStatelessReset(
                triggeringPacketLength,
                exactLimit + 1,
                hasLoopPreventionState: true));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0639")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MatchingTokenFuzz_EntersDrainingOnlyWhenTheDatagramTailMatches()
    {
        foreach ((byte TokenStart, byte NonMatchingTokenStart) testCase in new (byte, byte)[]
        {
            (0x20, 0x30),
            (0x40, 0x50),
            (0x60, 0x70),
            (0x80, 0x90),
        })
        {
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken(testCase.TokenStart);
            byte[] nonMatchingToken = QuicStatelessResetRequirementTestData.CreateToken(testCase.NonMatchingTokenStart);
            byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);

            QuicConnectionLifecycleState matchingState = new();
            Assert.True(matchingState.TryHandlePotentialStatelessReset(datagram, token));
            Assert.True(matchingState.IsDraining);
            Assert.False(matchingState.CanSendPackets);

            QuicConnectionLifecycleState nonMatchingState = new();
            Assert.False(nonMatchingState.TryHandlePotentialStatelessReset(datagram, nonMatchingToken));
            Assert.False(nonMatchingState.IsDraining);
            Assert.True(nonMatchingState.CanSendPackets);
        }
    }
}

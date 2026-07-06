// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S10P3P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P3P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StatelessResetTailTokenFuzz_UsesTrailingTokenAndEntersDrainingOnlyOnMatch()
    {
        for (int datagramLength = QuicStatelessReset.MinimumDatagramLength;
             datagramLength < QuicStatelessReset.MinimumDatagramLength + 64;
             datagramLength++)
        {
            byte tokenStart = (byte)(0x20 + datagramLength);
            byte[] earlierToken = QuicStatelessResetRequirementTestData.CreateToken((byte)(tokenStart + 0x20));
            byte[] trailingToken = QuicStatelessResetRequirementTestData.CreateToken(tokenStart);
            byte[] nonMatchingToken = QuicStatelessResetRequirementTestData.CreateToken((byte)(tokenStart + 0x40));
            byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(trailingToken, datagramLength);

            if (datagramLength >= (QuicStatelessReset.StatelessResetTokenLength * 2) + 1)
            {
                earlierToken.CopyTo(datagram, 1);
            }

            Assert.True(QuicStatelessReset.TryGetTrailingStatelessResetToken(
                datagram,
                out ReadOnlySpan<byte> detectedToken));
            Assert.True(trailingToken.AsSpan().SequenceEqual(detectedToken));
            Assert.False(earlierToken.AsSpan().SequenceEqual(detectedToken));

            byte[] candidateTokens = FlattenTokens(nonMatchingToken, trailingToken);
            QuicConnectionLifecycleState state = new();

            Assert.True(state.TryHandlePotentialStatelessReset(datagram, candidateTokens));
            Assert.True(state.IsDraining);
            Assert.False(state.CanSendPackets);
            Assert.False(state.TryHandlePotentialStatelessReset(datagram, candidateTokens));

            QuicConnectionLifecycleState nonMatchingState = new();
            Assert.False(nonMatchingState.TryHandlePotentialStatelessReset(datagram, FlattenTokens(nonMatchingToken, earlierToken)));
            Assert.False(nonMatchingState.IsDraining);
            Assert.True(nonMatchingState.CanSendPackets);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P1-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StatelessResetTokenRegistryFuzz_RemembersLiveTokensAndExcludesUnusedOrRetiredTokens()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 128);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.190", RemotePort: 443);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        for (int iteration = 0; iteration < 16; iteration++)
        {
            ulong connectionId = 700UL + (ulong)iteration;
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0x30 + iteration));

            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, connectionId, token));
            Assert.False(endpoint.TryRegisterStatelessResetToken(handle, connectionId, token));

            QuicConnectionStatelessResetEmissionResult emitted = endpoint.TryCreateStatelessResetDatagram(
                handle,
                connectionId,
                triggeringPacketLength: 90 + iteration,
                hasLoopPreventionState: true);

            Assert.True(emitted.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emitted.Disposition);
            Assert.Equal(pathIdentity, emitted.PathIdentity);
            Assert.Equal(89 + iteration, emitted.Datagram.Length);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emitted.Datagram.Span, token);

            QuicConnectionStatelessResetEmissionResult unused = endpoint.TryCreateStatelessResetDatagram(
                handle,
                connectionId + 10_000UL,
                triggeringPacketLength: 90 + iteration,
                hasLoopPreventionState: true);
            Assert.False(unused.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, unused.Disposition);

            Assert.True(endpoint.TryRetireStatelessResetToken(handle, connectionId));
            Assert.False(endpoint.TryRetireStatelessResetToken(handle, connectionId));

            QuicConnectionStatelessResetEmissionResult retired = endpoint.TryCreateStatelessResetDatagram(
                handle,
                connectionId,
                triggeringPacketLength: 90 + iteration,
                hasLoopPreventionState: true);

            Assert.False(retired.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, retired.Disposition);
        }
    }

    private static byte[] FlattenTokens(params byte[][] tokens)
    {
        byte[] flattened = new byte[tokens.Length * QuicStatelessReset.StatelessResetTokenLength];

        for (int index = 0; index < tokens.Length; index++)
        {
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, tokens[index].Length);
            tokens[index].CopyTo(flattened, index * QuicStatelessReset.StatelessResetTokenLength);
        }

        return flattened;
    }
}

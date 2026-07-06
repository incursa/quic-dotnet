// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2P5P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetryReplayFuzz_PreservesRequiredReplayFieldsAndDoesNotAckRetry()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
            byte[] retrySourceConnectionId = CreateBytes((byte)(0x30 + iteration), 1 + (iteration % QuicConnectionIdKey.MaximumLength));
            byte[] retryToken = CreateBytes((byte)(0x70 + iteration), 1 + (iteration % 16));
            QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                observedAtTicks: 1 + iteration,
                retrySourceConnectionId,
                retryToken);

            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryReceivedEvent.Datagram.Span, out _));

            QuicConnectionTransitionResult retryResult = runtime.Transition(
                retryReceivedEvent,
                nowTicks: 1 + iteration);

            QuicS17P2P5P3TestSupport.RetryReplayInitialPacket replayPacket =
                QuicS17P2P5P2TestSupport.ReadSingleRetryReplayInitialPacket(
                    retryResult,
                    retrySourceConnectionId);

            Assert.Equal(retrySourceConnectionId, replayPacket.DestinationConnectionId);
            Assert.Equal(retryToken, replayPacket.Token);
            Assert.Null(replayPacket.AckFrame);
            Assert.True(replayPacket.CryptoPayload.Length > 0);

            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                replayPacket.OpenedPacket,
                out _,
                out _,
                out _,
                out ReadOnlySpan<byte> openedSourceConnectionId,
                out _));
            Assert.Equal(QuicS17P2P5P2TestSupport.InitialSourceConnectionId, openedSourceConnectionId.ToArray());
            Assert.NotEqual(retrySourceConnectionId, openedSourceConnectionId.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetryReplayFuzz_RejectsZeroLengthRetrySourceConnectionIds()
    {
        for (int tokenLength = 1; tokenLength <= 16; tokenLength++)
        {
            using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
            QuicConnectionTransitionResult retryResult = runtime.Transition(
                new QuicConnectionRetryReceivedEvent(
                    ObservedAtTicks: tokenLength,
                    RetrySourceConnectionId: ReadOnlyMemory<byte>.Empty,
                    RetryToken: CreateBytes((byte)(0xA0 + tokenLength), tokenLength)),
                nowTicks: tokenLength);

            Assert.False(retryResult.StateChanged);
            Assert.Empty(retryResult.Effects);
        }
    }

    private static byte[] CreateBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }
}

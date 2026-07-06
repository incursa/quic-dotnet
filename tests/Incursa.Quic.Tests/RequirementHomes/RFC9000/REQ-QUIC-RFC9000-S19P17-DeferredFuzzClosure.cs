// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P17_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathChallengeMigrationFuzz_StartsValidationWithAChallengeOnNewPeerPaths()
    {
        QuicConnectionPathIdentity originalPath = new("203.0.113.70", RemotePort: 443);

        for (int iteration = 0; iteration < 12; iteration++)
        {
            using QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(originalPath);
            QuicConnectionPathIdentity migratedPath = new(
                $"203.0.113.{80 + iteration}",
                RemotePort: 443 + iteration);
            byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize + iteration];

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    migratedPath,
                    datagram),
                nowTicks: 20 + iteration);

            Assert.True(runtime.CandidatePaths.TryGetValue(
                migratedPath,
                out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
            Assert.Equal(QuicPathValidation.PathChallengeDataLength, candidatePath.Validation.ChallengePayload.Length);

            QuicConnectionSendDatagramEffect send = Assert.Single(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
            Assert.Equal(migratedPath, send.PathIdentity);
            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(
                send.Datagram.Span,
                out QuicPathChallengeFrame parsedChallenge,
                out int bytesConsumed));
            Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, bytesConsumed);
            Assert.Equal(QuicPathValidation.PathChallengeDataLength, parsedChallenge.Data.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathChallengeFrameFuzz_RoundTripsExactlyEightBytesOfArbitraryData()
    {
        byte[] destination = new byte[QuicPathValidation.PathChallengeDataLength + 1];

        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] data = CreateData((byte)(0x20 + iteration));
            QuicPathChallengeFrame frame = new(data);
            byte[] encoded = QuicFrameTestData.BuildPathChallengeFrame(frame);

            Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, encoded.Length);
            Assert.Equal(0x1A, encoded[0]);
            Assert.True(data.AsSpan().SequenceEqual(encoded.AsSpan(1)));

            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(encoded, out QuicPathChallengeFrame parsed, out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));

            Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination.AsSpan(0, bytesWritten)));
            Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(encoded[..^1], out _, out _));
        }
    }

    private static byte[] CreateData(byte seed)
    {
        byte[] data = new byte[QuicPathValidation.PathChallengeDataLength];
        for (int index = 0; index < data.Length; index++)
        {
            data[index] = unchecked((byte)(seed + (index * 17)));
        }

        return data;
    }
}

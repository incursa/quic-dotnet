// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-3-3-P5-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0502
{
    private static readonly byte[] PacketNumber =
    [
        0x00, 0x00, 0x00, 0x01,
    ];

    [Fact]
    [Requirement("RFC9000-S9-3-3-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathChallengeFramesOnTheActivePathAreAnsweredWithPathResponseFrames()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] challengeData =
        [
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
        ];
        byte[] applicationPayload = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value;

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x01],
            applicationPayload,
            material,
            declaredPacketNumberLength: 4);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                activePath,
                protectedPacket),
            nowTicks: 9);

        QuicConnectionSendDatagramEffect send =
            QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
                runtime,
                result,
                activePath,
                challengeData);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("RFC9000-S9-3-3-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PathChallengeFramesOnCandidatePathsRemainProbingUntilValidationCompletes()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity candidatePath = new("203.0.113.86", RemotePort: 443);
        byte[] challengeData =
        [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
        ];

        _ = QuicS8P2PathValidationTestSupport.StartCandidatePath(
            runtime,
            candidatePath,
            observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out _));

        QuicConnectionTransitionResult result = QuicS8P2PathValidationTestSupport.ReceiveProtectedPathChallenge(
            runtime,
            candidatePath,
            challengeData,
            packetNumber: 2,
            observedAtTicks: 21);

        QuicConnectionSendDatagramEffect send = Assert.Single(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(candidatePath, send.PathIdentity);
        Assert.True(QuicS8P2PathValidationTestSupport.TryOpenPathChallengePayload(
            runtime,
            send.Datagram.Span,
            out _,
            out _,
            out _));
        Assert.True(QuicS8P2PathValidationTestSupport.TryOpenPathResponsePayload(
            runtime,
            send.Datagram.Span,
            out QuicPathResponseFrame parsedResponse,
            out _,
            out _));
        Assert.True(challengeData.AsSpan().SequenceEqual(parsedResponse.Data));
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("RFC9000-S9-3-3-P5-S1-R01")]
    [Requirement("REQ-QUIC-RFC9000-0815")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PathChallengeFramesOnActivePathEmitOneMatchingPathResponse()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(runtime.ActivePath.HasValue);

            QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
            byte[] challengeData = BuildChallengeData(iteration);
            byte[] protectedPacket = BuildProtectedPathChallengePacket(runtime, challengeData);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 30 + iteration,
                    activePath,
                    protectedPacket),
                nowTicks: 30 + iteration);

            QuicConnectionSendDatagramEffect send =
                QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
                    runtime,
                    result,
                    activePath,
                    challengeData);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        }
    }

    private static byte[] BuildChallengeData(int iteration)
    {
        byte[] challengeData = new byte[QuicPathValidation.PathChallengeDataLength];
        for (int index = 0; index < challengeData.Length; index++)
        {
            challengeData[index] = (byte)((iteration * 17 + index * 31) & 0xFF);
        }

        return challengeData;
    }

    private static byte[] BuildProtectedPathChallengePacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> challengeData)
    {
        byte[] applicationPayload = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value;

        return QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            PacketNumber,
            applicationPayload,
            material,
            declaredPacketNumberLength: PacketNumber.Length);
    }
}

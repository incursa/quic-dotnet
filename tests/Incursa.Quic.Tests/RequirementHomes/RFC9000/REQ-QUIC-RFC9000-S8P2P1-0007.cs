// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-2-1-P7-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S8P2P1_0007
{
    [Fact]
    [Requirement("RFC9000-S8-2-1-P7-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TooSmallPacketContainingPathChallengeIsProcessed()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(0x30);
        byte[] pathChallengePayload = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData));
        byte[] protectedPacket = CreateProtectedApplicationPacket(runtime, pathChallengePayload, packetNumber: 0x30);
        Assert.InRange(protectedPacket.Length, 1, QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                activePath,
                protectedPacket),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
            runtime,
            result,
            activePath,
            challengeData);
    }

    [Fact]
    [Requirement("RFC9000-S8-2-1-P7-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TooSmallPacketContainingPathResponseIsNotDiscarded()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.128", RemotePort: 443);

        QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));

        byte[] pathResponsePayload = QuicFrameTestData.BuildPathResponseFrame(
            new QuicPathResponseFrame(candidate.Validation.ChallengePayload.Span));
        byte[] protectedPacket = CreateProtectedApplicationPacket(runtime, pathResponsePayload, packetNumber: 0x31);
        Assert.InRange(protectedPacket.Length, 1, QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 21,
                candidatePath,
                protectedPacket),
            nowTicks: 21);

        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(candidatePath, runtime.ActivePath!.Value.Identity);
    }

    private static byte[] CreateProtectedApplicationPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload,
        byte packetNumber)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        return QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, packetNumber],
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 4);
    }
}

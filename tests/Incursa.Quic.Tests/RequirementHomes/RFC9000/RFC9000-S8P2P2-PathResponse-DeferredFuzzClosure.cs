// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S8P2P2_PathResponse_DeferredFuzzClosure
{
    [Theory]
    [InlineData(0x21, 0, false)]
    [InlineData(0x31, 1, true)]
    [InlineData(0x41, 2, false)]
    [Requirement("RFC9000-S8-2-2-P1-S1-R01")]
    [Requirement("RFC9000-S8-2-2-P1-S2-R01")]
    [Requirement("RFC9000-S8-2-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathChallengeResponseFuzz_EchoesDataImmediatelyOnTheReceivedPath(
        int challengeSeed,
        int remotePortOffset,
        bool includePing)
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity receivedPath = activePath with
        {
            RemotePort = activePath.RemotePort + remotePortOffset,
        };
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(unchecked((byte)challengeSeed));

        QuicConnectionTransitionResult result =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathChallenge(
                runtime,
                receivedPath,
                challengeData,
                packetNumber: unchecked((byte)challengeSeed),
                observedAtTicks: 20 + remotePortOffset,
                includePing);

        Assert.True(result.StateChanged);
        QuicConnectionSendDatagramEffect response =
            QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
                runtime,
                result,
                receivedPath,
                challengeData,
                expectMinimumSize: receivedPath == activePath);
        Assert.Equal(receivedPath, response.PathIdentity);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionArmTimerEffect arm
                && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);
    }

    [Theory]
    [InlineData("203.0.113.141", 443, false)]
    [InlineData("203.0.113.142", 8443, true)]
    [InlineData("2001:db8::142", 443, true)]
    [Requirement("RFC9000-S8-2-2-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void InitiatorPathResponseFuzz_AcceptsOnlyMatchingCandidatePathWithoutPeerViolation(
        string candidateAddress,
        int candidatePort,
        bool respondOnCandidatePath)
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity candidatePath = new(candidateAddress, RemotePort: candidatePort);

        QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));

        QuicConnectionPathIdentity responsePath = respondOnCandidatePath
            ? candidatePath
            : activePath;
        QuicConnectionTransitionResult responseResult =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathResponse(
                runtime,
                responsePath,
                candidate.Validation.ChallengePayload.Span,
                packetNumber: 0x51,
                observedAtTicks: 21);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.ActivePath.HasValue);
        if (respondOnCandidatePath)
        {
            Assert.True(responseResult.StateChanged);
            Assert.Equal(candidatePath, runtime.ActivePath!.Value.Identity);
            Assert.DoesNotContain(runtime.CandidatePaths, entry => entry.Key == candidatePath);
        }
        else
        {
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord stillPendingCandidate));
            Assert.False(stillPendingCandidate.Validation.IsValidated);
            Assert.False(stillPendingCandidate.Validation.IsAbandoned);
            Assert.DoesNotContain(
                responseResult.Effects,
                effect => effect is QuicConnectionPromoteActivePathEffect promote
                    && promote.PathIdentity == candidatePath);
        }
    }
}

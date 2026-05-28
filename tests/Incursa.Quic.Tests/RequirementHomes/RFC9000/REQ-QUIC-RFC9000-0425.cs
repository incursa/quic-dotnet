// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0425")]
public sealed class REQ_QUIC_RFC9000_0425
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0425")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationFramesCanBeProcessedWithOtherFramesInTheSamePacket()
    {
        using QuicConnectionRuntime challengeRuntime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(challengeRuntime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = challengeRuntime.ActivePath!.Value.Identity;
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(0x10);

        QuicConnectionTransitionResult challengeResult =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathChallenge(
                challengeRuntime,
                activePath,
                challengeData,
                packetNumber: 0x20,
                observedAtTicks: 20,
                includePing: true);

        Assert.True(challengeResult.StateChanged);
        QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
            challengeRuntime,
            challengeResult,
            activePath,
            challengeData);

        using QuicConnectionRuntime responseRuntime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.120", RemotePort: 443);

        Assert.True(QuicS8P2PathValidationTestSupport.StartCandidatePath(
            responseRuntime,
            candidatePath,
            observedAtTicks: 30).StateChanged);
        Assert.True(responseRuntime.CandidatePaths.TryGetValue(
            candidatePath,
            out QuicConnectionCandidatePathRecord candidate));

        QuicConnectionTransitionResult responseResult =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathResponse(
                responseRuntime,
                candidatePath,
                candidate.Validation.ChallengePayload.Span,
                packetNumber: 0x21,
                observedAtTicks: 31,
                includePing: true);

        Assert.True(responseResult.StateChanged);
        Assert.True(responseRuntime.ActivePath.HasValue);
        Assert.Equal(candidatePath, responseRuntime.ActivePath!.Value.Identity);
    }
}

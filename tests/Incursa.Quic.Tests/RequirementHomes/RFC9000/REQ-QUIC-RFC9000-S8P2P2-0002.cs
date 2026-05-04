namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P2P2-0002")]
public sealed class REQ_QUIC_RFC9000_S8P2P2_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathResponseIsEmittedInTheSameTransitionAsThePathChallenge()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(0x40);

        QuicConnectionTransitionResult result =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathChallenge(
                runtime,
                activePath,
                challengeData,
                packetNumber: 0x40,
                observedAtTicks: 20);

        Assert.True(result.StateChanged);
        QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
            result,
            activePath,
            challengeData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PathResponseDoesNotArmApplicationSendDelayForLaterEmission()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(0x41);

        QuicConnectionTransitionResult result =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathChallenge(
                runtime,
                activePath,
                challengeData,
                packetNumber: 0x41,
                observedAtTicks: 20);

        QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
            result,
            activePath,
            challengeData);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionArmTimerEffect arm
                && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);
    }
}

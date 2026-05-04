namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P2P2-0003")]
public sealed class REQ_QUIC_RFC9000_S8P2P2_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathResponseIsSentOnThePathWhereThePathChallengeArrived()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(0x50);

        QuicConnectionTransitionResult result =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathChallenge(
                runtime,
                activePath,
                challengeData,
                packetNumber: 0x50,
                observedAtTicks: 20);

        QuicConnectionSendDatagramEffect response =
            QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
                result,
                activePath,
                challengeData);

        Assert.Equal(activePath, response.PathIdentity);
    }
}

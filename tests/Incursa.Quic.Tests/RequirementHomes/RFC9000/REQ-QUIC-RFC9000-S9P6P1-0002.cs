namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P1-0002")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientInitiatesPreferredAddressPathValidationWhenHandshakeIsConfirmed()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        QuicConnectionTransitionResult result = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path, runtime.ActivePath!.Value.Identity);
        QuicS9P6P1PreferredAddressTestSupport.AssertCandidatePathPendingValidation(runtime, preferredPath);
        QuicS9P6P1PreferredAddressTestSupport.AssertPathChallengeSent(runtime, result, preferredPath);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDoesNotStartPreferredAddressValidationWhenTheServerDidNotProvideOne()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path);

        QuicConnectionTransitionResult result = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Empty(runtime.CandidatePaths);
        QuicS9P6P1PreferredAddressTestSupport.AssertNoPathChallengeSent(result);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientSelectsTheIpv6PreferredAddressWhenTheActivePathUsesIpv6()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6: true);

        QuicConnectionTransitionResult result = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path, runtime.ActivePath!.Value.Identity);
        QuicS9P6P1PreferredAddressTestSupport.AssertCandidatePathPendingValidation(runtime, preferredPath);
        QuicS9P6P1PreferredAddressTestSupport.AssertPathChallengeSent(runtime, result, preferredPath);
    }
}


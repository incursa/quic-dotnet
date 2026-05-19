namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P1-0007")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientChoosesThePreferredAddressFamilyMatchingTheOriginalServerAddress()
    {
        AssertChoosesPreferredAddressFamily(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath());
        AssertChoosesPreferredAddressFamily(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6: true));
    }

    private static void AssertChoosesPreferredAddressFamily(
        QuicConnectionPathIdentity originalPath,
        QuicConnectionPathIdentity expectedPreferredPath)
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            originalPath,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());

        QuicConnectionTransitionResult result = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        QuicS9P6P1PreferredAddressTestSupport.AssertCandidatePathPendingValidation(runtime, expectedPreferredPath);
        Assert.DoesNotContain(runtime.CandidatePaths.Keys, path => path != expectedPreferredPath);
        QuicS9P6P1PreferredAddressTestSupport.AssertPathChallengeSent(runtime, result, expectedPreferredPath);
    }
}


namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P2-0005")]
public sealed class REQ_QUIC_RFC9000_S9P6P2_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerContinuesProcessingDelayedPacketsReceivedOnTheOldAddressAfterPreferredAddressValidationCompletes()
    {
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());

        QuicConnectionTransitionResult handshakeResult = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        Assert.True(handshakeResult.StateChanged);

        QuicConnectionTransitionResult validationResult = QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
            runtime,
            preferredPath,
            observedAtTicks: 40);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(preferredPath));

        QuicConnectionTransitionResult delayedResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            runtime.CurrentPeerDestinationConnectionId.Span,
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, [0x11, 0x22]),
            observedAtTicks: 50);

        Assert.True(delayedResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path));
        Assert.DoesNotContain(delayedResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect);
    }
}

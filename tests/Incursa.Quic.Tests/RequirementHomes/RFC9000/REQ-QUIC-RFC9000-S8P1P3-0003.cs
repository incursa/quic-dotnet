namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P3-0003">A client MUST NOT use the token provided in a Retry for future connections.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P3-0003")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetryReceived_UsesTheRetryTokenOnlyForTheImmediateReplayInitial()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionTransitionResult retryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(observedAtTicks: 1),
            nowTicks: 1);

        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket[] replayPackets =
            QuicS17P2P5P3TestSupport.ReadRetryReplayInitialPackets(
                retryResult,
                QuicS17P2P5P3TestSupport.CreateServerProtection());

        Assert.NotEmpty(replayPackets);
        Assert.All(replayPackets, packet =>
        {
            Assert.True(packet.Token.AsSpan().SequenceEqual(QuicS17P2P5P2TestSupport.RetryToken));
            Assert.False(packet.Token.AsSpan().SequenceEqual(QuicS8P1P3TokenLifecycleTestSupport.NewToken));
        });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreateForFutureConnection_RejectsRetryTokens()
    {
        Assert.False(QuicClientAddressValidationToken.TryCreate(
            QuicS17P2P5P2TestSupport.RetryToken,
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
            QuicVersionNegotiation.Version1,
            QuicAddressValidationTokenSource.Retry,
            out QuicClientAddressValidationToken? token));
        Assert.Null(token);
    }
}

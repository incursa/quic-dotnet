// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S8-1-3-P2-S4-R01">A client MUST NOT use the token provided in a Retry for future connections.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S8-1-3-P2-S4-R01")]
public sealed class REQ_QUIC_RFC9000_0392
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

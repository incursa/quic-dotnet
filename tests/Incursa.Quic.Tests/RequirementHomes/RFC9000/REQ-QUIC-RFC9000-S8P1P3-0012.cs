// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P3-0012">A Retry token MUST be used immediately during the connection attempt and MUST NOT be used in subsequent attempts.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P3-0012")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetryToken_IsUsedImmediatelyForTheReplayInitial()
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
            Assert.True(packet.Token.AsSpan().SequenceEqual(QuicS17P2P5P2TestSupport.RetryToken)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RetryToken_IsRejectedAsAFutureConnectionToken()
    {
        Assert.False(QuicClientAddressValidationToken.TryCreate(
            QuicS17P2P5P2TestSupport.RetryToken,
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
            QuicVersionNegotiation.Version1,
            QuicAddressValidationTokenSource.Retry,
            out QuicClientAddressValidationToken? token));
        Assert.Null(token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryTokensAreUsedOnlyForImmediateReplayAcrossTokenVariants()
    {
        (byte[] RetrySourceConnectionId, byte[] RetryToken)[] scenarios =
        [
            (QuicS17P2P5P2TestSupport.RetrySourceConnectionId, QuicS17P2P5P2TestSupport.RetryToken),
            (QuicS17P2P5P2TestSupport.RetrySourceConnectionId, QuicS17P2P5P2TestSupport.SingleByteRetryToken),
            (QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId, [0x81, 0x82, 0x83, 0x84, 0x85]),
        ];

        for (int scenarioIndex = 0; scenarioIndex < scenarios.Length; scenarioIndex++)
        {
            (byte[] retrySourceConnectionId, byte[] retryToken) = scenarios[scenarioIndex];
            using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

            QuicConnectionTransitionResult retryResult = runtime.Transition(
                QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                    observedAtTicks: scenarioIndex + 1,
                    retrySourceConnectionId,
                    retryToken),
                nowTicks: scenarioIndex + 1);

            QuicS17P2P5P3TestSupport.RetryReplayInitialPacket[] replayPackets =
                QuicS17P2P5P3TestSupport.ReadRetryReplayInitialPackets(
                    retryResult,
                    QuicS17P2P5P3TestSupport.CreateServerProtection(retrySourceConnectionId));

            Assert.NotEmpty(replayPackets);
            Assert.All(replayPackets, packet => Assert.True(packet.Token.AsSpan().SequenceEqual(retryToken)));
            Assert.False(QuicClientAddressValidationToken.TryCreate(
                retryToken,
                QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
                QuicVersionNegotiation.Version1,
                QuicAddressValidationTokenSource.Retry,
                out QuicClientAddressValidationToken? token));
            Assert.Null(token);
        }
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S5P1P1P4_ConnectionIdPool_DeferredFuzzClosure
{
    [Theory]
    [InlineData(0xA0)]
    [InlineData(0xB0)]
    [InlineData(0xC0)]
    [Requirement("RFC9000-S5-1-1-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetiredIssuedConnectionIdFuzz_ReplenishesThePeerConnectionIdPool(int seed)
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] issuedConnectionId = CreateConnectionId(seed, length: 4);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(unchecked((byte)(seed + 0x10))),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 0).StateChanged);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL));
        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            issuedConnectionId,
            retirePayload,
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionRetireConnectionIdRouteEffect retireRoute
            && retireRoute.ConnectionId == 1UL
            && retireRoute.ConnectionIdBytes.ToArray().SequenceEqual(issuedConnectionId));
        QuicConnectionRegisterConnectionIdRouteEffect replacementRoute =
            Assert.Single(result.Effects.OfType<QuicConnectionRegisterConnectionIdRouteEffect>());
        QuicNewConnectionIdFrameProofSnapshot replacementFrame =
            Assert.Single(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));

        Assert.Equal(2UL, replacementRoute.ConnectionId);
        Assert.Equal(2UL, replacementFrame.SequenceNumber);
        Assert.Equal(0UL, replacementFrame.RetirePriorTo);
        Assert.True(replacementRoute.ConnectionIdBytes.ToArray().SequenceEqual(replacementFrame.ConnectionId));
    }

    [Theory]
    [InlineData(2UL)]
    [InlineData(3UL)]
    [InlineData(8UL)]
    [InlineData(16UL)]
    [Requirement("RFC9000-S5-1-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ActiveConnectionIdLimitFuzz_AdvertisesConfiguredLimit(ulong activeConnectionIdLimit)
    {
        QuicTransportParameters parameters = new()
        {
            ActiveConnectionIdLimit = activeConnectionIdLimit,
            InitialSourceConnectionId = [0xA0, 0xA1],
        };

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.Equal(activeConnectionIdLimit, parsed.ActiveConnectionIdLimit);
        Assert.True(parameters.InitialSourceConnectionId.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId));
    }

    [Theory]
    [InlineData(2UL, 0x20)]
    [InlineData(3UL, 0x40)]
    [InlineData(4UL, 0x60)]
    [Requirement("RFC9000-S5-1-1-P4-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TemporaryConnectionIdExcessFuzz_AllowsOnlyWhenRetirePriorToRemovesTheExcess(
        ulong activeConnectionIdLimit,
        int seed)
    {
        QuicConnectionPeerConnectionIdState state = new();

        for (ulong sequenceNumber = 1; sequenceNumber < activeConnectionIdLimit; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceNumber,
                retirePriorTo: 0UL,
                connectionIdStart: unchecked((byte)(seed + (int)sequenceNumber)),
                activeConnectionIdLimit,
                out QuicTransportErrorCode errorCode,
                out _,
                out ulong[] retiredSequenceNumbers));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.Empty(retiredSequenceNumbers);
        }

        Assert.Equal((int)activeConnectionIdLimit, state.ActiveConnectionIdCount);

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: activeConnectionIdLimit,
            retirePriorTo: 1UL,
            connectionIdStart: unchecked((byte)(seed + (int)activeConnectionIdLimit)),
            activeConnectionIdLimit,
            out QuicTransportErrorCode acceptanceCode,
            out bool destinationConnectionIdChanged,
            out ulong[] acceptedRetiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, acceptanceCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL], acceptedRetiredSequenceNumbers);
        Assert.Equal((int)activeConnectionIdLimit, state.ActiveConnectionIdCount);

        Assert.False(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: activeConnectionIdLimit + 1,
            retirePriorTo: 1UL,
            connectionIdStart: unchecked((byte)(seed + (int)activeConnectionIdLimit + 1)),
            activeConnectionIdLimit,
            out QuicTransportErrorCode rejectionCode,
            out bool rejectedDestinationChange,
            out ulong[] rejectedRetiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, rejectionCode);
        Assert.False(rejectedDestinationChange);
        Assert.Empty(rejectedRetiredSequenceNumbers);
        Assert.Equal((int)activeConnectionIdLimit, state.ActiveConnectionIdCount);
    }

    private static byte[] CreateConnectionId(int seed, int length)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = unchecked((byte)(seed + (index * 7)));
        }

        return connectionId;
    }
}

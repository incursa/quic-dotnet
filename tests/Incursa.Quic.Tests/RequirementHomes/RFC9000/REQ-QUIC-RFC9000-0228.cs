namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0228")]
public sealed class REQ_QUIC_RFC9000_0228
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetireConnectionIdFrame_ReplenishesTheAvailableIssuedConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] issuedConnectionId = [0xA0, 0xA1, 0xA2, 0xA3];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x20),
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
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retireRoute
                && retireRoute.ConnectionId == 1UL
                && retireRoute.ConnectionIdBytes.ToArray().SequenceEqual(issuedConnectionId));
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRetireStatelessResetTokenEffect retireToken
                && retireToken.ConnectionId == 1UL);

        QuicConnectionRegisterConnectionIdRouteEffect replacementRoute =
            Assert.Single(result.Effects.OfType<QuicConnectionRegisterConnectionIdRouteEffect>());
        QuicConnectionRegisterStatelessResetTokenEffect replacementToken =
            Assert.Single(result.Effects.OfType<QuicConnectionRegisterStatelessResetTokenEffect>());

        Assert.Equal(2UL, replacementRoute.ConnectionId);
        Assert.Equal(2UL, replacementToken.ConnectionId);
        Assert.Equal(8, replacementRoute.ConnectionIdBytes.Length);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, replacementToken.Token.Length);

        QuicNewConnectionIdFrameSnapshot replacementFrame = GetReplacementNewConnectionIdFrame(runtime, result);

        Assert.Equal(2UL, replacementFrame.SequenceNumber);
        Assert.Equal(0UL, replacementFrame.RetirePriorTo);
        Assert.True(replacementRoute.ConnectionIdBytes.ToArray().SequenceEqual(replacementFrame.ConnectionId));
        Assert.True(replacementToken.Token.ToArray().SequenceEqual(replacementFrame.StatelessResetToken));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RetireConnectionIdFrame_DoesNotReplenishWhenTheSequenceWasNotActive()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
            nowTicks: 0).StateChanged);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(0UL));
        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            QuicS17P2P3TestSupport.PacketConnectionId,
            retirePayload,
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    private static QuicNewConnectionIdFrameSnapshot GetReplacementNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result)
    {
        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(TryFindNewConnectionIdFrame(payload, out QuicNewConnectionIdFrameSnapshot frame));
        return frame;
    }

    private static bool TryFindNewConnectionIdFrame(
        ReadOnlySpan<byte> payload,
        out QuicNewConnectionIdFrameSnapshot frame)
    {
        frame = default;
        int offset = 0;

        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed)
                && paddingBytesConsumed > 0)
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed)
                && ackBytesConsumed > 0)
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseNewConnectionIdFrame(
                    remaining,
                    out QuicNewConnectionIdFrame parsed,
                    out int newConnectionIdBytesConsumed)
                && newConnectionIdBytesConsumed > 0)
            {
                frame = new QuicNewConnectionIdFrameSnapshot(
                    parsed.SequenceNumber,
                    parsed.RetirePriorTo,
                    parsed.ConnectionId.ToArray(),
                    parsed.StatelessResetToken.ToArray());
                return true;
            }

            return false;
        }

        return false;
    }

    private readonly record struct QuicNewConnectionIdFrameSnapshot(
        ulong SequenceNumber,
        ulong RetirePriorTo,
        byte[] ConnectionId,
        byte[] StatelessResetToken);
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-1-1-P6-S2-R01")]
public sealed class REQ_QUIC_RFC9000_0234
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ShortHeaderPacketOnPreviouslyUnusedIssuedConnectionId_ReplenishesThroughEndpointRoute()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] issuedConnectionId = [0xB0, 0xB1, 0xB2, 0xB3];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 9,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x80),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 9);

        Assert.True(issued.StateChanged);
        ApplyEndpointEffects(endpoint, handle, issued.Effects);

        TaskCompletionSource<QuicConnectionTransitionResult> replenishment = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();
        Task runTask = endpoint.RunAsync(
            transitionObserver: (observedHandle, _, transition) =>
            {
                if (observedHandle == handle
                    && transition.Effects.OfType<QuicConnectionRegisterConnectionIdRouteEffect>()
                        .Any(effect => effect.ConnectionId == 2UL))
                {
                    replenishment.TrySetResult(transition);
                }
            },
            cancellationToken: cancellation.Token);

        try
        {
            byte[] packet = BuildOneRttPacket(runtime, issuedConnectionId, QuicFrameTestData.BuildPingFrame());

            QuicConnectionIngressResult ingress = endpoint.ReceiveDatagram(packet, activePath);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, ingress.Disposition);
            Assert.Equal(handle, ingress.Handle);

            QuicConnectionTransitionResult result = await replenishment.Task.WaitAsync(TimeSpan.FromSeconds(5));

            QuicConnectionRegisterConnectionIdRouteEffect replacementRoute =
                Assert.Single(result.Effects.OfType<QuicConnectionRegisterConnectionIdRouteEffect>());
            QuicConnectionRegisterStatelessResetTokenEffect replacementToken =
                Assert.Single(result.Effects.OfType<QuicConnectionRegisterStatelessResetTokenEffect>());
            QuicNewConnectionIdFrameSnapshot replacementFrame = GetSingleNewConnectionIdFrame(runtime, result);

            Assert.Equal(2UL, replacementRoute.ConnectionId);
            Assert.Equal(2UL, replacementToken.ConnectionId);
            Assert.Equal(8, replacementRoute.ConnectionIdBytes.Length);
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, replacementToken.Token.Length);
            Assert.Equal(2UL, replacementFrame.SequenceNumber);
            Assert.Equal(0UL, replacementFrame.RetirePriorTo);
            Assert.True(replacementRoute.ConnectionIdBytes.ToArray().SequenceEqual(replacementFrame.ConnectionId));
            Assert.True(replacementToken.Token.ToArray().SequenceEqual(replacementFrame.StatelessResetToken));
        }
        finally
        {
            cancellation.Cancel();
            await runTask;
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PreviouslyUsedIssuedConnectionId_DoesNotReplenishAgain()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 4);
        byte[] issuedConnectionId = [0xB4, 0xB5, 0xB6, 0xB7];
        QuicHandshakeFlowCoordinator coordinator = new(
            issuedConnectionId,
            QuicS17P2P3TestSupport.PacketSourceConnectionId);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 9,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x90),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 9).StateChanged);

        QuicConnectionTransitionResult firstUse = TransitionOneRttPacket(
            runtime,
            coordinator,
            QuicFrameTestData.BuildPingFrame(),
            routedLocallyIssuedConnectionId: 1UL,
            observedAtTicks: 10);

        Assert.True(firstUse.StateChanged);
        Assert.Contains(
            firstUse.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect register
                && register.ConnectionId == 2UL);

        QuicConnectionTransitionResult repeatedUse = TransitionOneRttPacket(
            runtime,
            coordinator,
            QuicFrameTestData.BuildPingFrame(),
            routedLocallyIssuedConnectionId: 1UL,
            observedAtTicks: 11);

        Assert.DoesNotContain(
            repeatedUse.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(
            repeatedUse.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
    }

    private static byte[] BuildOneRttPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> payload)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(
            destinationConnectionId.ToArray(),
            QuicS17P2P3TestSupport.PacketSourceConnectionId);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static QuicConnectionTransitionResult TransitionOneRttPacket(
        QuicConnectionRuntime runtime,
        QuicHandshakeFlowCoordinator coordinator,
        ReadOnlySpan<byte> payload,
        ulong? routedLocallyIssuedConnectionId,
        long observedAtTicks)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket,
                routedLocallyIssuedConnectionId),
            nowTicks: observedAtTicks);
    }

    private static void ApplyEndpointEffects(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionHandle handle,
        IEnumerable<QuicConnectionEffect> effects)
    {
        foreach (QuicConnectionEffect effect in effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }
    }

    private static QuicNewConnectionIdFrameSnapshot GetSingleNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
        List<QuicNewConnectionIdFrameSnapshot> frames = [];

        foreach (QuicConnectionSendDatagramEffect sendEffect in result.Effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
            if (!coordinator.TryOpenProtectedApplicationDataPacket(
                    sendEffect.Datagram.Span,
                    material,
                    out byte[] openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out _))
            {
                continue;
            }

            ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
            if (TryFindNewConnectionIdFrame(payload, out QuicNewConnectionIdFrameSnapshot frame))
            {
                frames.Add(frame);
            }
        }

        return Assert.Single(frames);
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

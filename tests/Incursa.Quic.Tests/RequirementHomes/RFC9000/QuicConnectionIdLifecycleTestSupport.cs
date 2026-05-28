// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicConnectionIdLifecycleTestSupport
{
    internal static QuicConnectionTransitionResult ProcessNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        long observedAtTicks,
        byte statelessResetTokenStart = 0x60)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            CreateStatelessResetToken(statelessResetTokenStart)));

        return QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            payload,
            observedAtTicks);
    }

    internal static ulong[] GetRetiredSequenceNumbers(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
        List<ulong> retiredSequenceNumbers = [];

        foreach (QuicConnectionSendDatagramEffect effect in result.Effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
            if (!coordinator.TryOpenProtectedApplicationDataPacket(
                    effect.Datagram.Span,
                    material,
                    out byte[] openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out _))
            {
                continue;
            }

            ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
            int frameOffset = 0;
            while (frameOffset < payload.Length)
            {
                ReadOnlySpan<byte> remaining = payload[frameOffset..];
                if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed)
                    && paddingBytesConsumed > 0)
                {
                    frameOffset += paddingBytesConsumed;
                    continue;
                }

                if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed)
                    && ackBytesConsumed > 0)
                {
                    frameOffset += ackBytesConsumed;
                    continue;
                }

                if (QuicFrameCodec.TryParseRetireConnectionIdFrame(
                        remaining,
                        out QuicRetireConnectionIdFrame frame,
                        out int retireBytesConsumed)
                    && retireBytesConsumed > 0)
                {
                    retiredSequenceNumbers.Add(frame.SequenceNumber);
                    frameOffset += retireBytesConsumed;
                    continue;
                }

                break;
            }
        }

        return retiredSequenceNumbers.ToArray();
    }

    internal static QuicNewConnectionIdFrameProofSnapshot[] GetNewConnectionIdFrames(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
        List<QuicNewConnectionIdFrameProofSnapshot> frames = [];

        foreach (QuicConnectionSendDatagramEffect effect in result.Effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
            if (!coordinator.TryOpenProtectedApplicationDataPacket(
                    effect.Datagram.Span,
                    material,
                    out byte[] openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out _))
            {
                continue;
            }

            ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
            int frameOffset = 0;
            while (frameOffset < payload.Length)
            {
                ReadOnlySpan<byte> remaining = payload[frameOffset..];
                if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed)
                    && paddingBytesConsumed > 0)
                {
                    frameOffset += paddingBytesConsumed;
                    continue;
                }

                if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed)
                    && ackBytesConsumed > 0)
                {
                    frameOffset += ackBytesConsumed;
                    continue;
                }

                if (QuicFrameCodec.TryParseNewConnectionIdFrame(
                        remaining,
                        out QuicNewConnectionIdFrame frame,
                        out int newConnectionIdBytesConsumed)
                    && newConnectionIdBytesConsumed > 0)
                {
                    frames.Add(new QuicNewConnectionIdFrameProofSnapshot(
                        frame.SequenceNumber,
                        frame.RetirePriorTo,
                        frame.ConnectionId.ToArray(),
                        frame.StatelessResetToken.ToArray()));
                    frameOffset += newConnectionIdBytesConsumed;
                    continue;
                }

                break;
            }
        }

        return frames.ToArray();
    }

    internal static byte[] BuildOneRttPacket(
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

    internal static QuicConnectionTransitionResult TransitionOneRttPacket(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> payload,
        ulong? routedLocallyIssuedConnectionId,
        long observedAtTicks)
    {
        byte[] protectedPacket = BuildOneRttPacket(runtime, destinationConnectionId, payload);
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                observedAtTicks,
                pathIdentity,
                protectedPacket,
                routedLocallyIssuedConnectionId),
            nowTicks: observedAtTicks);
    }

    internal static bool TryAcceptNewConnectionId(
        QuicConnectionPeerConnectionIdState state,
        ulong sequenceNumber,
        ulong retirePriorTo,
        byte connectionIdStart,
        ulong activeConnectionIdLimit,
        out QuicTransportErrorCode errorCode,
        out bool destinationConnectionIdChanged,
        out ulong[] retiredSequenceNumbers)
    {
        byte[] connectionId =
        [
            connectionIdStart,
            unchecked((byte)(connectionIdStart + 1)),
            unchecked((byte)(connectionIdStart + 2)),
        ];
        byte[] statelessResetToken = CreateStatelessResetToken(connectionIdStart);

        return state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                sequenceNumber,
                retirePriorTo,
                connectionId,
                statelessResetToken),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers);
    }

    internal static byte[] CreateStatelessResetToken(byte startValue)
    {
        byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = unchecked((byte)(startValue + index));
        }

        return token;
    }
}

internal readonly record struct QuicNewConnectionIdFrameProofSnapshot(
    ulong SequenceNumber,
    ulong RetirePriorTo,
    byte[] ConnectionId,
    byte[] StatelessResetToken);

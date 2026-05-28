// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicStreamControlFrameTestSupport
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    internal static byte[] BuildResetStreamPayload(
        byte[] typeEncoding,
        byte[] streamIdEncoding,
        byte[] applicationProtocolErrorCodeEncoding,
        byte[] finalSizeEncoding)
    {
        return [.. typeEncoding, .. streamIdEncoding, .. applicationProtocolErrorCodeEncoding, .. finalSizeEncoding];
    }

    internal static byte[] BuildStopSendingPayload(
        byte[] typeEncoding,
        byte[] streamIdEncoding,
        byte[] applicationProtocolErrorCodeEncoding)
    {
        return [.. typeEncoding, .. streamIdEncoding, .. applicationProtocolErrorCodeEncoding];
    }

    internal static bool TryFindResetStreamFrame(
        ReadOnlySpan<byte> payload,
        out QuicResetStreamFrame frame,
        out int frameOffset,
        out int bytesConsumed)
    {
        frame = default;
        frameOffset = default;
        bytesConsumed = default;

        return TryFindControlFrame(
            payload,
            (ReadOnlySpan<byte> candidate, out QuicResetStreamFrame parsed, out int consumed) =>
                QuicFrameCodec.TryParseResetStreamFrame(candidate, out parsed, out consumed),
            out frame,
            out frameOffset,
            out bytesConsumed);
    }

    internal static bool TryFindProtectedResetStreamFrame(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        out QuicResetStreamFrame frame)
    {
        foreach (QuicConnectionSendDatagramEffect effect in sendEffects)
        {
            if (!TryOpenProtectedApplicationPayload(
                runtime,
                effect.Datagram.Span,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
            {
                continue;
            }

            if (TryFindResetStreamFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out frame,
                out _,
                out _))
            {
                return true;
            }
        }

        frame = default;
        return false;
    }

    internal static bool TryFindStopSendingFrame(
        ReadOnlySpan<byte> payload,
        out QuicStopSendingFrame frame,
        out int frameOffset,
        out int bytesConsumed)
    {
        frame = default;
        frameOffset = default;
        bytesConsumed = default;

        return TryFindControlFrame(
            payload,
            (ReadOnlySpan<byte> candidate, out QuicStopSendingFrame parsed, out int consumed) =>
                QuicFrameCodec.TryParseStopSendingFrame(candidate, out parsed, out consumed),
            out frame,
            out frameOffset,
            out bytesConsumed);
    }

    internal static bool TryFindProtectedStopSendingFrame(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        out QuicStopSendingFrame frame)
    {
        foreach (QuicConnectionSendDatagramEffect effect in sendEffects)
        {
            if (!TryOpenProtectedApplicationPayload(
                runtime,
                effect.Datagram.Span,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
            {
                continue;
            }

            if (TryFindStopSendingFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out frame,
                out _,
                out _))
            {
                return true;
            }
        }

        frame = default;
        return false;
    }

    internal static QuicConnectionTransitionResult ReceiveProtectedApplicationPayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload,
        long nowTicks = 1)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            out byte[] protectedPacket));

        Assert.NotNull(runtime.ActivePath);
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                nowTicks,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks);
    }

    private delegate bool TryParseControlFrame<TFrame>(
        ReadOnlySpan<byte> payload,
        out TFrame frame,
        out int bytesConsumed);

    private static bool TryOpenProtectedApplicationPayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> protectedPacket,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        return coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out openedPacket,
            out payloadOffset,
            out payloadLength);
    }

    private static bool TryFindControlFrame<TFrame>(
        ReadOnlySpan<byte> payload,
        TryParseControlFrame<TFrame> tryParseFrame,
        out TFrame frame,
        out int frameOffset,
        out int bytesConsumed)
        where TFrame : struct
    {
        frame = default;
        frameOffset = default;
        bytesConsumed = default;

        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (!tryParseFrame(remaining, out frame, out bytesConsumed))
            {
                return false;
            }

            frameOffset = offset;
            return true;
        }

        return false;
    }
}

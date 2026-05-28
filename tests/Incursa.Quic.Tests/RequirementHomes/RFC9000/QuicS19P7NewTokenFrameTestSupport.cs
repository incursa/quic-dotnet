// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS19P7NewTokenFrameTestSupport
{
    internal const byte NewTokenFrameType = 0x07;
    internal static readonly byte[] RepresentativeToken = [0x10, 0x20, 0x30, 0x40];
    internal static readonly byte[] AlternateToken = [0x40, 0x30, 0x20, 0x10];

    internal static byte[] BuildNewTokenFrame(ReadOnlySpan<byte> token)
    {
        return QuicFrameTestData.BuildNewTokenFrame(new QuicNewTokenFrame(token));
    }

    internal static byte[] BuildNewTokenFrameWithTokenLength(ulong tokenLength, ReadOnlySpan<byte> tokenBytes)
    {
        List<byte> bytes = [NewTokenFrameType];
        bytes.AddRange(EncodeVarint(tokenLength));
        bytes.AddRange(tokenBytes.ToArray());
        return bytes.ToArray();
    }

    internal static byte[] BuildNewTokenFrameWithEncodedFrameType(ReadOnlySpan<byte> encodedFrameType, ReadOnlySpan<byte> token)
    {
        List<byte> bytes = [];
        bytes.AddRange(encodedFrameType.ToArray());
        bytes.AddRange(EncodeVarint((ulong)token.Length));
        bytes.AddRange(token.ToArray());
        return bytes.ToArray();
    }

    internal static byte[] BuildNewTokenFrameWithTrailingPing(ReadOnlySpan<byte> token)
    {
        return [.. BuildNewTokenFrame(token), .. QuicFrameTestData.BuildPingFrame()];
    }

    internal static void AssertParses(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> expectedToken, int expectedBytesConsumed)
    {
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(encoded, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.True(expectedToken.SequenceEqual(parsed.Token));
        Assert.Equal(expectedBytesConsumed, bytesConsumed);
    }

    internal static void AssertRejects(ReadOnlySpan<byte> encoded)
    {
        Assert.False(QuicFrameCodec.TryParseNewTokenFrame(encoded, out _, out _));
    }

    internal static QuicConnectionTransitionResult ReceiveProtectedApplicationPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload,
        long observedAtTicks)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        byte[] destinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(destinationConnectionId));
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        QuicConnectionPathIdentity pathIdentity = runtime.ActivePath?.Identity
            ?? new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443);
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                pathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    internal static byte[] CreateSequentialToken(int length)
    {
        byte[] token = new byte[length];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = (byte)index;
        }

        return token;
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS8P2PathValidationTestSupport
{
    internal static byte[] CreateChallengeData(byte seed)
    {
        byte[] challengeData = new byte[QuicPathValidation.PathChallengeDataLength];
        for (int index = 0; index < challengeData.Length; index++)
        {
            challengeData[index] = unchecked((byte)(seed + (index * 17)));
        }

        return challengeData;
    }

    internal static QuicConnectionSendDatagramEffect AssertSinglePathChallengeDatagram(
        QuicConnectionTransitionResult result,
        QuicConnectionPathIdentity expectedPath,
        bool expectMinimumSize = true,
        QuicConnectionRuntime? runtime = null)
    {
        QuicConnectionSendDatagramEffect send = Assert.Single(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => QuicFrameCodec.TryParsePathChallengeFrame(effect.Datagram.Span, out _, out _)
                || (runtime is not null && TryOpenPathChallengePayload(runtime, effect.Datagram.Span, out _, out _, out _)));

        Assert.Equal(expectedPath, send.PathIdentity);
        if (expectMinimumSize)
        {
            if (runtime is null)
            {
                Assert.Equal(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, send.Datagram.Length);
            }
            else
            {
                Assert.True(send.Datagram.Length >= QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);
            }
        }

        Assert.True(runtime is not null
            ? TryOpenPathChallengePayload(runtime, send.Datagram.Span, out QuicPathChallengeFrame parsedChallenge, out int bytesConsumed, out ReadOnlyMemory<byte> payload)
            : TryParseRawPathChallenge(send.Datagram.Span, out parsedChallenge, out bytesConsumed, out payload));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, bytesConsumed);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, parsedChallenge.Data.Length);
        Assert.Equal(1, CountPathChallengeFrames(payload.Span));
        AssertPaddingOnly(payload.Span[bytesConsumed..]);
        return send;
    }

    private static bool TryParseRawPathChallenge(
        ReadOnlySpan<byte> datagram,
        out QuicPathChallengeFrame frame,
        out int bytesConsumed,
        out ReadOnlyMemory<byte> payload)
    {
        if (QuicFrameCodec.TryParsePathChallengeFrame(datagram, out frame, out bytesConsumed))
        {
            payload = datagram.ToArray();
            return true;
        }

        payload = ReadOnlyMemory<byte>.Empty;
        return false;
    }

    internal static QuicConnectionSendDatagramEffect AssertSinglePathResponseDatagram(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result,
        QuicConnectionPathIdentity expectedPath,
        ReadOnlySpan<byte> expectedResponseData,
        bool expectMinimumSize = true)
    {
        QuicConnectionSendDatagramEffect send = Assert.Single(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => TryOpenPathResponsePayload(runtime, effect.Datagram.Span, out _, out _, out _));

        Assert.Equal(expectedPath, send.PathIdentity);
        if (expectMinimumSize)
        {
            Assert.True(send.Datagram.Length >= QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);
        }

        Assert.True(TryOpenPathResponsePayload(
            runtime,
            send.Datagram.Span,
            out QuicPathResponseFrame parsedResponse,
            out int bytesConsumed,
            out ReadOnlyMemory<byte> payload));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, bytesConsumed);
        Assert.True(expectedResponseData.SequenceEqual(parsedResponse.Data));
        Assert.Equal(1, CountPathResponseFrames(payload.Span));
        AssertPaddingOnly(payload.Span[bytesConsumed..]);
        return send;
    }

    internal static bool TryOpenPathChallengePayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> datagram,
        out QuicPathChallengeFrame frame,
        out int bytesConsumed,
        out ReadOnlyMemory<byte> payload)
    {
        if (QuicFrameCodec.TryParsePathChallengeFrame(datagram, out frame, out bytesConsumed))
        {
            payload = datagram.ToArray();
            return true;
        }

        frame = default;
        bytesConsumed = 0;
        if (TryOpenProtectedApplicationPayload(runtime, datagram, out payload))
        {
            int offset = SkipLeadingAckAndPadding(payload.Span);
            ReadOnlySpan<byte> remaining = payload.Span[offset..];
            if (QuicFrameCodec.TryParsePathChallengeFrame(remaining, out frame, out bytesConsumed))
            {
                payload = payload.Slice(offset);
                return true;
            }
        }

        payload = ReadOnlyMemory<byte>.Empty;
        return false;
    }

    internal static bool TryOpenPathResponsePayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> datagram,
        out QuicPathResponseFrame frame,
        out int bytesConsumed,
        out ReadOnlyMemory<byte> payload)
    {
        if (QuicFrameCodec.TryParsePathResponseFrame(datagram, out frame, out bytesConsumed))
        {
            payload = datagram.ToArray();
            return true;
        }

        frame = default;
        bytesConsumed = 0;
        if (TryOpenProtectedApplicationPayload(runtime, datagram, out payload))
        {
            int offset = SkipLeadingAckPaddingAndPathChallenge(payload.Span);
            ReadOnlySpan<byte> remaining = payload.Span[offset..];
            if (QuicFrameCodec.TryParsePathResponseFrame(remaining, out frame, out bytesConsumed))
            {
                payload = payload.Slice(offset);
                return true;
            }
        }

        payload = ReadOnlyMemory<byte>.Empty;
        return false;
    }

    private static bool TryOpenProtectedApplicationPayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> datagram,
        out ReadOnlyMemory<byte> payload)
    {
        payload = ReadOnlyMemory<byte>.Empty;
        if (!runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        if (!coordinator.TryOpenProtectedApplicationDataPacket(
                datagram,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out _))
        {
            return false;
        }

        payload = openedPacket.AsMemory(payloadOffset, payloadLength);
        return true;
    }

    private static int SkipLeadingAckAndPadding(ReadOnlySpan<byte> payload)
    {
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

            return offset;
        }

        return offset;
    }

    private static int SkipLeadingAckPaddingAndPathChallenge(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParsePathChallengeFrame(remaining, out _, out int pathChallengeBytesConsumed)
                && pathChallengeBytesConsumed > 0)
            {
                offset += pathChallengeBytesConsumed;
                continue;
            }

            int nextOffset = SkipLeadingAckAndPadding(remaining);
            if (nextOffset == 0)
            {
                return offset;
            }

            offset += nextOffset;
        }

        return offset;
    }

    internal static QuicConnectionTransitionResult StartCandidatePath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity candidatePath,
        long observedAtTicks,
        int receivedPayloadBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize)
    {
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                candidatePath,
                new byte[receivedPayloadBytes]),
            nowTicks: observedAtTicks);
    }

    internal static QuicConnectionTransitionResult ReceiveProtectedPathChallenge(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> challengeData,
        byte packetNumber,
        long observedAtTicks,
        bool includePing = false)
    {
        byte[] payload = includePing
            ? [.. QuicFrameTestData.BuildPingFrame(), .. QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData))]
            : QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData));

        return ReceiveProtectedApplicationPayload(
            runtime,
            pathIdentity,
            payload,
            packetNumber,
            observedAtTicks);
    }

    internal static QuicConnectionTransitionResult ReceiveProtectedPathResponse(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> responseData,
        byte packetNumber,
        long observedAtTicks,
        bool includePing = false)
    {
        byte[] payload = includePing
            ? [.. QuicFrameTestData.BuildPingFrame(), .. QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame(responseData))]
            : QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame(responseData));

        return ReceiveProtectedApplicationPayload(
            runtime,
            pathIdentity,
            payload,
            packetNumber,
            observedAtTicks);
    }

    private static QuicConnectionTransitionResult ReceiveProtectedApplicationPayload(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> payload,
        byte packetNumber,
        long observedAtTicks)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value;

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, packetNumber],
            payload,
            material,
            declaredPacketNumberLength: 4);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                pathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    internal static int CountPathChallengeFrames(ReadOnlySpan<byte> datagram)
    {
        int count = 0;
        int offset = 0;
        while (offset < datagram.Length)
        {
            ReadOnlySpan<byte> remaining = datagram[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePathChallengeFrame(remaining, out _, out int pathChallengeBytesConsumed))
            {
                count++;
                offset += pathChallengeBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePathResponseFrame(remaining, out _, out int pathResponseBytesConsumed))
            {
                offset += pathResponseBytesConsumed;
                continue;
            }

            break;
        }

        return count;
    }

    internal static int CountPathResponseFrames(ReadOnlySpan<byte> datagram)
    {
        int count = 0;
        int offset = 0;
        while (offset < datagram.Length)
        {
            ReadOnlySpan<byte> remaining = datagram[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePathChallengeFrame(remaining, out _, out int pathChallengeBytesConsumed))
            {
                offset += pathChallengeBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePathResponseFrame(remaining, out _, out int pathResponseBytesConsumed))
            {
                count++;
                offset += pathResponseBytesConsumed;
                continue;
            }

            break;
        }

        return count;
    }

    internal static void AssertPaddingOnly(ReadOnlySpan<byte> payload)
    {
        Assert.True(payload.SequenceEqual(new byte[payload.Length]));
    }
}

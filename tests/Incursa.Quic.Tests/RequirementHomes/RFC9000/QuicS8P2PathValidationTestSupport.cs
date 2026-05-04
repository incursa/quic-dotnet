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
        bool expectMinimumSize = true)
    {
        QuicConnectionSendDatagramEffect send = Assert.Single(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => QuicFrameCodec.TryParsePathChallengeFrame(effect.Datagram.Span, out _, out _));

        Assert.Equal(expectedPath, send.PathIdentity);
        if (expectMinimumSize)
        {
            Assert.Equal(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, send.Datagram.Length);
        }

        Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(
            send.Datagram.Span,
            out QuicPathChallengeFrame parsedChallenge,
            out int bytesConsumed));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, bytesConsumed);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, parsedChallenge.Data.Length);
        Assert.Equal(1, CountPathChallengeFrames(send.Datagram.Span));
        AssertPaddingOnly(send.Datagram.Span[bytesConsumed..]);
        return send;
    }

    internal static QuicConnectionSendDatagramEffect AssertSinglePathResponseDatagram(
        QuicConnectionTransitionResult result,
        QuicConnectionPathIdentity expectedPath,
        ReadOnlySpan<byte> expectedResponseData,
        bool expectMinimumSize = true)
    {
        QuicConnectionSendDatagramEffect send = Assert.Single(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => QuicFrameCodec.TryParsePathResponseFrame(effect.Datagram.Span, out _, out _));

        Assert.Equal(expectedPath, send.PathIdentity);
        if (expectMinimumSize)
        {
            Assert.Equal(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, send.Datagram.Length);
        }

        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(
            send.Datagram.Span,
            out QuicPathResponseFrame parsedResponse,
            out int bytesConsumed));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, bytesConsumed);
        Assert.True(expectedResponseData.SequenceEqual(parsedResponse.Data));
        Assert.Equal(1, CountPathResponseFrames(send.Datagram.Span));
        AssertPaddingOnly(send.Datagram.Span[bytesConsumed..]);
        return send;
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

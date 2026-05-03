namespace Incursa.Quic.Tests;

internal static class QuicS2P3PriorityTestSupport
{
    internal static (QuicConnectionRuntime Runtime, List<QuicConnectionTransitionResult> Transitions) CreateRuntimeWithTransitionCapture()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionTransitionResult> transitions = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            transitions.Add(runtime.Transition(connectionEvent));
            return true;
        });

        return (runtime, transitions);
    }

    internal static ReadOnlyMemory<byte> OpenProtectedApplicationPayload(QuicConnectionRuntime runtime, ReadOnlyMemory<byte> protectedPacket)
    {
        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId.ToArray());

        if (!runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            throw new InvalidOperationException("The runtime does not have 1-RTT protect packet protection material.");
        }

        if (!coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            throw new InvalidOperationException("The protected application packet could not be opened for inspection.");
        }

        return openedPacket.AsMemory(payloadOffset, payloadLength);
    }

    internal static ulong[] ReadStreamFrameIds(ReadOnlySpan<byte> payload)
    {
        List<ulong> streamIds = [];
        int offset = 0;

        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            int paddingLength = 0;
            while (paddingLength < remaining.Length && remaining[paddingLength] == 0)
            {
                paddingLength++;
            }

            if (paddingLength > 0)
            {
                offset += paddingLength;
                continue;
            }

            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                streamIds.Add(streamFrame.StreamId.Value);
                offset += streamFrame.ConsumedLength;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            throw new InvalidOperationException("Unexpected frame while inspecting the queued application payload.");
        }

        return streamIds.ToArray();
    }
}

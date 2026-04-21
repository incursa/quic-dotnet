using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0010">On the supported active loopback path, send-capable QuicStream facades MUST support immediate 1-RTT writes, best-effort graceful write completion through stream disposal, peer read-side byte delivery, and matching EOF observation without implying broader stream parity.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0010")]
public sealed class REQ_QUIC_API_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackWriteAndDisposeCompletion_DeliversBytesAndPeerEof()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        byte[] payload = [0x10, 0x20, 0x30, 0x40, 0x50];
        await pair.ClientStream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        byte[] receiveBuffer = new byte[payload.Length];
        int bytesRead = await ReadWithDiagnosticsAsync(pair, receiveBuffer, payload.Length);
        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(receiveBuffer));

        Assert.Equal(0, await pair.ServerStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ServerStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AcceptedBidirectionalStreamCanReturnResponseBytesAfterTheRequesterCompletesOnlyItsWriteSide()
    {
        // Regression from the local interop-runner handshake lane on 2026-04-20:
        // the client must finish its HTTP/0.9 request write side while keeping the read side open
        // so the peer can send the response back on the same bidirectional stream.
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        byte[] request = Encoding.ASCII.GetBytes("GET /captured-interop.txt\r\n");
        byte[] response = Encoding.ASCII.GetBytes("captured interop response");

        await pair.ClientStream.WriteAsync(request, 0, request.Length).WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        byte[] requestBuffer = new byte[request.Length];
        int requestBytesRead = await ReadWithDiagnosticsAsync(pair, requestBuffer, request.Length);
        Assert.Equal(request.Length, requestBytesRead);
        Assert.True(request.AsSpan().SequenceEqual(requestBuffer));
        Assert.Equal(0, await pair.ServerStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ServerStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));

        const int responseChunkBytes = 64;
        for (int offset = 0; offset < response.Length; offset += responseChunkBytes)
        {
            int bytesToWrite = Math.Min(responseChunkBytes, response.Length - offset);
            await pair.ServerStream.WriteAsync(response, offset, bytesToWrite).WaitAsync(TimeSpan.FromSeconds(5));
        }

        await pair.ServerStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ServerStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        byte[] responseBuffer = new byte[response.Length];
        int responseBytesRead = await pair.ClientStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(response.Length, responseBytesRead);
        Assert.True(response.AsSpan().SequenceEqual(responseBuffer));
        Assert.Equal(0, await pair.ClientStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ClientStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamOperationsAfterDispose_AreRejectedHonestly()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        await pair.ClientStream.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => pair.ClientStream.WriteAsync(new byte[] { 0x01 }, 0, 1));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => pair.ClientStream.ReadAsync(new byte[1], 0, 1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamWritesAfterConnectionClose_AreRejectedWithTheTerminalConnectionOutcome()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        await pair.ClientConnection.CloseAsync(27);

        QuicException exception = await Assert.ThrowsAsync<QuicException>(() => pair.ClientStream.WriteAsync(new byte[] { 0xAA }, 0, 1));
        Assert.Equal(QuicError.ConnectionAborted, exception.QuicError);
        Assert.Equal(27, exception.ApplicationErrorCode);
    }

    private sealed class LoopbackStreamPair : IAsyncDisposable
    {
        private LoopbackStreamPair(
            QuicListener listener,
            QuicConnection serverConnection,
            QuicConnection clientConnection,
            QuicStream serverStream,
            QuicStream clientStream)
        {
            Listener = listener;
            ServerConnection = serverConnection;
            ClientConnection = clientConnection;
            ServerStream = serverStream;
            ClientStream = clientStream;
        }

        public QuicListener Listener { get; }

        public QuicConnection ServerConnection { get; }

        public QuicConnection ClientConnection { get; }

        public QuicStream ServerStream { get; }

        public QuicStream ClientStream { get; }

        public static async Task<LoopbackStreamPair> CreateAsync()
        {
            using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = listenEndPoint,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ListenBacklog = 1,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                    QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
            };

            QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
            Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync().AsTask();
            Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

            await Task.WhenAll(acceptConnectionTask, connectTask);

            QuicConnection serverConnection = await acceptConnectionTask;
            QuicConnection clientConnection = await connectTask;

            Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
            await Task.Yield();
            Task<QuicStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask();
            await Task.WhenAll(acceptStreamTask, openStreamTask);

            return new LoopbackStreamPair(
                listener,
                serverConnection,
                clientConnection,
                await acceptStreamTask,
                await openStreamTask);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await ServerStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ClientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ServerConnection.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ClientConnection.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await Listener.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }
        }
    }

    private static async Task<int> ReadWithDiagnosticsAsync(LoopbackStreamPair pair, byte[] buffer, int count)
    {
        try
        {
            return await pair.ServerStream.ReadAsync(buffer, 0, count).WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (TimeoutException timeout)
        {
            throw new TimeoutException(
                $"Timed out waiting for peer bytes. Client={QuicLoopbackEstablishmentTestSupport.DescribeConnection(pair.ClientConnection)}; Server={QuicLoopbackEstablishmentTestSupport.DescribeConnection(pair.ServerConnection)}; ClientStream={DescribeStream(pair.ClientStream)}; ServerStream={DescribeStream(pair.ServerStream)}; ClientAppPackets={DescribeApplicationPackets(pair.ClientConnection, pair.ServerConnection)}",
                timeout);
        }
    }

    private static string DescribeApplicationPackets(QuicConnection senderConnection, QuicConnection receiverConnection)
    {
        QuicConnectionRuntime senderRuntime = GetRuntime(senderConnection);
        QuicConnectionRuntime receiverRuntime = GetRuntime(receiverConnection);

        if (!receiverRuntime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue)
        {
            return "<receiver open material unavailable>";
        }

        QuicHandshakeFlowCoordinator receiverHandshakeFlow = GetHandshakeFlow(receiverRuntime);
        QuicConnectionSentPacket[] packets = senderRuntime.SendRuntime.SentPackets.Values
            .Where(static packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .OrderBy(static packet => packet.PacketNumber)
            .ToArray();

        if (packets.Length == 0)
        {
            return "<none>";
        }

        StringBuilder description = new();
        for (int index = 0; index < packets.Length; index++)
        {
            if (index > 0)
            {
                description.Append(" | ");
            }

            QuicConnectionSentPacket packet = packets[index];
            description.Append($"pn={packet.PacketNumber},bytes={packet.PacketBytes.Length},streams={FormatStreamIds(packet.StreamIds)}");

            if (!receiverHandshakeFlow.TryOpenProtectedApplicationDataPacket(
                    packet.PacketBytes.Span,
                    receiverRuntime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
                    out byte[] openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out bool keyPhase))
            {
                description.Append(",open=false");
                continue;
            }

            description.Append($",open=true,keyPhase={keyPhase},frames={DescribeFrames(openedPacket.AsSpan(payloadOffset, payloadLength))}");
        }

        return description.ToString();
    }

    private static string DescribeStream(QuicStream stream)
    {
        FieldInfo? bookkeepingField = typeof(QuicStream).GetField("bookkeeping", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(bookkeepingField);

        if (bookkeepingField!.GetValue(stream) is not QuicConnectionStreamState bookkeeping
            || !bookkeeping.TryGetStreamSnapshot((ulong)stream.Id, out QuicConnectionStreamSnapshot snapshot))
        {
            return "<snapshot unavailable>";
        }

        return string.Join(
            "; ",
            [
                $"Id={stream.Id}",
                $"Type={stream.Type}",
                $"CanRead={stream.CanRead}",
                $"CanWrite={stream.CanWrite}",
                $"SendState={snapshot.SendState}",
                $"ReceiveState={snapshot.ReceiveState}",
                $"UniqueBytesSent={snapshot.UniqueBytesSent}",
                $"UniqueBytesReceived={snapshot.UniqueBytesReceived}",
                $"BufferedReadableBytes={snapshot.BufferedReadableBytes}",
                $"HasFinalSize={snapshot.HasFinalSize}",
                $"FinalSize={snapshot.FinalSize}",
                $"ReadOffset={snapshot.ReadOffset}",
            ]);
    }

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        FieldInfo? runtimeField = typeof(QuicConnection).GetField("runtime", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(runtimeField);
        Assert.IsType<QuicConnectionRuntime>(runtimeField!.GetValue(connection));
        return (QuicConnectionRuntime)runtimeField.GetValue(connection)!;
    }

    private static QuicHandshakeFlowCoordinator GetHandshakeFlow(QuicConnectionRuntime runtime)
    {
        FieldInfo? handshakeFlowField = typeof(QuicConnectionRuntime).GetField("handshakeFlowCoordinator", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(handshakeFlowField);
        Assert.IsType<QuicHandshakeFlowCoordinator>(handshakeFlowField!.GetValue(runtime));
        return (QuicHandshakeFlowCoordinator)handshakeFlowField.GetValue(runtime)!;
    }

    private static string DescribeFrames(ReadOnlySpan<byte> payload)
    {
        StringBuilder description = new();
        int offset = 0;
        int frameCount = 0;

        while (offset < payload.Length && frameCount < 8)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                description.Append(frameCount == 0 ? string.Empty : ",");
                description.Append($"padding({paddingBytesConsumed})");
                offset += paddingBytesConsumed;
                frameCount++;
                continue;
            }

            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                description.Append(frameCount == 0 ? string.Empty : ",");
                description.Append(
                    $"stream(id={streamFrame.StreamId},off={streamFrame.Offset},len={streamFrame.StreamDataLength},fin={streamFrame.IsFin},data={Convert.ToHexString(streamFrame.StreamData[..Math.Min(streamFrame.StreamDataLength, 8)]).ToLowerInvariant()})");
                offset += streamFrame.ConsumedLength;
                frameCount++;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                description.Append(frameCount == 0 ? string.Empty : ",");
                description.Append("ping");
                offset += pingBytesConsumed;
                frameCount++;
                continue;
            }

            description.Append(frameCount == 0 ? string.Empty : ",");
            description.Append($"unknown(0x{remaining[0]:X2})");
            break;
        }

        return description.Length == 0 ? "<empty>" : description.ToString();
    }

    private static string FormatStreamIds(ulong[]? streamIds)
    {
        if (streamIds is null || streamIds.Length == 0)
        {
            return "<none>";
        }

        return string.Join(",", streamIds);
    }
}

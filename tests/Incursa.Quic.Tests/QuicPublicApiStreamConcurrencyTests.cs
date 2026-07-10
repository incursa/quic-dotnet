// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class QuicPublicApiStreamConcurrencyTests
{
    private const int ConcurrentStreamCount = 8;
    private const int PayloadBytes = 1024;

    [Fact]
    [Trait("Category", "Performance")]
    public async Task SupportedLoopback_AllowsConcurrentBidirectionalRequestResponseStreams()
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(30));
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        byte[] requestPayload = CreatePayload(PayloadBytes, 0x11);
        byte[] responsePayload = CreatePayload(PayloadBytes, 0x33);

        QuicServerConnectionOptions serverConnectionOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverConnectionOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            trustedServerCertificate: serverCertificate);

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions, cancellationSource.Token);
        Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions, cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).WaitAsync(cancellationSource.Token);

        await using QuicConnection serverConnection = await acceptConnectionTask;
        await using QuicConnection clientConnection = await connectTask;

        Task[] transfers = new Task[ConcurrentStreamCount];
        for (int index = 0; index < transfers.Length; index++)
        {
            transfers[index] = RunRequestResponseTransferAsync(
                clientConnection,
                serverConnection,
                requestPayload,
                responsePayload,
                cancellationSource.Token);
        }

        await Task.WhenAll(transfers).WaitAsync(cancellationSource.Token);
    }

    private static async Task RunRequestResponseTransferAsync(
        QuicConnection clientConnection,
        QuicConnection serverConnection,
        byte[] requestPayload,
        byte[] responsePayload,
        CancellationToken cancellationToken)
    {
        Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<QuicStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            QuicStreamType.Bidirectional,
            cancellationToken).AsTask();

        await using QuicStream clientStream = await openStreamTask;
        await using QuicStream serverStream = await acceptStreamTask;

        await clientStream.WriteAsync(requestPayload.AsMemory(), cancellationToken);
        await clientStream.CompleteWritesAsync(cancellationToken);
        await clientStream.WritesClosed.WaitAsync(cancellationToken);

        byte[] requestBuffer = new byte[requestPayload.Length];
        await ReadExactlyAsync(serverStream, requestBuffer, cancellationToken);
        Assert.Equal(requestPayload, requestBuffer);
        await AssertEndOfStreamAsync(serverStream, cancellationToken);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken);

        await serverStream.WriteAsync(responsePayload.AsMemory(), cancellationToken);
        await serverStream.CompleteWritesAsync(cancellationToken);
        await serverStream.WritesClosed.WaitAsync(cancellationToken);

        byte[] responseBuffer = new byte[responsePayload.Length];
        await ReadExactlyAsync(clientStream, responseBuffer, cancellationToken);
        Assert.Equal(responsePayload, responseBuffer);
        await AssertEndOfStreamAsync(clientStream, cancellationToken);
        await clientStream.ReadsClosed.WaitAsync(cancellationToken);
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken);
            if (bytesRead == 0)
            {
                throw new InvalidOperationException("Unexpected EOF before the full payload was read.");
            }

            offset += bytesRead;
        }
    }

    private static async Task AssertEndOfStreamAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[1];
        int bytesRead = await stream.ReadAsync(buffer, cancellationToken);
        Assert.Equal(0, bytesRead);
    }

    private static byte[] CreatePayload(int length, byte seed)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = unchecked((byte)(seed + index));
        }

        return payload;
    }
}

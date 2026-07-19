// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class QuicQueuedFinalWriteDeliveryTests
{
    private const int WriteBytes = 16 * 1024;
    private const int WriteCount = 64;

    [Fact]
    public async Task Loopback_RepeatedQueuedWritesDeliverAllBytesBeforeFinal()
        => await RunRepeatedQueuedWriteScenarioAsync(interleaveSmallWrites: false, streamCount: 1);

    [Fact]
    public async Task Loopback_InterleavedSmallAndQueuedWritesDeliverAllBytesBeforeFinal()
        => await RunRepeatedQueuedWriteScenarioAsync(interleaveSmallWrites: true, streamCount: 16);

    private static async Task RunRepeatedQueuedWriteScenarioAsync(bool interleaveSmallWrites, int streamCount)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(30));
        using X509Certificate2 serverCertificate =
            QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicServerConnectionOptions serverOptions =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        };
        QuicClientConnectionOptions clientOptions =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                trustedServerCertificate: serverCertificate);

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions, cancellationSource.Token);
        Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions, cancellationSource.Token).AsTask();
        await Task.WhenAll(acceptConnectionTask, connectTask).WaitAsync(cancellationSource.Token);

        await using QuicConnection serverConnection = await acceptConnectionTask;
        await using QuicConnection clientConnection = await connectTask;

        Task[] transfers = new Task[streamCount];
        for (int index = 0; index < transfers.Length; index++)
        {
            transfers[index] = RunTransferAsync(
                clientConnection,
                serverConnection,
                interleaveSmallWrites,
                cancellationSource.Token);
        }

        await Task.WhenAll(transfers).WaitAsync(cancellationSource.Token);
    }

    private static async Task RunTransferAsync(
        QuicConnection clientConnection,
        QuicConnection serverConnection,
        bool interleaveSmallWrites,
        CancellationToken cancellationToken)
    {
        Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        await using QuicStream clientStream = await clientConnection.OpenOutboundStreamAsync(
            QuicStreamType.Bidirectional,
            cancellationToken);
        await clientStream.WriteFinalAsync(new byte[] { 0x01 }, cancellationToken);
        QuicStream serverStream = await acceptStreamTask.WaitAsync(cancellationToken);

        byte[] request = new byte[1];
        await ReadExactlyAsync(serverStream, request, cancellationToken);
        Assert.Equal(0x01, request[0]);
        Assert.Equal(0, await serverStream.ReadAsync(request, cancellationToken));

        const int smallWriteBytes = 4;
        int stride = WriteBytes + (interleaveSmallWrites ? smallWriteBytes : 0);
        byte[] expected = CreatePayload(stride * WriteCount);
        Task<byte[]> readTask = ReadToEndAsync(clientStream, expected.Length, cancellationToken);
        for (int index = 0; index < WriteCount; index++)
        {
            int offset = index * stride;
            if (interleaveSmallWrites)
            {
                Assert.True(await serverStream.TryWriteAsync(
                    expected.AsMemory(offset, smallWriteBytes),
                    cancellationToken));
                offset += smallWriteBytes;
            }

            ReadOnlyMemory<byte> write = expected.AsMemory(offset, WriteBytes);
            bool written = index + 1 == WriteCount
                ? await serverStream.TryWriteFinalAsync(write, cancellationToken)
                : await serverStream.TryWriteAsync(write, cancellationToken);
            Assert.True(written);
        }

        await serverStream.DisposeAsync();
        byte[] actual = await readTask.WaitAsync(cancellationToken);
        Assert.Equal(expected, actual);
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer[offset..], cancellationToken);
            Assert.NotEqual(0, bytesRead);
            offset += bytesRead;
        }
    }

    private static async Task<byte[]> ReadToEndAsync(
        Stream stream,
        int expectedLength,
        CancellationToken cancellationToken)
    {
        byte[] received = new byte[expectedLength];
        await ReadExactlyAsync(stream, received, cancellationToken);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], cancellationToken));
        return received;
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = unchecked((byte)(index * 31 + 17));
        }

        return payload;
    }
}

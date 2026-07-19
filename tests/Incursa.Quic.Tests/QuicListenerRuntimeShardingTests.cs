// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class QuicListenerRuntimeShardingTests
{
    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(4, 4)]
    [InlineData(5, 5)]
    [InlineData(8, 8)]
    [InlineData(9, QuicListener.MaximumDefaultRuntimeShardCount)]
    [InlineData(32, QuicListener.MaximumDefaultRuntimeShardCount)]
    public void Default_runtime_shard_count_is_bounded_by_processor_count(int processorCount, int expected)
    {
        Assert.Equal(expected, QuicListener.SelectDefaultRuntimeShardCount(processorCount));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Default_runtime_shard_count_rejects_nonpositive_processor_count(int processorCount)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicListener.SelectDefaultRuntimeShardCount(processorCount));
    }

    [Fact]
    public async Task Public_listener_uses_the_bounded_runtime_shard_default()
    {
        QuicListenerOptions options = new()
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ApplicationProtocols = [new SslApplicationProtocol("runtime-sharding-test")],
            ListenBacklog = 1,
            ConnectionOptionsCallback = static (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions())
        };

        await using QuicListener listener = await QuicListener.ListenAsync(options);

        Assert.Equal(
            QuicListener.SelectDefaultRuntimeShardCount(Environment.ProcessorCount),
            listener.Host.RuntimeShardCount);
    }

    [Fact]
    public async Task Public_listener_preserves_the_platform_receive_buffer_before_shared_fan_in()
    {
        using Socket baselineSocket = new(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.Udp);
        int platformDefault = baselineSocket.ReceiveBufferSize;
        QuicListenerOptions options = new()
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ApplicationProtocols = [new SslApplicationProtocol("receive-buffer-test")],
            ListenBacklog = 1,
            ConnectionOptionsCallback = static (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions())
        };

        await using QuicListener listener = await QuicListener.ListenAsync(options);

        Assert.Equal(4 * 1024 * 1024, QuicListenerHost.DesiredSocketReceiveBufferBytes);
        Assert.True(listener.Host.Socket.ReceiveBufferSize >= platformDefault);
    }

    [Fact]
    public async Task Public_listener_increases_receive_buffer_after_shared_fan_in()
    {
        using Socket probeSocket = new(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.Udp);
        int expectedAvailableBufferSize = probeSocket.ReceiveBufferSize;
        try
        {
            probeSocket.ReceiveBufferSize = QuicListenerHost.DesiredSocketReceiveBufferBytes;
            expectedAvailableBufferSize = probeSocket.ReceiveBufferSize;
        }
        catch (SocketException)
        {
        }

        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(30));
        using var serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions serverOptions =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 2,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions, cancellationSource.Token);
        List<QuicConnection> connections = [];
        try
        {
            for (int index = 0; index < 2; index++)
            {
                Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
                QuicClientConnectionOptions clientOptions =
                    QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                        new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                        trustedServerCertificate: serverCertificate);
                Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
                    clientOptions,
                    cancellationSource.Token).AsTask();
                await Task.WhenAll(acceptTask, connectTask).WaitAsync(cancellationSource.Token);
                connections.Add(await acceptTask);
                connections.Add(await connectTask);
            }

            Assert.True(listener.Host.Socket.ReceiveBufferSize >= expectedAvailableBufferSize);
        }
        finally
        {
            foreach (QuicConnection connection in connections)
            {
                await connection.DisposeAsync();
            }
        }
    }
}

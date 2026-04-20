using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0009">The library MUST surface the initial peer stream-capacity delta through QuicConnectionOptions.StreamCapacityCallback on the supported loopback establishment path, and it MUST surface later real peer stream-capacity growth plus the supported close-driven reclaim increment through the same callback on the supported active loopback path. It MUST remain silent when the supported boundary is never reached and it MUST not emit synthetic deltas.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0009")]
public sealed class REQ_QUIC_API_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackEstablishment_ReportsTheInitialPeerStreamCapacityExactlyOnce()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        int callbackCount = 0;
        QuicConnection? observedConnection = null;
        QuicStreamCapacityChangedArgs observedArgs = default;
        TaskCompletionSource<bool> callbackObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (connection, args) =>
        {
            Interlocked.Increment(ref callbackCount);
            observedConnection = connection;
            observedArgs = args;
            callbackObserved.TrySetResult(true);
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await callbackObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, callbackCount);
        Assert.Equal(expectedServerOptions.MaxInboundBidirectionalStreams, observedArgs.BidirectionalIncrement);
        Assert.Equal(expectedServerOptions.MaxInboundUnidirectionalStreams, observedArgs.UnidirectionalIncrement);

        Task completionTask = Task.WhenAll(acceptTask, connectTask);
        Task completedTask = await Task.WhenAny(completionTask, Task.Delay(TimeSpan.FromSeconds(5)));
        if (completedTask != completionTask)
        {
            throw new TimeoutException(
                $"Loopback establishment did not complete. Observed callback count: {callbackCount}; client runtime: {QuicLoopbackEstablishmentTestSupport.DescribeConnection(observedConnection)}");
        }

        await completionTask;

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            Assert.Same(clientConnection, observedConnection);
            Assert.Equal(1, callbackCount);
            await Task.Delay(200);
            Assert.Equal(1, callbackCount);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackStreamClose_ReportsTheReleasedPeerStreamCapacityOnce()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 0;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 1;

        int callbackCount = 0;
        QuicConnection? observedConnection = null;
        ConcurrentQueue<QuicStreamCapacityChangedArgs> observedArgs = new();
        TaskCompletionSource<bool> initialObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> releaseObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (connection, args) =>
        {
            observedConnection = connection;
            observedArgs.Enqueue(args);

            int currentCount = Interlocked.Increment(ref callbackCount);
            if (currentCount == 1)
            {
                initialObserved.TrySetResult(true);
            }
            else if (currentCount == 2)
            {
                releaseObserved.TrySetResult(true);
            }
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            await initialObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Same(clientConnection, observedConnection);
            QuicStreamCapacityChangedArgs[] initialCallbacks = observedArgs.ToArray();
            Assert.Single(initialCallbacks);
            Assert.Equal(0, initialCallbacks[0].BidirectionalIncrement);
            Assert.Equal(1, initialCallbacks[0].UnidirectionalIncrement);
            Assert.Equal(1, callbackCount);

            QuicStream clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional);
            QuicStream serverStream = await serverConnection.AcceptInboundStreamAsync();

            byte[] payload = new byte[256];
            payload.AsSpan().Fill(0x51);
            await clientStream.WriteAsync(payload, 0, payload.Length);

            byte[] receiveBuffer = new byte[payload.Length];
            int bytesRead = await serverStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(payload.Length, bytesRead);
            Assert.True(payload.AsSpan().SequenceEqual(receiveBuffer));

            await Task.Delay(200);
            Assert.Equal(1, callbackCount);

            await clientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, await serverStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));

            Task completedReleaseTask = await Task.WhenAny(releaseObserved.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            if (completedReleaseTask != releaseObserved.Task)
            {
                QuicConnectionRuntime serverRuntime = GetRuntime(serverConnection);
                QuicConnectionRuntime clientRuntime = GetRuntime(clientConnection);
                bool hasServerSnapshot = serverRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)serverStream.Id, out QuicConnectionStreamSnapshot serverSnapshot);
                bool hasClientSnapshot = clientRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)clientStream.Id, out QuicConnectionStreamSnapshot clientSnapshot);
                throw new TimeoutException(
                    $"The released peer capacity was not observed. " +
                    $"ServerIncomingUnidirectionalLimit={serverRuntime.StreamRegistry.Bookkeeping.IncomingUnidirectionalStreamLimit}; " +
                    $"ClientPeerUnidirectionalLimit={clientRuntime.StreamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit}; " +
                    $"ServerStreamSnapshot={(hasServerSnapshot ? $"{serverSnapshot.SendState}/{serverSnapshot.ReceiveState}" : "<missing>")}; " +
                    $"ClientStreamSnapshot={(hasClientSnapshot ? $"{clientSnapshot.SendState}/{clientSnapshot.ReceiveState}" : "<missing>")}; " +
                    $"Server={QuicLoopbackEstablishmentTestSupport.DescribeConnection(serverConnection)}; " +
                    $"Client={QuicLoopbackEstablishmentTestSupport.DescribeConnection(clientConnection)}");
            }

            Assert.Equal(2, callbackCount);
            QuicStreamCapacityChangedArgs[] callbacks = observedArgs.ToArray();
            Assert.Equal(2, callbacks.Length);
            Assert.Equal(0, callbacks[1].BidirectionalIncrement);
            Assert.Equal(10, callbacks[1].UnidirectionalIncrement);

            QuicStream reopenedStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional);
            await reopenedStream.DisposeAsync();
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackBidirectionalStreamWriteAbortAfterPeerEof_ReportsTheReleasedPeerStreamCapacityOnce()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 1;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 0;

        int callbackCount = 0;
        QuicConnection? observedConnection = null;
        ConcurrentQueue<QuicStreamCapacityChangedArgs> observedArgs = new();
        TaskCompletionSource<bool> initialObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> releaseObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (connection, args) =>
        {
            observedConnection = connection;
            observedArgs.Enqueue(args);

            int currentCount = Interlocked.Increment(ref callbackCount);
            if (currentCount == 1)
            {
                initialObserved.TrySetResult(true);
            }
            else if (currentCount == 2)
            {
                releaseObserved.TrySetResult(true);
            }
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;
        QuicStream? clientStream = null;
        QuicStream? serverStream = null;

        try
        {
            await initialObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Same(clientConnection, observedConnection);
            QuicStreamCapacityChangedArgs[] initialCallbacks = observedArgs.ToArray();
            Assert.Single(initialCallbacks);
            Assert.Equal(1, initialCallbacks[0].BidirectionalIncrement);
            Assert.Equal(0, initialCallbacks[0].UnidirectionalIncrement);
            Assert.Equal(1, callbackCount);

            clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            serverStream = await serverConnection.AcceptInboundStreamAsync();

            byte[] payload = new byte[256];
            payload.AsSpan().Fill(0x62);
            await clientStream.WriteAsync(payload, 0, payload.Length);

            byte[] receiveBuffer = new byte[payload.Length];
            int bytesRead = await serverStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(payload.Length, bytesRead);
            Assert.True(payload.AsSpan().SequenceEqual(receiveBuffer));

            await clientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, await serverStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));

            serverStream.Abort(QuicAbortDirection.Write, 91);

            Task completedReleaseTask = await Task.WhenAny(releaseObserved.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            if (completedReleaseTask != releaseObserved.Task)
            {
                QuicConnectionRuntime serverRuntime = GetRuntime(serverConnection);
                QuicConnectionRuntime clientRuntime = GetRuntime(clientConnection);
                bool hasServerSnapshot = serverRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)clientStream!.Id, out QuicConnectionStreamSnapshot serverSnapshot);
                bool hasClientSnapshot = clientRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)clientStream.Id, out QuicConnectionStreamSnapshot clientSnapshot);
                throw new TimeoutException(
                    $"The released peer capacity was not observed. " +
                    $"ServerIncomingBidirectionalLimit={serverRuntime.StreamRegistry.Bookkeeping.IncomingBidirectionalStreamLimit}; " +
                    $"ClientPeerBidirectionalLimit={clientRuntime.StreamRegistry.Bookkeeping.PeerBidirectionalStreamLimit}; " +
                    $"ServerStreamSnapshot={(hasServerSnapshot ? $"{serverSnapshot.SendState}/{serverSnapshot.ReceiveState}" : "<missing>")}; " +
                    $"ClientStreamSnapshot={(hasClientSnapshot ? $"{clientSnapshot.SendState}/{clientSnapshot.ReceiveState}" : "<missing>")}; " +
                    $"Server={QuicLoopbackEstablishmentTestSupport.DescribeConnection(serverConnection)}; " +
                    $"Client={QuicLoopbackEstablishmentTestSupport.DescribeConnection(clientConnection)}");
            }

            Assert.Equal(2, callbackCount);
            QuicStreamCapacityChangedArgs[] callbacks = observedArgs.ToArray();
            Assert.Equal(2, callbacks.Length);
            Assert.Equal(100, callbacks[1].BidirectionalIncrement);
            Assert.Equal(0, callbacks[1].UnidirectionalIncrement);

            QuicStream reopenedStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            await reopenedStream.DisposeAsync();
        }
        finally
        {
            if (serverStream is not null)
            {
                await serverStream.DisposeAsync();
            }

            if (clientStream is not null)
            {
                await clientStream.DisposeAsync();
            }

            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackBidirectionalStreamWriteAbortAfterPeerEofWithoutLocalWrites_ReportsTheReleasedPeerStreamCapacityOnce()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 1;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 0;

        int callbackCount = 0;
        QuicConnection? observedConnection = null;
        ConcurrentQueue<QuicStreamCapacityChangedArgs> observedArgs = new();
        TaskCompletionSource<bool> initialObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> releaseObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (connection, args) =>
        {
            observedConnection = connection;
            observedArgs.Enqueue(args);

            int currentCount = Interlocked.Increment(ref callbackCount);
            if (currentCount == 1)
            {
                initialObserved.TrySetResult(true);
            }
            else if (currentCount == 2)
            {
                releaseObserved.TrySetResult(true);
            }
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;
        QuicStream? clientStream = null;
        QuicStream? serverStream = null;

        try
        {
            await initialObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Same(clientConnection, observedConnection);
            QuicStreamCapacityChangedArgs[] initialCallbacks = observedArgs.ToArray();
            Assert.Single(initialCallbacks);
            Assert.Equal(1, initialCallbacks[0].BidirectionalIncrement);
            Assert.Equal(0, initialCallbacks[0].UnidirectionalIncrement);
            Assert.Equal(1, callbackCount);

            clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            serverStream = await serverConnection.AcceptInboundStreamAsync();

            await clientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            byte[] receiveBuffer = new byte[1];
            Assert.Equal(0, await serverStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));

            serverStream.Abort(QuicAbortDirection.Write, 91);

            Task completedReleaseTask = await Task.WhenAny(releaseObserved.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            if (completedReleaseTask != releaseObserved.Task)
            {
                QuicConnectionRuntime serverRuntime = GetRuntime(serverConnection);
                QuicConnectionRuntime clientRuntime = GetRuntime(clientConnection);
                bool hasServerSnapshot = serverRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)clientStream!.Id, out QuicConnectionStreamSnapshot serverSnapshot);
                bool hasClientSnapshot = clientRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)clientStream.Id, out QuicConnectionStreamSnapshot clientSnapshot);
                throw new TimeoutException(
                    $"The released peer capacity was not observed. " +
                    $"ServerIncomingBidirectionalLimit={serverRuntime.StreamRegistry.Bookkeeping.IncomingBidirectionalStreamLimit}; " +
                    $"ClientPeerBidirectionalLimit={clientRuntime.StreamRegistry.Bookkeeping.PeerBidirectionalStreamLimit}; " +
                    $"ServerStreamSnapshot={(hasServerSnapshot ? $"{serverSnapshot.SendState}/{serverSnapshot.ReceiveState}" : "<missing>")}; " +
                    $"ClientStreamSnapshot={(hasClientSnapshot ? $"{clientSnapshot.SendState}/{clientSnapshot.ReceiveState}" : "<missing>")}; " +
                    $"Server={QuicLoopbackEstablishmentTestSupport.DescribeConnection(serverConnection)}; " +
                    $"Client={QuicLoopbackEstablishmentTestSupport.DescribeConnection(clientConnection)}");
            }

            Assert.Equal(2, callbackCount);
            QuicStreamCapacityChangedArgs[] callbacks = observedArgs.ToArray();
            Assert.Equal(2, callbacks.Length);
            Assert.Equal(100, callbacks[1].BidirectionalIncrement);
            Assert.Equal(0, callbacks[1].UnidirectionalIncrement);

            QuicStream reopenedStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            await reopenedStream.DisposeAsync();
        }
        finally
        {
            if (serverStream is not null)
            {
                await serverStream.DisposeAsync();
            }

            if (clientStream is not null)
            {
                await clientStream.DisposeAsync();
            }

            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackBidirectionalStreamBothAbortAfterPeerEof_ReportsTheReleasedPeerStreamCapacityOnce()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 1;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 0;

        int callbackCount = 0;
        QuicConnection? observedConnection = null;
        ConcurrentQueue<QuicStreamCapacityChangedArgs> observedArgs = new();
        TaskCompletionSource<bool> initialObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> releaseObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (connection, args) =>
        {
            observedConnection = connection;
            observedArgs.Enqueue(args);

            int currentCount = Interlocked.Increment(ref callbackCount);
            if (currentCount == 1)
            {
                initialObserved.TrySetResult(true);
            }
            else if (currentCount == 2)
            {
                releaseObserved.TrySetResult(true);
            }
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;
        QuicStream? clientStream = null;
        QuicStream? serverStream = null;

        try
        {
            await initialObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Same(clientConnection, observedConnection);
            QuicStreamCapacityChangedArgs[] initialCallbacks = observedArgs.ToArray();
            Assert.Single(initialCallbacks);
            Assert.Equal(1, initialCallbacks[0].BidirectionalIncrement);
            Assert.Equal(0, initialCallbacks[0].UnidirectionalIncrement);
            Assert.Equal(1, callbackCount);

            clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            serverStream = await serverConnection.AcceptInboundStreamAsync();

            byte[] payload = new byte[256];
            payload.AsSpan().Fill(0x63);
            await clientStream.WriteAsync(payload, 0, payload.Length);

            byte[] receiveBuffer = new byte[payload.Length];
            int bytesRead = await serverStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(payload.Length, bytesRead);
            Assert.True(payload.AsSpan().SequenceEqual(receiveBuffer));

            await clientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, await serverStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));

            serverStream.Abort(QuicAbortDirection.Both, 91);

            Task completedReleaseTask = await Task.WhenAny(releaseObserved.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            if (completedReleaseTask != releaseObserved.Task)
            {
                QuicConnectionRuntime serverRuntime = GetRuntime(serverConnection);
                QuicConnectionRuntime clientRuntime = GetRuntime(clientConnection);
                bool hasServerSnapshot = serverRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)clientStream!.Id, out QuicConnectionStreamSnapshot serverSnapshot);
                bool hasClientSnapshot = clientRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)clientStream.Id, out QuicConnectionStreamSnapshot clientSnapshot);
                throw new TimeoutException(
                    $"The released peer capacity was not observed. " +
                    $"ServerIncomingBidirectionalLimit={serverRuntime.StreamRegistry.Bookkeeping.IncomingBidirectionalStreamLimit}; " +
                    $"ClientPeerBidirectionalLimit={clientRuntime.StreamRegistry.Bookkeeping.PeerBidirectionalStreamLimit}; " +
                    $"ServerStreamSnapshot={(hasServerSnapshot ? $"{serverSnapshot.SendState}/{serverSnapshot.ReceiveState}" : "<missing>")}; " +
                    $"ClientStreamSnapshot={(hasClientSnapshot ? $"{clientSnapshot.SendState}/{clientSnapshot.ReceiveState}" : "<missing>")}; " +
                    $"Server={QuicLoopbackEstablishmentTestSupport.DescribeConnection(serverConnection)}; " +
                    $"Client={QuicLoopbackEstablishmentTestSupport.DescribeConnection(clientConnection)}");
            }

            Assert.Equal(2, callbackCount);
            QuicStreamCapacityChangedArgs[] callbacks = observedArgs.ToArray();
            Assert.Equal(2, callbacks.Length);
            Assert.Equal(100, callbacks[1].BidirectionalIncrement);
            Assert.Equal(0, callbacks[1].UnidirectionalIncrement);

            QuicStream reopenedStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            await reopenedStream.DisposeAsync();
        }
        finally
        {
            if (serverStream is not null)
            {
                await serverStream.DisposeAsync();
            }

            if (clientStream is not null)
            {
                await clientStream.DisposeAsync();
            }

            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackLaterCapacityGrowth_ReportsRealMaxStreamsDeltasExactlyOnce()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 3;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 2;

        int callbackCount = 0;
        QuicConnection? observedConnection = null;
        ConcurrentQueue<QuicStreamCapacityChangedArgs> observedArgs = new();
        TaskCompletionSource<bool> initialObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> laterObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (connection, args) =>
        {
            observedConnection = connection;
            observedArgs.Enqueue(args);

            int currentCount = Interlocked.Increment(ref callbackCount);
            if (currentCount == 1)
            {
                initialObserved.TrySetResult(true);
            }
            else if (currentCount == 2)
            {
                laterObserved.TrySetResult(true);
            }
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            await initialObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Same(clientConnection, observedConnection);
            Assert.Equal(1, callbackCount);

            QuicStreamCapacityChangedArgs[] initialCallbacks = observedArgs.ToArray();
            Assert.Single(initialCallbacks);
            Assert.Equal(3, initialCallbacks[0].BidirectionalIncrement);
            Assert.Equal(2, initialCallbacks[0].UnidirectionalIncrement);

            IPEndPoint clientLocalEndPoint = GetConnectionLocalEndPoint(clientConnection);
            SendLaterMaxStreamsFrame(listener, serverConnection, clientLocalEndPoint, 5, 4);

            await laterObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(2, callbackCount);
            QuicStreamCapacityChangedArgs[] laterCallbacks = observedArgs.ToArray();
            Assert.Equal(2, laterCallbacks.Length);
            Assert.Equal(2, laterCallbacks[1].BidirectionalIncrement);
            Assert.Equal(2, laterCallbacks[1].UnidirectionalIncrement);

            SendLaterMaxStreamsFrame(listener, serverConnection, clientLocalEndPoint, 5, 4);
            await Task.Delay(200);

            Assert.Equal(2, callbackCount);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SupportedLoopbackCloseDrivenRelease_DoesNotFireForLocalReadAbortAlone()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 1;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 0;

        int callbackCount = 0;
        TaskCompletionSource<bool> initialObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (_, _) =>
        {
            if (Interlocked.Increment(ref callbackCount) == 1)
            {
                initialObserved.TrySetResult(true);
            }
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;
        QuicStream? serverStream = null;
        QuicStream? clientStream = null;

        try
        {
            await initialObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
            clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            serverStream = await acceptStreamTask.WaitAsync(TimeSpan.FromSeconds(5));

            serverStream.Abort(QuicAbortDirection.Read, 17);

            await Task.Delay(300);
            Assert.Equal(1, callbackCount);
        }
        finally
        {
            if (serverStream is not null)
            {
                await serverStream.DisposeAsync();
            }

            if (clientStream is not null)
            {
                await clientStream.DisposeAsync();
            }

            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SupportedLoopbackCloseDrivenRelease_DoesNotFireForLocalWriteAbortAlone()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 1;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 0;

        int callbackCount = 0;
        TaskCompletionSource<bool> initialObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (_, _) =>
        {
            if (Interlocked.Increment(ref callbackCount) == 1)
            {
                initialObserved.TrySetResult(true);
            }
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;
        QuicStream? serverStream = null;
        QuicStream? clientStream = null;

        try
        {
            await initialObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, callbackCount);

            clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            serverStream = await serverConnection.AcceptInboundStreamAsync();

            byte[] payload = new byte[256];
            payload.AsSpan().Fill(0x64);
            await clientStream.WriteAsync(payload, 0, payload.Length);

            byte[] receiveBuffer = new byte[payload.Length];
            int bytesRead = await serverStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(payload.Length, bytesRead);
            Assert.True(payload.AsSpan().SequenceEqual(receiveBuffer));

            serverStream.Abort(QuicAbortDirection.Write, 17);
            await Task.Delay(200);

            Assert.Equal(1, callbackCount);
        }
        finally
        {
            if (serverStream is not null)
            {
                await serverStream.DisposeAsync();
            }

            if (clientStream is not null)
            {
                await clientStream.DisposeAsync();
            }

            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SupportedLoopbackLaterCapacityGrowth_IsSilentAfterClientDisposal()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 3;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 2;

        int callbackCount = 0;
        TaskCompletionSource<bool> initialObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (_, _) =>
        {
            int currentCount = Interlocked.Increment(ref callbackCount);
            if (currentCount == 1)
            {
                initialObserved.TrySetResult(true);
            }
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            await initialObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, callbackCount);

            IPEndPoint clientLocalEndPoint = GetConnectionLocalEndPoint(clientConnection);
            await clientConnection.DisposeAsync();

            SendLaterMaxStreamsFrame(listener, serverConnection, clientLocalEndPoint, 5, 4);
            await Task.Delay(200);

            Assert.Equal(1, callbackCount);
        }
        finally
        {
            await serverConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task CanceledConnect_DoesNotReportStreamCapacity()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        int callbackCount = 0;
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> callbackRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = async (_, _, cancellationToken) =>
            {
                callbackEntered.TrySetResult(true);
                await callbackRelease.Task.WaitAsync(cancellationToken);
                return QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
            },
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (_, _) => Interlocked.Increment(ref callbackCount);

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        using CancellationTokenSource cancellationSource = new();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions, cancellationSource.Token).AsTask();

        await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellationSource.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connectTask);
        callbackRelease.TrySetResult(true);

        await Task.Delay(TimeSpan.FromMilliseconds(100));
        Assert.Equal(0, callbackCount);
    }

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        FieldInfo? runtimeField = typeof(QuicConnection).GetField("runtime", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(runtimeField);
        return Assert.IsType<QuicConnectionRuntime>(runtimeField!.GetValue(connection));
    }

    private static IPEndPoint GetConnectionLocalEndPoint(QuicConnection connection)
    {
        QuicConnectionRuntime runtime = GetRuntime(connection);
        Assert.NotNull(runtime.ActivePath);

        QuicConnectionPathIdentity identity = runtime.ActivePath!.Value.Identity;
        Assert.False(string.IsNullOrWhiteSpace(identity.LocalAddress));
        Assert.True(identity.LocalPort.HasValue);

        return new IPEndPoint(IPAddress.Parse(identity.LocalAddress!), identity.LocalPort.Value);
    }

    private static void SendLaterMaxStreamsFrame(
        QuicListener listener,
        QuicConnection senderConnection,
        IPEndPoint receiverLocalEndPoint,
        ulong bidirectionalMaximumStreams,
        ulong unidirectionalMaximumStreams)
    {
        QuicConnectionRuntime senderRuntime = GetRuntime(senderConnection);
        Socket listenerSocket = GetListenerSocket(listener);
        QuicHandshakeFlowCoordinator handshakeFlowCoordinator = GetHandshakeFlowCoordinator(senderRuntime);
        QuicTlsPacketProtectionMaterial? protectMaterial = senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial;
        Assert.NotNull(protectMaterial);

        Span<byte> applicationPayload = stackalloc byte[32];
        Assert.True(
            QuicFrameCodec.TryFormatMaxStreamsFrame(
                new QuicMaxStreamsFrame(true, bidirectionalMaximumStreams),
                applicationPayload,
                out int bidirectionalBytesWritten));
        Assert.True(
            QuicFrameCodec.TryFormatMaxStreamsFrame(
                new QuicMaxStreamsFrame(false, unidirectionalMaximumStreams),
                applicationPayload[bidirectionalBytesWritten..],
                out int unidirectionalBytesWritten));

        int payloadBytes = bidirectionalBytesWritten + unidirectionalBytesWritten;
        Assert.True(
            handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload[..payloadBytes],
                protectMaterial.Value,
                out byte[] protectedPacket));

        int bytesSent = listenerSocket.SendTo(protectedPacket, SocketFlags.None, receiverLocalEndPoint);
        Assert.Equal(protectedPacket.Length, bytesSent);
    }

    private static QuicHandshakeFlowCoordinator GetHandshakeFlowCoordinator(QuicConnectionRuntime runtime)
    {
        FieldInfo? handshakeFlowField = typeof(QuicConnectionRuntime).GetField(
            "handshakeFlowCoordinator",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(handshakeFlowField);
        return Assert.IsType<QuicHandshakeFlowCoordinator>(handshakeFlowField!.GetValue(runtime));
    }

    private static Socket GetListenerSocket(QuicListener listener)
    {
        FieldInfo? hostField = typeof(QuicListener).GetField("host", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(hostField);
        QuicListenerHost host = Assert.IsType<QuicListenerHost>(hostField!.GetValue(listener));
        FieldInfo? socketField = typeof(QuicListenerHost).GetField("socket", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(socketField);
        return Assert.IsType<Socket>(socketField!.GetValue(host));
    }
}

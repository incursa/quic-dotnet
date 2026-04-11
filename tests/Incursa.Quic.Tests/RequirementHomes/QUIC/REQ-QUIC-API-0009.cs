using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0009">The library MUST surface the initial peer stream-capacity delta through QuicConnectionOptions.StreamCapacityCallback on the supported loopback establishment path, and it MUST remain silent when the supported boundary is never reached.</workbench-requirement>
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

            QuicStream clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            QuicStream serverStream = await serverConnection.AcceptInboundStreamAsync();
            await clientStream.DisposeAsync();
            await serverStream.DisposeAsync();
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
}

using System.Buffers;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Threading.Channels;

namespace Incursa.Quic;

internal sealed class QuicListenerHost : IAsyncDisposable, IDisposable
{
    private readonly Socket socket;
    private readonly CancellationTokenSource shutdown = new();
    private readonly Channel<object> acceptQueue;
    private readonly Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> connectionOptionsCallback;

    private CancellationTokenSource? listenerCancellationSource;
    private Task? runningTask;
    private int started;
    private int disposed;

    public QuicListenerHost(
        IPEndPoint listenEndPoint,
        List<SslApplicationProtocol> applicationProtocols,
        Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> connectionOptionsCallback,
        int listenBacklog)
    {
        ArgumentNullException.ThrowIfNull(listenEndPoint);
        ArgumentNullException.ThrowIfNull(applicationProtocols);
        ArgumentNullException.ThrowIfNull(connectionOptionsCallback);

        if (listenBacklog <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(listenBacklog));
        }

        this.connectionOptionsCallback = connectionOptionsCallback;
        acceptQueue = Channel.CreateBounded<object>(new BoundedChannelOptions(listenBacklog)
        {
            SingleReader = false,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
            FullMode = BoundedChannelFullMode.Wait,
        });

        IPEndPoint boundEndPoint = new(listenEndPoint.Address, listenEndPoint.Port);
        socket = new Socket(boundEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (socket.AddressFamily == AddressFamily.InterNetworkV6 && boundEndPoint.Address.Equals(IPAddress.IPv6Any))
        {
            socket.DualMode = true;
        }

        socket.Bind(boundEndPoint);
    }

    public Task RunAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (Interlocked.CompareExchange(ref started, 1, 0) != 0)
        {
            throw new InvalidOperationException("The listener host can only be started once.");
        }

        listenerCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);
        CancellationToken hostCancellation = listenerCancellationSource.Token;
        runningTask = ReceiveLoopAsync(hostCancellation);
        return runningTask;
    }

    public async ValueTask<QuicConnection> EnqueueIncomingConnectionAsync(
        SslClientHelloInfo clientHello,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        QuicServerConnectionOptions selectedOptions = new();
        QuicConnectionRuntime runtime = CreateRuntime(selectedOptions);
        QuicConnection connection = new(runtime, selectedOptions);

        try
        {
            using CancellationTokenSource acceptCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);
            QuicServerConnectionOptions returnedOptions = await connectionOptionsCallback(
                connection,
                clientHello,
                acceptCancellationSource.Token).ConfigureAwait(false);

            if (returnedOptions is null)
            {
                throw new InvalidOperationException("The connection-options callback returned null.");
            }

            ApplyReturnedOptions(selectedOptions, returnedOptions);
            await acceptQueue.Writer.WriteAsync(connection, acceptCancellationSource.Token).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<QuicConnection> AcceptConnectionAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        using CancellationTokenSource acceptCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);

        try
        {
            object item = await acceptQueue.Reader.ReadAsync(acceptCancellationSource.Token).ConfigureAwait(false);
            return UnwrapQueuedItem(item);
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new ObjectDisposedException(nameof(QuicListenerHost));
        }
        catch (ChannelClosedException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await shutdown.CancelAsync().ConfigureAwait(false);
        CancellationTokenSource? cancellationSource = Interlocked.Exchange(ref listenerCancellationSource, null);
        if (cancellationSource is not null)
        {
            await cancellationSource.CancelAsync().ConfigureAwait(false);
        }

        try
        {
            socket.Dispose();
        }
        catch
        {
            // Best-effort shutdown only.
        }

        acceptQueue.Writer.TryComplete(ExceptionDispatchInfo.SetCurrentStackTrace(new ObjectDisposedException(nameof(QuicListenerHost))));

        Task? task = runningTask;
        if (task is not null)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
            {
                // Expected during shutdown.
            }
        }

        while (acceptQueue.Reader.TryRead(out object? item))
        {
            if (item is QuicConnection connection)
            {
                try
                {
                    await connection.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                    // Best-effort cleanup only.
                }
            }
        }

        cancellationSource?.Dispose();
        shutdown.Dispose();
    }

    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int bytesReceived;
                try
                {
                    bytesReceived = await socket.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException) when (shutdown.IsCancellationRequested)
                {
                    break;
                }

                if (bytesReceived > 0)
                {
                    // In this slice we only keep the socket honest; connection admission is fed through the narrow callback seam.
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static QuicConnection UnwrapQueuedItem(object item)
    {
        if (item is QuicConnection connection)
        {
            return connection;
        }

        if (item is Exception exception)
        {
            throw exception;
        }

        throw new InvalidOperationException("Unexpected listener queue item.");
    }

    private static QuicConnectionRuntime CreateRuntime(QuicServerConnectionOptions options)
    {
        QuicReceiveWindowSizes receiveWindowSizes = options.InitialReceiveWindowSizes;
        QuicConnectionStreamState bookkeeping = new(new QuicConnectionStreamStateOptions(
            IsServer: true,
            InitialConnectionReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.Connection),
            InitialConnectionSendLimit: (ulong)Math.Max(0, receiveWindowSizes.Connection),
            InitialIncomingBidirectionalStreamLimit: (ulong)Math.Max(0, options.MaxInboundBidirectionalStreams),
            InitialIncomingUnidirectionalStreamLimit: (ulong)Math.Max(0, options.MaxInboundUnidirectionalStreams),
            InitialPeerBidirectionalStreamLimit: 0,
            InitialPeerUnidirectionalStreamLimit: 0,
            InitialLocalBidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.LocallyInitiatedBidirectionalStream),
            InitialPeerBidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.RemotelyInitiatedBidirectionalStream),
            InitialPeerUnidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.UnidirectionalStream),
            InitialLocalBidirectionalSendLimit: (ulong)Math.Max(0, receiveWindowSizes.LocallyInitiatedBidirectionalStream),
            InitialLocalUnidirectionalSendLimit: (ulong)Math.Max(0, receiveWindowSizes.UnidirectionalStream),
            InitialPeerBidirectionalSendLimit: 0));

        return new QuicConnectionRuntime(bookkeeping, tlsRole: QuicTlsRole.Server);
    }

    private static void ApplyReturnedOptions(QuicServerConnectionOptions selectedOptions, QuicServerConnectionOptions returnedOptions)
    {
        selectedOptions.DefaultCloseErrorCode = returnedOptions.DefaultCloseErrorCode;
        selectedOptions.DefaultStreamErrorCode = returnedOptions.DefaultStreamErrorCode;
        selectedOptions.HandshakeTimeout = returnedOptions.HandshakeTimeout;
        selectedOptions.IdleTimeout = returnedOptions.IdleTimeout;
        selectedOptions.KeepAliveInterval = returnedOptions.KeepAliveInterval;
        selectedOptions.MaxInboundBidirectionalStreams = returnedOptions.MaxInboundBidirectionalStreams;
        selectedOptions.MaxInboundUnidirectionalStreams = returnedOptions.MaxInboundUnidirectionalStreams;
        selectedOptions.ServerAuthenticationOptions = returnedOptions.ServerAuthenticationOptions;

        QuicReceiveWindowSizes returnedWindowSizes = returnedOptions.InitialReceiveWindowSizes;
        selectedOptions.InitialReceiveWindowSizes = new QuicReceiveWindowSizes
        {
            Connection = returnedWindowSizes.Connection,
            LocallyInitiatedBidirectionalStream = returnedWindowSizes.LocallyInitiatedBidirectionalStream,
            RemotelyInitiatedBidirectionalStream = returnedWindowSizes.RemotelyInitiatedBidirectionalStream,
            UnidirectionalStream = returnedWindowSizes.UnidirectionalStream,
        };
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicListenerHost));
        }
    }
}

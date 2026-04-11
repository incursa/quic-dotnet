using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace Incursa.Quic;

internal sealed class QuicListenerHost : IAsyncDisposable, IDisposable
{
    private const int RouteConnectionIdLength = 8;
    private const ulong MinimumActiveConnectionIdLimit = 2;
    private const ulong TicksPerMicrosecond = (ulong)TimeSpan.TicksPerSecond / 1_000_000UL;

    private readonly Socket socket;
    private readonly CancellationTokenSource shutdown = new();
    private readonly Channel<object> acceptQueue;
    private readonly List<SslApplicationProtocol> applicationProtocols;
    private readonly Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> connectionOptionsCallback;
    private readonly QuicConnectionRuntimeEndpoint endpoint;
    private readonly ConcurrentDictionary<QuicConnectionHandle, PendingConnectionState> connections = new();

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

        this.applicationProtocols = [.. applicationProtocols];
        this.connectionOptionsCallback = connectionOptionsCallback;
        endpoint = new QuicConnectionRuntimeEndpoint(1);
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

        Task endpointTask = endpoint.RunAsync(
            ObserveTransition,
            ObserveEffect,
            hostCancellation);

        Task receiveTask = ReceiveLoopAsync(hostCancellation);
        runningTask = Task.WhenAll(endpointTask, receiveTask);
        return runningTask;
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

        try
        {
            await endpoint.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
            // Best-effort shutdown only.
        }

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

        foreach (PendingConnectionState state in connections.Values)
        {
            try
            {
                await state.Connection.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // Best-effort cleanup only.
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
            EndPoint remoteEndPoint = socket.AddressFamily == AddressFamily.InterNetworkV6
                ? new IPEndPoint(IPAddress.IPv6Any, 0)
                : new IPEndPoint(IPAddress.Any, 0);

            while (!cancellationToken.IsCancellationRequested)
            {
                SocketReceiveFromResult receiveResult;
                try
                {
                    receiveResult = await socket.ReceiveFromAsync(
                        buffer.AsMemory(),
                        SocketFlags.None,
                        remoteEndPoint,
                        cancellationToken).ConfigureAwait(false);
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

                if (receiveResult.ReceivedBytes <= 0)
                {
                    continue;
                }

                IPEndPoint receivedFrom = (IPEndPoint)receiveResult.RemoteEndPoint;
                IPEndPoint localEndPoint = (IPEndPoint)socket.LocalEndPoint!;
                QuicConnectionPathIdentity pathIdentity = CreatePathIdentity(receivedFrom, localEndPoint);

                byte[] datagram = buffer.AsSpan(0, receiveResult.ReceivedBytes).ToArray();
                QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(datagram, pathIdentity);
                if (ingressResult.Disposition == QuicConnectionIngressDisposition.RoutedToConnection
                    || ingressResult.Disposition == QuicConnectionIngressDisposition.EndpointHandling)
                {
                    continue;
                }

                if (TryParseInitialDatagram(datagram, out QuicLongHeaderPacket initialHeader))
                {
                    try
                    {
                        if (await TryAdmitIncomingInitialConnectionAsync(
                            datagram,
                            pathIdentity,
                            initialHeader.DestinationConnectionId.ToArray(),
                            initialHeader.SourceConnectionId.ToArray(),
                            cancellationToken).ConfigureAwait(false))
                        {
                            _ = endpoint.ReceiveDatagram(datagram, pathIdentity);
                        }
                    }
                    catch
                    {
                        // Admission failures remain local to the listener shell.
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void ObserveTransition(QuicConnectionHandle handle, int shardIndex, QuicConnectionTransitionResult transition)
    {
        _ = shardIndex;

        if (!connections.TryGetValue(handle, out PendingConnectionState? state))
        {
            return;
        }

        if (state.Runtime.TerminalState is QuicConnectionTerminalState terminalState
            && state.TryMarkFailed())
        {
            connections.TryRemove(handle, out _);
            _ = QueueConnectionFailureAsync(state.Connection, MapTerminalState(terminalState));
            return;
        }

        if (transition.CurrentPhase == QuicConnectionPhase.Active
            && state.Runtime.PeerHandshakeTranscriptCompleted
            && state.TryMarkAccepted())
        {
            connections.TryRemove(handle, out _);
            _ = QueueAcceptedConnectionAsync(state.Connection);
        }
    }

    private void ObserveEffect(QuicConnectionHandle handle, int shardIndex, QuicConnectionEffect effect)
    {
        _ = handle;
        _ = shardIndex;

        if (effect is QuicConnectionSendDatagramEffect sendDatagramEffect)
        {
            SendDatagram(sendDatagramEffect);
        }
    }

    private void SendDatagram(QuicConnectionSendDatagramEffect sendDatagramEffect)
    {
        try
        {
            EndPoint remoteEndPoint = new IPEndPoint(
                IPAddress.Parse(sendDatagramEffect.PathIdentity.RemoteAddress),
                sendDatagramEffect.PathIdentity.RemotePort ?? throw new InvalidOperationException("The listener connection path is missing a remote port."));

            int bytesSent = socket.SendTo(sendDatagramEffect.Datagram.Span, SocketFlags.None, remoteEndPoint);
            if (bytesSent != sendDatagramEffect.Datagram.Length)
            {
                throw new IOException("Failed to send the complete QUIC datagram.");
            }
        }
        catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
        {
            // Expected during shutdown.
        }
        catch (SocketException) when (shutdown.IsCancellationRequested)
        {
            // Expected during shutdown.
        }
    }

    private static bool TryParseInitialDatagram(ReadOnlySpan<byte> datagram, out QuicLongHeaderPacket longHeader)
    {
        if (!QuicPacketParser.TryParseLongHeader(datagram, out longHeader)
            || longHeader.Version != 1
            || longHeader.LongPacketTypeBits != QuicLongPacketTypeBits.Initial)
        {
            longHeader = default;
            return false;
        }

        return true;
    }

    private async ValueTask<bool> TryAdmitIncomingInitialConnectionAsync(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        byte[] initialDestinationConnectionId,
        byte[] clientSourceConnectionId,
        CancellationToken cancellationToken)
    {
        QuicServerConnectionOptions selectedOptions = new();
        QuicConnectionRuntime? runtime = null;
        QuicConnection? connection = null;
        QuicConnectionHandle handle = default;
        bool admitted = false;

        try
        {
            if (!QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Server,
                initialDestinationConnectionId,
                out QuicInitialPacketProtection initialProtection))
            {
                return false;
            }

            QuicHandshakeFlowCoordinator initialPacketCoordinator = new();
            if (!initialPacketCoordinator.TryOpenInitialPacket(
                datagram.Span,
                initialProtection,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength)
                || !TryValidateInitialCryptoPayload(openedPacket.AsSpan(payloadOffset, payloadLength)))
            {
                return false;
            }

            byte[] serverSourceConnectionId = GenerateServerSourceConnectionId();
            runtime = CreateRuntime(selectedOptions);
            handle = endpoint.AllocateConnectionHandle();
            QuicServerConnectionLifetime lifetimeOwner = new(endpoint, handle, runtime);
            connection = new QuicConnection(runtime, selectedOptions, lifetimeOwner);

            if (!endpoint.TryRegisterConnection(handle, runtime)
                || !endpoint.TryRegisterConnectionId(handle, initialDestinationConnectionId)
                || !endpoint.TryRegisterConnectionId(handle, serverSourceConnectionId)
                || !endpoint.TryUpdateEndpointBinding(handle, pathIdentity))
            {
                return false;
            }

            if (!connections.TryAdd(handle, new PendingConnectionState(handle, runtime, connection)))
            {
                return false;
            }

            using CancellationTokenSource acceptCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);
            QuicServerConnectionOptions returnedOptions = await connectionOptionsCallback(
                connection,
                new SslClientHelloInfo(string.Empty, SslProtocols.Tls13),
                acceptCancellationSource.Token).ConfigureAwait(false);

            if (returnedOptions is null)
            {
                return false;
            }

            QuicServerConnectionSettings validatedOptions = QuicServerConnectionOptionsValidator.Capture(
                returnedOptions,
                "returnedOptions",
                applicationProtocols);

            ApplyReturnedOptions(selectedOptions, returnedOptions);

            if (!runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId)
                || !runtime.TrySetHandshakeDestinationConnectionId(clientSourceConnectionId)
                || !runtime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId)
                || !runtime.TryConfigureServerAuthenticationMaterial(
                    validatedOptions.ServerLeafCertificateDer,
                    validatedOptions.ServerLeafSigningPrivateKey))
            {
                return false;
            }

            if (!endpoint.Host.TryPostEvent(
                handle,
                new QuicConnectionHandshakeBootstrapRequestedEvent(
                    runtime.Clock.Ticks,
                    CreateLocalTransportParameters(selectedOptions, serverSourceConnectionId))))
            {
                return false;
            }

            admitted = true;
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (!admitted)
            {
                if (!EqualityComparer<QuicConnectionHandle>.Default.Equals(handle, default))
                {
                    connections.TryRemove(handle, out _);
                }

                try
                {
                    if (connection is not null)
                    {
                        await connection.DisposeAsync().ConfigureAwait(false);
                    }
                    else if (runtime is not null)
                    {
                        await runtime.DisposeAsync().ConfigureAwait(false);
                    }
                }
                catch
                {
                    // Best-effort cleanup only.
                }
            }
        }
    }

    private static bool TryValidateInitialCryptoPayload(ReadOnlySpan<byte> payload)
    {
        bool sawCryptoFrame = false;
        int payloadOffset = 0;

        while (payloadOffset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[payloadOffset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                if (paddingBytesConsumed <= 0)
                {
                    return false;
                }

                payloadOffset += paddingBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out _, out int bytesConsumed)
                || bytesConsumed <= 0)
            {
                return false;
            }

            sawCryptoFrame = true;
            payloadOffset += bytesConsumed;
        }

        return sawCryptoFrame;
    }

    private static QuicConnectionPathIdentity CreatePathIdentity(IPEndPoint remoteEndPoint, IPEndPoint localEndPoint)
    {
        return new QuicConnectionPathIdentity(
            remoteEndPoint.Address.ToString(),
            localEndPoint.Address.ToString(),
            remoteEndPoint.Port,
            localEndPoint.Port);
    }

    private static byte[] GenerateServerSourceConnectionId()
    {
        byte[] connectionId = new byte[RouteConnectionIdLength];
        RandomNumberGenerator.Fill(connectionId);
        return connectionId;
    }

    private static QuicTransportParameters CreateLocalTransportParameters(
        QuicServerConnectionOptions options,
        ReadOnlySpan<byte> sourceConnectionId)
    {
        QuicReceiveWindowSizes receiveWindowSizes = options.InitialReceiveWindowSizes;

        return new QuicTransportParameters
        {
            MaxIdleTimeout = options.IdleTimeout > TimeSpan.Zero
                ? checked((ulong)options.IdleTimeout.Ticks / TicksPerMicrosecond)
                : 0,
            InitialMaxData = (ulong)Math.Max(0, receiveWindowSizes.Connection),
            InitialMaxStreamDataBidiLocal = (ulong)Math.Max(0, receiveWindowSizes.LocallyInitiatedBidirectionalStream),
            InitialMaxStreamDataBidiRemote = (ulong)Math.Max(0, receiveWindowSizes.RemotelyInitiatedBidirectionalStream),
            InitialMaxStreamDataUni = (ulong)Math.Max(0, receiveWindowSizes.UnidirectionalStream),
            InitialMaxStreamsBidi = (ulong)Math.Max(0, options.MaxInboundBidirectionalStreams),
            InitialMaxStreamsUni = (ulong)Math.Max(0, options.MaxInboundUnidirectionalStreams),
            ActiveConnectionIdLimit = MinimumActiveConnectionIdLimit,
            InitialSourceConnectionId = sourceConnectionId.ToArray(),
        };
    }

    private static Exception MapTerminalState(QuicConnectionTerminalState terminalState)
    {
        if (terminalState.Close.TransportErrorCode.HasValue)
        {
            return new QuicException(
                QuicError.TransportError,
                null,
                (long)terminalState.Close.TransportErrorCode.Value,
                terminalState.Close.ReasonPhrase ?? "The listener connection terminated during establishment.");
        }

        if (terminalState.Origin == QuicConnectionCloseOrigin.IdleTimeout)
        {
            return new QuicException(
                QuicError.ConnectionIdle,
                null,
                terminalState.Close.ReasonPhrase ?? "The listener connection idled before establishment completed.");
        }

        long? applicationErrorCode = terminalState.Close.ApplicationErrorCode.HasValue
            ? checked((long)terminalState.Close.ApplicationErrorCode.Value)
            : null;

        return new QuicException(
            QuicError.ConnectionAborted,
            applicationErrorCode,
            terminalState.Close.ReasonPhrase ?? "The listener connection terminated during establishment.");
    }

    private async Task QueueAcceptedConnectionAsync(QuicConnection connection)
    {
        try
        {
            await acceptQueue.Writer.WriteAsync(connection, shutdown.Token).ConfigureAwait(false);
        }
        catch
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

    private async Task QueueConnectionFailureAsync(QuicConnection connection, Exception exception)
    {
        try
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
            // Best-effort cleanup only.
        }

        try
        {
            await acceptQueue.Writer.WriteAsync(exception, shutdown.Token).ConfigureAwait(false);
        }
        catch
        {
            // The listener is shutting down or the queue is closed.
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

    private sealed class PendingConnectionState
    {
        private const int AcceptedStatus = 1;
        private const int FailedStatus = 2;
        private int status;

        public PendingConnectionState(
            QuicConnectionHandle handle,
            QuicConnectionRuntime runtime,
            QuicConnection connection)
        {
            Handle = handle;
            Runtime = runtime;
            Connection = connection;
        }

        public QuicConnectionHandle Handle { get; }

        public QuicConnectionRuntime Runtime { get; }

        public QuicConnection Connection { get; }

        public bool TryMarkAccepted()
        {
            return Interlocked.CompareExchange(ref status, AcceptedStatus, 0) == 0;
        }

        public bool TryMarkFailed()
        {
            return Interlocked.CompareExchange(ref status, FailedStatus, 0) == 0;
        }
    }

    private sealed class QuicServerConnectionLifetime : IAsyncDisposable
    {
        private readonly QuicConnectionRuntimeEndpoint endpoint;
        private readonly QuicConnectionHandle handle;
        private readonly QuicConnectionRuntime runtime;
        private int disposed;

        public QuicServerConnectionLifetime(
            QuicConnectionRuntimeEndpoint endpoint,
            QuicConnectionHandle handle,
            QuicConnectionRuntime runtime)
        {
            this.endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
            this.handle = handle;
            this.runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            endpoint.TryUnregisterConnection(handle);
            await runtime.DisposeAsync().ConfigureAwait(false);
        }
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

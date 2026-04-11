using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Incursa.Quic;

[SuppressMessage("Performance", "S1450", Justification = "The client host must retain its runtime, endpoint, socket-backed host, and connection objects across the async connect lifecycle.")]
internal sealed class QuicClientConnectionHost : IAsyncDisposable
{
    private const int RouteConnectionIdLength = 8;
    private const ulong MinimumActiveConnectionIdLimit = 2;
    private const ulong TicksPerMicrosecond = (ulong)TimeSpan.TicksPerSecond / 1_000_000UL;

    private readonly QuicClientConnectionSettings settings;
    private readonly TaskCompletionSource<QuicConnection> establishedConnection = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly QuicConnectionRuntimeEndpoint endpoint;
    private readonly QuicConnectionRuntime runtime;
    private readonly QuicConnectionEndpointHost endpointHost;
    private readonly QuicConnection connection;
    private readonly QuicConnectionHandle handle;
    private readonly byte[] routeConnectionId;

    private int started;
    private int disposed;

    public QuicClientConnectionHost(QuicClientConnectionSettings settings)
    {
        this.settings = settings ?? throw new ArgumentNullException(nameof(settings));

        routeConnectionId = new byte[RouteConnectionIdLength];
        RandomNumberGenerator.Fill(routeConnectionId);

        Socket socket = CreateSocket(settings);

        IPEndPoint localEndPoint = (IPEndPoint)socket.LocalEndPoint!;
        IPEndPoint remoteEndPoint = (IPEndPoint)socket.RemoteEndPoint!;
        QuicConnectionPathIdentity pathIdentity = new(
            remoteEndPoint.Address.ToString(),
            localEndPoint.Address.ToString(),
            remoteEndPoint.Port,
            localEndPoint.Port);

        endpoint = new QuicConnectionRuntimeEndpoint(1);
        runtime = CreateRuntime(settings.Options);
        connection = new QuicConnection(runtime, settings.Options, this);
        handle = endpoint.AllocateConnectionHandle();

        if (!endpoint.TryRegisterConnection(handle, runtime)
            || !endpoint.TryRegisterConnectionId(handle, routeConnectionId)
            || !endpoint.TryUpdateEndpointBinding(handle, pathIdentity))
        {
            throw new InvalidOperationException("The client runtime shell could not register its connection state.");
        }

        endpointHost = new QuicConnectionEndpointHost(
            endpoint,
            socket,
            pathIdentity,
            transitionObserver: ObserveTransition);
    }

    public ValueTask<QuicConnection> ConnectAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        if (Interlocked.CompareExchange(ref started, 1, 0) != 0)
        {
            throw new InvalidOperationException("The client host can only be started once.");
        }

        Task runningTask = endpointHost.RunAsync();
        _ = ObserveCompletionAsync(runningTask);

        if (!endpoint.Host.TryPostEvent(
            handle,
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                runtime.Clock.Ticks,
                CreateLocalTransportParameters(settings.Options, routeConnectionId))))
        {
            throw new InvalidOperationException("The client runtime could not bootstrap the handshake.");
        }

        return AwaitConnectionAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        establishedConnection.TrySetException(new ObjectDisposedException(nameof(QuicClientConnectionHost)));

        try
        {
            await endpointHost.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            await endpoint.DisposeAsync().ConfigureAwait(false);
            await runtime.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask<QuicConnection> AwaitConnectionAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await establishedConnection.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task ObserveCompletionAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (Volatile.Read(ref disposed) != 0)
        {
            // Shutdown path owns the pending-connect outcome.
        }
        catch (Exception ex)
        {
            establishedConnection.TrySetException(MapRunFailure(ex));
        }
    }

    private void ObserveTransition(QuicConnectionTransitionResult transition)
    {
        if (runtime.TerminalState is QuicConnectionTerminalState terminalState)
        {
            establishedConnection.TrySetException(MapTerminalState(terminalState));
            return;
        }

        if (transition.CurrentPhase == QuicConnectionPhase.Active
            && runtime.PeerHandshakeTranscriptCompleted)
        {
            establishedConnection.TrySetResult(connection);
        }
    }

    private static Socket CreateSocket(QuicClientConnectionSettings settings)
    {
        Socket socket = new(settings.RemoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

        try
        {
            if (settings.LocalEndPoint is not null)
            {
                socket.Bind(settings.LocalEndPoint);
            }

            socket.Connect(settings.RemoteEndPoint);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static QuicConnectionRuntime CreateRuntime(QuicClientConnectionOptions options)
    {
        QuicReceiveWindowSizes receiveWindowSizes = options.InitialReceiveWindowSizes;
        QuicConnectionStreamState bookkeeping = new(new QuicConnectionStreamStateOptions(
            IsServer: false,
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

        return new QuicConnectionRuntime(
            bookkeeping,
            tlsRole: QuicTlsRole.Client,
            remoteCertificateValidationCallback: options.ClientAuthenticationOptions.RemoteCertificateValidationCallback);
    }

    private static QuicTransportParameters CreateLocalTransportParameters(
        QuicClientConnectionOptions options,
        ReadOnlySpan<byte> routeConnectionId)
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
            InitialSourceConnectionId = routeConnectionId.ToArray(),
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
                terminalState.Close.ReasonPhrase ?? "The client connection terminated during establishment.");
        }

        if (terminalState.Origin == QuicConnectionCloseOrigin.IdleTimeout)
        {
            return new QuicException(
                QuicError.ConnectionIdle,
                null,
                terminalState.Close.ReasonPhrase ?? "The client connection idled before establishment completed.");
        }

        long? applicationErrorCode = terminalState.Close.ApplicationErrorCode.HasValue
            ? checked((long)terminalState.Close.ApplicationErrorCode.Value)
            : null;

        return new QuicException(
            QuicError.ConnectionAborted,
            applicationErrorCode,
            terminalState.Close.ReasonPhrase ?? "The client connection terminated during establishment.");
    }

    private static Exception MapRunFailure(Exception exception)
    {
        if (exception is QuicException quicException)
        {
            return quicException;
        }

        return new QuicException(
            QuicError.InternalError,
            null,
            "The client connection runtime failed.",
            exception);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicClientConnectionHost));
        }
    }
}

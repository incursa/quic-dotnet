using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace Incursa.Quic;

[SuppressMessage("Performance", "S1450", Justification = "The client host must retain its runtime, endpoint, socket-backed host, and connection objects across the async connect lifecycle.")]
internal sealed class QuicClientConnectionHost : IAsyncDisposable
{
    private const int RouteConnectionIdLength = 8;
    private const ulong MinimumActiveConnectionIdLimit = 2;
    private const ulong TicksPerMicrosecond = (ulong)TimeSpan.TicksPerSecond / 1_000_000UL;
    private const int ReplayPacketValidationFailureMissingFieldsOrHeader = 1;
    private const int ReplayPacketValidationFailureTokenMismatch = 2;

    private readonly QuicClientConnectionSettings settings;
    private readonly TaskCompletionSource<QuicConnection> establishedConnection = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly QuicConnectionRuntimeEndpoint endpoint;
    private readonly QuicConnectionRuntime runtime;
    private readonly QuicConnectionEndpointHost endpointHost;
    private readonly QuicConnection connection;
    private readonly QuicConnectionHandle handle;
    private readonly byte[] initialDestinationConnectionId;
    private readonly byte[] routeConnectionId;

    public ConcurrentQueue<QuicConnectionTransitionResult> TransitionHistory { get; } = new();

    private int started;
    private int disposed;
    private int retryReceivedObserved;
    private int retryBootstrapReplayDatagramSent;
    private int retryBootstrapReplayPacketValidated;
    private int retryBootstrapReplayPacketValidationFailureCode;
    private byte[]? retrySourceConnectionIdFromRetry;
    private byte[]? retryTokenFromRetry;
    private string? retryTokenFromRetryHex;
    private string? retryBootstrapReplayPacketTokenHex;

    public QuicClientConnectionHost(QuicClientConnectionSettings settings)
    {
        this.settings = settings ?? throw new ArgumentNullException(nameof(settings));

        initialDestinationConnectionId = new byte[RouteConnectionIdLength];
        routeConnectionId = new byte[RouteConnectionIdLength];
        RandomNumberGenerator.Fill(initialDestinationConnectionId);
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
        runtime = CreateRuntime(settings);
        connection = new QuicConnection(runtime, settings.Options, this);
        handle = endpoint.AllocateConnectionHandle();

        if (!runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId)
            || !runtime.TrySetBootstrapOutboundPath(pathIdentity)
            || !runtime.TrySetHandshakeSourceConnectionId(routeConnectionId))
        {
            throw new InvalidOperationException("The client runtime could not configure its initial bootstrap state.");
        }

        if (!endpoint.TryRegisterConnection(handle, runtime)
            || !endpoint.TryRegisterConnectionId(handle, routeConnectionId)
            || !endpoint.TryUpdateEndpointBinding(handle, pathIdentity))
        {
            throw new InvalidOperationException("The client runtime shell could not register its connection state.");
        }

        runtime.SetLocalApiEventDispatcher(connectionEvent => endpoint.Host.TryPostEvent(handle, connectionEvent));

        endpointHost = new QuicConnectionEndpointHost(
            endpoint,
            socket,
            pathIdentity,
            transitionObserver: ObserveTransition,
            ingressDatagramObserver: ObserveIngressDatagram);
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

    internal bool RetryBootstrapReplayDatagramSent => Volatile.Read(ref retryBootstrapReplayDatagramSent) != 0;

    internal bool RetryBootstrapReplayPacketValidated => Volatile.Read(ref retryBootstrapReplayPacketValidated) != 0;

    internal int RetryBootstrapReplayPacketValidationFailureCode => Volatile.Read(ref retryBootstrapReplayPacketValidationFailureCode);

    internal string? RetryTokenFromRetryHex => retryTokenFromRetryHex;

    internal string? RetryBootstrapReplayPacketTokenHex => retryBootstrapReplayPacketTokenHex;

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
        TransitionHistory.Enqueue(transition);

        if (transition.EventKind == QuicConnectionEventKind.RetryReceived)
        {
            Interlocked.Exchange(ref retryReceivedObserved, 1);
            if (transition.HasEffects && transition.Effects.Any(effect =>
                effect is QuicConnectionSendDatagramEffect sendDatagramEffect
                && IsReplayInitialPacket(sendDatagramEffect.Datagram.Span)))
            {
                Interlocked.Exchange(ref retryBootstrapReplayDatagramSent, 1);
            }
        }

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

    private void ObserveIngressDatagram(ReadOnlyMemory<byte> datagram, QuicConnectionIngressResult ingressResult)
    {
        if (ingressResult.Disposition != QuicConnectionIngressDisposition.EndpointHandling
            || ingressResult.HandlingKind != QuicConnectionEndpointHandlingKind.Retry
            || !QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
                initialDestinationConnectionId,
                datagram.Span,
                out QuicRetryBootstrapMetadata retryMetadata))
        {
            return;
        }

        retrySourceConnectionIdFromRetry = retryMetadata.RetrySourceConnectionId.ToArray();
        retryTokenFromRetry = retryMetadata.RetryToken.ToArray();
        retryTokenFromRetryHex = Convert.ToHexString(retryMetadata.RetryToken);

        _ = endpoint.Host.TryPostEvent(
            handle,
            new QuicConnectionRetryReceivedEvent(
                runtime.Clock.Ticks,
                retryMetadata.RetrySourceConnectionId,
                retryMetadata.RetryToken));
    }

    private bool IsReplayInitialPacket(ReadOnlySpan<byte> datagram)
    {
        if (retrySourceConnectionIdFromRetry is null
            || retryTokenFromRetry is null
            || !QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket sentPacket)
            || sentPacket.Version != 1
            || sentPacket.LongPacketTypeBits != QuicLongPacketTypeBits.Initial
            || !sentPacket.DestinationConnectionId.SequenceEqual(retrySourceConnectionIdFromRetry)
            || !TryParseInitialRetryToken(sentPacket.VersionSpecificData, out byte[] replayToken))
        {
            Interlocked.Exchange(ref retryBootstrapReplayPacketValidationFailureCode, ReplayPacketValidationFailureMissingFieldsOrHeader);
            return false;
        }

        if (!replayToken.SequenceEqual(retryTokenFromRetry))
        {
            Interlocked.Exchange(ref retryBootstrapReplayPacketValidationFailureCode, ReplayPacketValidationFailureTokenMismatch);
            return false;
        }

        retryBootstrapReplayPacketTokenHex = Convert.ToHexString(replayToken);
        Interlocked.Exchange(ref retryBootstrapReplayPacketValidationFailureCode, 0);
        Interlocked.Exchange(ref retryBootstrapReplayPacketValidated, 1);
        return true;
    }

    private static bool TryParseInitialRetryToken(ReadOnlySpan<byte> versionSpecificData, out byte[] retryToken)
    {
        retryToken = [];

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes)
            || tokenLength > (ulong)(versionSpecificData.Length - tokenLengthBytes))
        {
            return false;
        }

        retryToken = versionSpecificData.Slice(tokenLengthBytes, (int)tokenLength).ToArray();
        return true;
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

    private static QuicConnectionRuntime CreateRuntime(QuicClientConnectionSettings settings)
    {
        QuicClientConnectionOptions options = settings.Options;
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
            clientCertificatePolicySnapshot: settings.ClientCertificatePolicySnapshot,
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

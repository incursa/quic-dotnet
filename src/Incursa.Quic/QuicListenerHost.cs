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
    private const int RetryBootstrapTokenLength = 16;
    private const ulong TicksPerMicrosecond = (ulong)TimeSpan.TicksPerSecond / 1_000_000UL;
    private const int RetryBootstrapReplayValidationFailureParseHeader = 2;
    private const int RetryBootstrapReplayValidationFailureVersionOrType = 3;
    private const int RetryBootstrapReplayValidationFailureDestinationConnectionIdMismatch = 4;
    private const int RetryBootstrapReplayValidationFailureTokenParse = 5;
    private const int RetryBootstrapReplayValidationFailureTokenMismatch = 6;
    private const int RetryBootstrapReplayValidationFailureOpen = 7;
    private const int RetryBootstrapReplayValidationFailurePayload = 8;

    private readonly Socket socket;
    private readonly CancellationTokenSource shutdown = new();
    private readonly Channel<object> acceptQueue;
    private readonly List<SslApplicationProtocol> applicationProtocols;
    private readonly Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> connectionOptionsCallback;
    private readonly Func<IQuicDiagnosticsSink>? diagnosticsSinkFactory;
    private readonly QuicConnectionRuntimeEndpoint endpoint;
    private readonly ConcurrentDictionary<QuicConnectionHandle, PendingConnectionState> connections = new();
    private readonly bool retryBootstrapEnabled;

    private CancellationTokenSource? listenerCancellationSource;
    private Task? runningTask;
    private int started;
    private int disposed;
    private int retryBootstrapIssued;
    private int retryBootstrapReplayValidated;
    private int retryBootstrapReplayAdmitted;
    private int retryBootstrapReplayValidationFailureCode;
    private byte[]? retryBootstrapOriginalDestinationConnectionId;
    private byte[]? retryBootstrapSourceConnectionId;
    private byte[]? retryBootstrapToken;
    private string? retryBootstrapTokenHex;
    private string? retryBootstrapReplayTokenHex;

    public QuicListenerHost(
        IPEndPoint listenEndPoint,
        List<SslApplicationProtocol> applicationProtocols,
        Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> connectionOptionsCallback,
        int listenBacklog,
        bool retryBootstrapEnabled = false,
        Func<IQuicDiagnosticsSink>? diagnosticsSinkFactory = null)
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
        this.retryBootstrapEnabled = retryBootstrapEnabled;
        this.diagnosticsSinkFactory = diagnosticsSinkFactory;
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

    internal bool RetryBootstrapIssued => Volatile.Read(ref retryBootstrapIssued) != 0;

    internal bool RetryBootstrapReplayValidated => Volatile.Read(ref retryBootstrapReplayValidated) != 0;

    internal bool RetryBootstrapReplayAdmitted => Volatile.Read(ref retryBootstrapReplayAdmitted) != 0;

    internal int RetryBootstrapReplayValidationFailureCode => Volatile.Read(ref retryBootstrapReplayValidationFailureCode);

    internal string? RetryBootstrapTokenHex => retryBootstrapTokenHex;

    internal string? RetryBootstrapReplayTokenHex => retryBootstrapReplayTokenHex;

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
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.ConnectionRefused)
                {
                    // Best-effort listener shell: peer resets during cancel/dispose are not actionable.
                    break;
                }

                if (receiveResult.ReceivedBytes <= 0)
                {
                    continue;
                }

                IPEndPoint receivedFrom = (IPEndPoint)receiveResult.RemoteEndPoint;
                QuicConnectionPathIdentity pathIdentity;
                try
                {
                    IPEndPoint localEndPoint = (IPEndPoint)socket.LocalEndPoint!;
                    pathIdentity = CreatePathIdentity(receivedFrom, localEndPoint);
                }
                catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
                {
                    break;
                }

                byte[] datagram = buffer.AsSpan(0, receiveResult.ReceivedBytes).ToArray();
                QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(datagram, pathIdentity);
                if (ingressResult.Disposition == QuicConnectionIngressDisposition.RoutedToConnection
                    || ingressResult.Disposition == QuicConnectionIngressDisposition.EndpointHandling)
                {
                    continue;
                }

                if (TryParseInitialDatagram(datagram, out _)
                    && datagram.Length < QuicVersionNegotiation.Version1MinimumDatagramPayloadSize)
                {
                    TrySendProtocolViolationCloseResponse(pathIdentity);
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

        state.TransitionHistory.Enqueue(transition);

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

    private void TrySendProtocolViolationCloseResponse(QuicConnectionPathIdentity pathIdentity)
    {
        byte[] closeDatagram = new byte[32];
        if (!QuicFrameCodec.TryFormatConnectionCloseFrame(
            new QuicConnectionCloseFrame(
                QuicTransportErrorCode.ProtocolViolation,
                triggeringFrameType: 0,
                []),
            closeDatagram,
            out int bytesWritten))
        {
            return;
        }

        SendDatagram(new QuicConnectionSendDatagramEffect(
            pathIdentity,
            closeDatagram.AsMemory(0, bytesWritten)));
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
            ReadOnlySpan<byte> protectionConnectionId = initialDestinationConnectionId;
            if (retryBootstrapEnabled
                && Volatile.Read(ref retryBootstrapIssued) != 0
                && retryBootstrapOriginalDestinationConnectionId is not null)
            {
                protectionConnectionId = retryBootstrapOriginalDestinationConnectionId;
            }

            if (!QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Server,
                protectionConnectionId,
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
                out int payloadLength))
            {
                if (retryBootstrapEnabled && Volatile.Read(ref retryBootstrapIssued) != 0)
                {
                    Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureOpen);
                }

                return false;
            }

            if (!TryValidateInitialCryptoPayload(openedPacket.AsSpan(payloadOffset, payloadLength)))
            {
                if (retryBootstrapEnabled && Volatile.Read(ref retryBootstrapIssued) != 0)
                {
                    Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailurePayload);
                }

                return false;
            }

            if (retryBootstrapEnabled)
            {
                if (Volatile.Read(ref retryBootstrapIssued) == 0)
                {
                    if (!TryIssueRetryBootstrapResponse(
                        pathIdentity,
                        initialDestinationConnectionId,
                        clientSourceConnectionId))
                    {
                        return false;
                    }

                    return false;
                }

                if (!TryValidateRetryBootstrapReplay(datagram.Span))
                {
                    return false;
                }

                Interlocked.Exchange(ref retryBootstrapReplayValidated, 1);
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

            runtime.SetLocalApiEventDispatcher(connectionEvent => endpoint.Host.TryPostEvent(handle, connectionEvent));

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
            connection.UpdateStreamCapacityCallback(selectedOptions.StreamCapacityCallback);

            ReadOnlySpan<byte> initialPacketProtectionConnectionId = retryBootstrapOriginalDestinationConnectionId is null
                ? initialDestinationConnectionId
                : retryBootstrapOriginalDestinationConnectionId;

            if (!runtime.TryConfigureInitialPacketProtection(initialPacketProtectionConnectionId)
                || !runtime.TrySetHandshakeDestinationConnectionId(clientSourceConnectionId)
                || !runtime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId)
                || !runtime.TryConfigureServerAuthenticationMaterial(
                    validatedOptions.ServerLeafCertificateDer,
                    validatedOptions.ServerLeafSigningPrivateKey,
                    selectedOptions.ServerAuthenticationOptions.ClientCertificateRequired,
                    selectedOptions.ServerAuthenticationOptions.CertificateChainPolicy,
                    selectedOptions.ServerAuthenticationOptions.CertificateRevocationCheckMode,
                    selectedOptions.ServerAuthenticationOptions.RemoteCertificateValidationCallback))
            {
                return false;
            }

            if (!endpoint.Host.TryPostEvent(
                handle,
                new QuicConnectionHandshakeBootstrapRequestedEvent(
                    runtime.Clock.Ticks,
                    CreateLocalTransportParameters(
                        selectedOptions,
                        serverSourceConnectionId,
                        retryBootstrapOriginalDestinationConnectionId is null
                            ? initialDestinationConnectionId
                            : retryBootstrapOriginalDestinationConnectionId,
                        retryBootstrapSourceConnectionId is null ? ReadOnlySpan<byte>.Empty : retryBootstrapSourceConnectionId))))
            {
                return false;
            }

            admitted = true;
            if (retryBootstrapEnabled && Volatile.Read(ref retryBootstrapIssued) != 0)
            {
                Interlocked.Exchange(ref retryBootstrapReplayAdmitted, 1);
            }
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

    internal static byte[] GenerateDistinctServerSourceConnectionId(ReadOnlySpan<byte> disallowedConnectionId)
    {
        byte[] connectionId;

        do
        {
            connectionId = GenerateServerSourceConnectionId();
        }
        while (connectionId.AsSpan().SequenceEqual(disallowedConnectionId));

        return connectionId;
    }

    private bool TryIssueRetryBootstrapResponse(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> clientSourceConnectionId)
    {
        if (Volatile.Read(ref retryBootstrapIssued) != 0)
        {
            return false;
        }

        byte[] retrySourceConnectionId = GenerateDistinctServerSourceConnectionId(originalDestinationConnectionId);
        byte[] retryToken = new byte[RetryBootstrapTokenLength];
        RandomNumberGenerator.Fill(retryToken);

        if (!QuicRetryIntegrity.TryBuildRetryPacket(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            retrySourceConnectionId,
            retryToken,
            out byte[] retryPacket))
        {
            return false;
        }

        try
        {
            EndPoint remoteEndPoint = new IPEndPoint(
                IPAddress.Parse(pathIdentity.RemoteAddress),
                pathIdentity.RemotePort ?? throw new InvalidOperationException("The listener connection path is missing a remote port."));

            int bytesSent = socket.SendTo(retryPacket.AsSpan(), SocketFlags.None, remoteEndPoint);
            if (bytesSent != retryPacket.Length)
            {
                return false;
            }
        }
        catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException) when (shutdown.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }

        retryBootstrapOriginalDestinationConnectionId = originalDestinationConnectionId.ToArray();
        retryBootstrapSourceConnectionId = retrySourceConnectionId;
        retryBootstrapToken = retryToken;
        retryBootstrapTokenHex = Convert.ToHexString(retryToken);
        Interlocked.Exchange(ref retryBootstrapIssued, 1);
        return true;
    }

    private bool TryValidateRetryBootstrapReplay(ReadOnlySpan<byte> datagram)
    {
        if (retryBootstrapOriginalDestinationConnectionId is null
            || retryBootstrapSourceConnectionId is null
            || retryBootstrapToken is null)
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, 1);
            return false;
        }

        if (!QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket retryHeader))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureParseHeader);
            return false;
        }

        if (retryHeader.Version != 1
            || retryHeader.LongPacketTypeBits != QuicLongPacketTypeBits.Initial)
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureVersionOrType);
            return false;
        }

        if (!retryHeader.DestinationConnectionId.SequenceEqual(retryBootstrapSourceConnectionId))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureDestinationConnectionIdMismatch);
            return false;
        }

        if (!TryParseInitialRetryToken(retryHeader.VersionSpecificData, out byte[] retryToken))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureTokenParse);
            return false;
        }

        retryBootstrapReplayTokenHex = Convert.ToHexString(retryToken);

        if (!retryToken.SequenceEqual(retryBootstrapToken))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureTokenMismatch);
            return false;
        }

        Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, 0);
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

    private static QuicTransportParameters CreateLocalTransportParameters(
        QuicServerConnectionOptions options,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> originalDestinationConnectionId = default,
        ReadOnlySpan<byte> retrySourceConnectionId = default)
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
            OriginalDestinationConnectionId = originalDestinationConnectionId.IsEmpty ? null : originalDestinationConnectionId.ToArray(),
            InitialSourceConnectionId = sourceConnectionId.ToArray(),
            RetrySourceConnectionId = retrySourceConnectionId.IsEmpty ? null : retrySourceConnectionId.ToArray(),
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

        if (terminalState.Origin == QuicConnectionCloseOrigin.VersionNegotiation)
        {
            return new QuicException(
                QuicError.VersionNegotiationError,
                null,
                terminalState.Close.ReasonPhrase ?? "The listener connection could not negotiate a compatible version.");
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

    private QuicConnectionRuntime CreateRuntime(QuicServerConnectionOptions options)
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
        IQuicDiagnosticsSink? diagnosticsSink = diagnosticsSinkFactory?.Invoke();

        return new QuicConnectionRuntime(
            bookkeeping,
            tlsRole: QuicTlsRole.Server,
            diagnosticsSink: QuicDiagnostics.ResolveConnectionSink(diagnosticsSink));
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

        public ConcurrentQueue<QuicConnectionTransitionResult> TransitionHistory { get; } = new();

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
        selectedOptions.StreamCapacityCallback = returnedOptions.StreamCapacityCallback;
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

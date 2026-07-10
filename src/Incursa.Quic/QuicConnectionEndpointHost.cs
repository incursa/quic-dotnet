// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Incursa.Quic;

// CONTEXT: The host owns the real socket boundary, and it may reopen the socket bound to the
// local endpoint so later ingress is not pinned to the original connected peer after migration.
// SEE: TryUpdateSocketBinding:
/// <summary>
/// Bridges one runtime-owned connection endpoint through a real UDP socket.
/// </summary>
internal sealed class QuicConnectionEndpointHost : IAsyncDisposable, IDisposable
{
    private static readonly bool EndpointIngressDebugEnabled =
        string.Equals(
            Environment.GetEnvironmentVariable("INCURSA_QUIC_DEBUG_APP_RX"),
            "1",
            StringComparison.Ordinal);

    private readonly QuicConnectionRuntimeEndpoint endpoint;
    private readonly Action<QuicConnectionIngressResult>? ingressObserver;
    private readonly Action<ReadOnlyMemory<byte>, QuicConnectionIngressResult>? ingressDatagramObserver;
    private readonly bool observeRoutedDatagrams;
    private readonly Action<QuicConnectionTransitionResult>? transitionObserver;
    private readonly Action<QuicConnectionEffect>? effectObserver;
    private readonly IQuicDiagnosticsSink diagnosticsSink;
    private readonly QuicReceiveBufferPool receiveBufferPool;
    private readonly object socketGate = new();
    private readonly CancellationTokenSource shutdown = new();
    private readonly uint flowLabelSeed;

    private Socket socket;
    private QuicConnectionPathIdentity peerPathIdentity;
    private QuicConnectionPathIdentity? cachedRemoteAddressPathIdentity;
    private IPEndPoint? cachedRemoteEndPoint;
    private SocketAddress? cachedRemoteSocketAddress;
    private Task? runningTask;
    private CancellationTokenSource? linkedCancellation;
    private CancellationTokenRegistration receiveLoopCancellationRegistration;
    private int disposed;

    public QuicConnectionEndpointHost(
        QuicConnectionRuntimeEndpoint endpoint,
        Socket socket,
        QuicConnectionPathIdentity peerPathIdentity,
        Action<QuicConnectionIngressResult>? ingressObserver = null,
        Action<QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionEffect>? effectObserver = null,
        int receiveBufferBytes = 4096,
        Action<ReadOnlyMemory<byte>, QuicConnectionIngressResult>? ingressDatagramObserver = null,
        bool observeRoutedDatagrams = true,
        IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(socket);
        QuicSocketFragmentationControl.TryEnableDontFragmentIfPossible(socket);

        if (receiveBufferBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(receiveBufferBytes));
        }

        this.endpoint = endpoint;
        this.socket = socket;
        this.peerPathIdentity = peerPathIdentity;
        this.ingressObserver = ingressObserver;
        this.ingressDatagramObserver = ingressDatagramObserver;
        this.observeRoutedDatagrams = observeRoutedDatagrams;
        this.transitionObserver = transitionObserver;
        this.effectObserver = effectObserver;
        this.diagnosticsSink = QuicDiagnostics.ResolveConnectionSink(diagnosticsSink);
        receiveBufferPool = new QuicReceiveBufferPool(
            receiveBufferBytes,
            ownerName: nameof(QuicConnectionEndpointHost),
            preallocateRingBuffers: true);
        flowLabelSeed = unchecked((uint)RandomNumberGenerator.GetInt32(1, int.MaxValue));

        // Keep the socket open to migrated source endpoints. Outbound effects still use the
        // current path identity, but ingress must not be pinned to the original connected peer.
        if (this.socket.LocalEndPoint is IPEndPoint localEndPoint)
        {
            Socket connectedSocket = this.socket;
            connectedSocket.Dispose();
            this.socket = CreateSocket(localEndPoint);
        }
    }

    /// <summary>
    /// Starts the endpoint host receive loop and runtime consumer.
    /// </summary>
    public Task RunAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (runningTask is not null)
        {
            throw new InvalidOperationException("The endpoint host can only be started once.");
        }

        linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);
        CancellationToken hostCancellation = linkedCancellation.Token;
        receiveLoopCancellationRegistration = hostCancellation.UnsafeRegister(
            static state => ((QuicConnectionEndpointHost)state!).WakeReceiveLoop(),
            this);

        Task runtimeTask = endpoint.RunAsync(
            (handle, shardIndex, transition) =>
            {
                _ = handle;
                _ = shardIndex;
                transitionObserver?.Invoke(transition);
            },
            (handle, shardIndex, effect) =>
            {
                _ = handle;
                _ = shardIndex;

                TryApplyEffect(effect);

                effectObserver?.Invoke(effect);
            },
            hostCancellation,
            (handle, shardIndex, update) =>
            {
                _ = handle;
                _ = shardIndex;
                TrySendDatagram(update);
                effectObserver?.Invoke(update.ToEffect());
            });

        Task receiveTask = ReceiveLoopAsync(hostCancellation);
        runningTask = Task.WhenAll(runtimeTask, receiveTask);
        return runningTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await shutdown.CancelAsync().ConfigureAwait(false);
        if (linkedCancellation is not null)
        {
            await linkedCancellation.CancelAsync().ConfigureAwait(false);
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

        await receiveLoopCancellationRegistration.DisposeAsync().ConfigureAwait(false);
        try
        {
            lock (socketGate)
            {
                socket.Dispose();
            }
        }
        catch
        {
            // Best-effort shutdown only.
        }

        linkedCancellation?.Dispose();
        receiveBufferPool.Dispose();
        shutdown.Dispose();
    }

    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    internal Socket Socket => socket;

    internal QuicConnectionPathIdentity PeerPathIdentity => peerPathIdentity;

    internal QuicReceiveBufferPoolSnapshot ReceiveBufferPoolSnapshot => receiveBufferPool.Snapshot;

    internal bool TryApplyEffect(QuicConnectionEffect effect)
    {
        ArgumentNullException.ThrowIfNull(effect);

        if (Volatile.Read(ref disposed) != 0 || shutdown.IsCancellationRequested)
        {
            return false;
        }

        return effect switch
        {
            QuicConnectionSendDatagramEffect sendDatagramEffect =>
                TrySendDatagram(sendDatagramEffect),
            QuicConnectionPromoteActivePathEffect promoteActivePathEffect =>
                TryUpdateSocketBinding(promoteActivePathEffect.PathIdentity),
            QuicConnectionUpdateEndpointBindingsEffect updateEndpointBindingsEffect =>
                TryUpdateSocketBinding(updateEndpointBindingsEffect.PathIdentity),
            _ => true,
        };
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        QuicSocketPacketInformationControl.LocalEndPointCache localEndPointCache = new();
        Socket? receiveSocket = null;
        QuicReusableReceiveEndPoint? remoteEndPoint = null;
        IPEndPoint? receiveLocalEndPoint = null;
        bool requiresPacketInformation = false;

        while (!cancellationToken.IsCancellationRequested)
        {
            GetSocketBinding(out Socket currentSocket);
            if (!ReferenceEquals(currentSocket, receiveSocket))
            {
                receiveSocket = currentSocket;
                remoteEndPoint = new QuicReusableReceiveEndPoint(currentSocket.AddressFamily);
                receiveLocalEndPoint = (IPEndPoint)currentSocket.LocalEndPoint!;
                requiresPacketInformation =
                    QuicSocketPacketInformationControl.RequiresPacketInformation(receiveLocalEndPoint);
            }

            QuicReceiveBufferLease datagramLease = receiveBufferPool.Rent();
            try
            {
                remoteEndPoint!.PrepareForReceive();
                SocketReceiveMessageFromResult receiveMessageResult = default;
                EndPoint receivedRemoteEndPoint;
                int receivedBytes;
                if (requiresPacketInformation)
                {
                    receiveMessageResult = await currentSocket.ReceiveMessageFromAsync(
                        datagramLease.Memory,
                        SocketFlags.None,
                        remoteEndPoint,
                        CancellationToken.None).ConfigureAwait(false);
                    receivedBytes = receiveMessageResult.ReceivedBytes;
                    receivedRemoteEndPoint = receiveMessageResult.RemoteEndPoint;
                }
                else
                {
                    SocketReceiveFromResult receiveFromResult = await currentSocket.ReceiveFromAsync(
                        datagramLease.Memory,
                        SocketFlags.None,
                        remoteEndPoint,
                        CancellationToken.None).ConfigureAwait(false);
                    receivedBytes = receiveFromResult.ReceivedBytes;
                    receivedRemoteEndPoint = receiveFromResult.RemoteEndPoint;
                }

                if (receivedBytes <= 0)
                {
                    continue;
                }

                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref disposed) != 0)
                {
                    break;
                }

                QuicMetrics.RecordDatagramReceived(QuicTlsRole.Client, receivedBytes);
                IPEndPoint receivedFrom = (IPEndPoint)receivedRemoteEndPoint;
                IPEndPoint localEndPoint = requiresPacketInformation
                    ? localEndPointCache.Resolve(
                        receiveLocalEndPoint!,
                        receiveMessageResult.PacketInformation.Address)
                    : receiveLocalEndPoint!;
                QuicConnectionPathIdentity currentPathIdentity = CreatePathIdentity(receivedFrom, localEndPoint);

                EmitSocketDatagramReceived(currentPathIdentity, receivedBytes);
                byte[] datagramBuffer = datagramLease.Buffer;
                ReadOnlyMemory<byte> datagram = datagramBuffer.AsMemory(0, receivedBytes);
                QuicEcnCounts? ecnCounts = requiresPacketInformation
                    && QuicSocketEcnControl.TryGetReceivedEcnCounts(
                        receiveMessageResult,
                        out QuicEcnCounts receivedEcnCounts)
                    ? receivedEcnCounts
                    : null;
                QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(
                    datagram,
                    currentPathIdentity,
                    ecnCounts,
                    ownedDatagramBuffer: datagramBuffer,
                    ownedDatagramBufferOwnership: datagramLease.Ownership);
                bool shouldInvokeDatagramObserver = ingressDatagramObserver is not null
                    && (observeRoutedDatagrams
                        || ingressResult.Disposition != QuicConnectionIngressDisposition.RoutedToConnection);
                ReadOnlyMemory<byte> observerDatagram = datagram;
                if (shouldInvokeDatagramObserver
                    && ingressResult.Disposition == QuicConnectionIngressDisposition.RoutedToConnection)
                {
                    observerDatagram = datagram.ToArray();
                }

                if (EndpointIngressDebugEnabled)
                {
                    await Console.Error.WriteLineAsync(
                        $"endpoint-rx len={receivedBytes} disposition={ingressResult.Disposition} handling={ingressResult.HandlingKind} routed={ingressResult.Handle.HasValue}.");
                }

                if (ingressResult.Disposition == QuicConnectionIngressDisposition.RoutedToConnection)
                {
                    datagramLease.TransferToRuntime();
                }
                else if (ingressResult.Disposition is not QuicConnectionIngressDisposition.EndpointHandling
                    and not QuicConnectionIngressDisposition.Dropped)
                {
                    SendStatelessResetResponse(currentSocket, datagram, currentPathIdentity);
                }
                else if (ingressResult.Disposition == QuicConnectionIngressDisposition.Dropped)
                {
                    QuicMetrics.RecordPacketDropped(QuicTlsRole.Client);
                }

                if (shouldInvokeDatagramObserver)
                {
                    ingressDatagramObserver?.Invoke(observerDatagram, ingressResult);
                }

                ingressObserver?.Invoke(ingressResult);
                continue;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested || Volatile.Read(ref disposed) != 0)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                continue;
            }
            catch (SocketException) when (cancellationToken.IsCancellationRequested || Volatile.Read(ref disposed) != 0)
            {
                break;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.ConnectionRefused)
            {
                EmitUdpReceiveError(ex);
                continue;
            }
            catch (SocketException ex)
            {
                EmitUdpReceiveError(ex);
                continue;
            }
            finally
            {
                datagramLease.Dispose();
            }
        }
    }

    private void EmitSocketDatagramReceived(QuicConnectionPathIdentity pathIdentity, int datagramLength)
    {
        if (!diagnosticsSink.IsEnabled)
        {
            return;
        }

        diagnosticsSink.Emit(QuicDiagnostics.SocketDatagramReceived(pathIdentity, datagramLength));
    }

    private void SendStatelessResetResponse(
        Socket socket,
        ReadOnlyMemory<byte> triggeringDatagram,
        QuicConnectionPathIdentity pathIdentity)
    {
        QuicConnectionStatelessResetEmissionResult reset = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringDatagram,
            pathIdentity,
            hasLoopPreventionState: true);

        if (!reset.Emitted)
        {
            return;
        }

        try
        {
            lock (socketGate)
            {
                _ = QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, QuicEcnMarking.NotEct);
                SocketAddress remoteSocketAddress = GetRemoteSocketAddress(pathIdentity);
                int bytesSent = socket.SendTo(reset.Datagram.Span, SocketFlags.None, remoteSocketAddress);
                if (bytesSent != reset.Datagram.Length)
                {
                    throw new IOException("Failed to send the complete QUIC Stateless Reset datagram.");
                }
            }
        }
        catch (ObjectDisposedException)
        {
            // Best-effort reset emission only.
        }
        catch (SocketException ex)
        {
            EmitUdpSendError(ex);
            // Best-effort reset emission only.
        }
        catch (IOException)
        {
            // Best-effort reset emission only.
        }
    }

    private bool TrySendDatagram(QuicConnectionSendDatagramEffect sendDatagramEffect)
        => TrySendDatagram(new QuicConnectionSendDatagramUpdate(
            sendDatagramEffect.PathIdentity,
            sendDatagramEffect.Datagram,
            sendDatagramEffect.EcnMarking));

    private bool TrySendDatagram(QuicConnectionSendDatagramUpdate sendDatagram)
    {
        try
        {
            lock (socketGate)
            {
                _ = QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, sendDatagram.EcnMarking);
                IPEndPoint localEndPoint = (IPEndPoint)socket.LocalEndPoint!;
                IPEndPoint remoteEndPoint = GetRemoteEndPoint(sendDatagram.PathIdentity);
                int bytesSent;
                if (TryResolvePacketInformationSourceAddress(
                    localEndPoint,
                    socket.AddressFamily,
                    sendDatagram.PathIdentity,
                    out IPAddress sourceAddress))
                {
                    bool usePacketInformationSender = socket.AddressFamily == AddressFamily.InterNetworkV6
                        || !sourceAddress.Equals(localEndPoint.Address);
                    uint flowLabel = sourceAddress.AddressFamily == AddressFamily.InterNetworkV6
                        ? QuicSocketPacketInformationSender.CreateIpv6FlowLabel(flowLabelSeed, sendDatagram.PathIdentity)
                        : 0;

                    if (!QuicSocketPacketInformationSender.TrySendTo(
                        socket,
                        sendDatagram.Datagram.Span,
                        remoteEndPoint,
                        sourceAddress,
                        flowLabel,
                        out bytesSent)
                        && usePacketInformationSender
                        && OperatingSystem.IsLinux())
                    {
                        return false;
                    }
                }
                else
                {
                    bytesSent = 0;
                }

                if (bytesSent == 0)
                {
                    bytesSent = socket.SendTo(
                        sendDatagram.Datagram.Span,
                        SocketFlags.None,
                        GetRemoteSocketAddress(sendDatagram.PathIdentity));
                }

                if (bytesSent != sendDatagram.Datagram.Length)
                {
                    throw new IOException("Failed to send the complete QUIC datagram.");
                }

                QuicMetrics.RecordDatagramSent(QuicTlsRole.Client, bytesSent);
            }

            return true;
        }
        catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
        {
            // Expected during shutdown.
        }
        catch (SocketException) when (shutdown.IsCancellationRequested)
        {
            // Expected during shutdown.
        }
        catch (SocketException ex)
        {
            EmitUdpSendError(ex);
        }

        return false;
    }

    private void EmitUdpReceiveError(SocketException exception)
    {
        QuicMetrics.RecordUdpError(QuicTlsRole.Client, "receive", exception.SocketErrorCode);

        if (!diagnosticsSink.IsEnabled)
        {
            return;
        }

        diagnosticsSink.Emit(QuicDiagnostics.UdpReceiveError(
            exception.SocketErrorCode.ToString(),
            exception.ErrorCode));
    }

    private void EmitUdpSendError(SocketException exception)
    {
        QuicMetrics.RecordUdpError(QuicTlsRole.Client, "send", exception.SocketErrorCode);

        if (!diagnosticsSink.IsEnabled)
        {
            return;
        }

        diagnosticsSink.Emit(QuicDiagnostics.UdpSendError(
            exception.SocketErrorCode.ToString(),
            exception.ErrorCode));
    }

    private bool TryUpdateSocketBinding(QuicConnectionPathIdentity pathIdentity)
    {
        if (Volatile.Read(ref disposed) != 0 || shutdown.IsCancellationRequested)
        {
            return false;
        }

        lock (socketGate)
        {
            if (Volatile.Read(ref disposed) != 0 || shutdown.IsCancellationRequested)
            {
                return false;
            }

            IPEndPoint currentLocalEndPoint = (IPEndPoint)socket.LocalEndPoint!;
            IPEndPoint? localEndPoint = CreateLocalEndPoint(pathIdentity, currentLocalEndPoint);

            if (PathIdentityEquals(peerPathIdentity, pathIdentity))
            {
                return true;
            }

            // Address-only promotions keep the existing bound socket alive so ingress does not
            // stall while the peer is still draining the original path. Rebind only when the
            // promoted path requires a different local port.
            if (localEndPoint is null || currentLocalEndPoint.Port == localEndPoint.Port)
            {
                peerPathIdentity = pathIdentity;
                return true;
            }

            Socket previousSocket = socket;
            socket = CreateSocket(localEndPoint);
            peerPathIdentity = pathIdentity;
            previousSocket.Dispose();
            return true;
        }
    }

    private void GetSocketBinding(out Socket currentSocket)
    {
        lock (socketGate)
        {
            currentSocket = socket;
        }
    }

    private void WakeReceiveLoop()
    {
        lock (socketGate)
        {
            if (QuicSocketReceiveLoopWakeup.TryWake(socket))
            {
                return;
            }

            try
            {
                socket.Dispose();
            }
            catch
            {
                // Falling back to socket disposal only needs to unblock the receive loop.
            }
        }
    }

    private static IPEndPoint CreateRemoteEndPoint(QuicConnectionPathIdentity pathIdentity)
    {
        return new IPEndPoint(
            IPAddress.Parse(pathIdentity.RemoteAddress),
            pathIdentity.RemotePort ?? throw new InvalidOperationException("The endpoint path is missing a remote port."));
    }

    private IPEndPoint GetRemoteEndPoint(QuicConnectionPathIdentity pathIdentity)
    {
        if (cachedRemoteEndPoint is not null
            && cachedRemoteAddressPathIdentity is QuicConnectionPathIdentity cachedPathIdentity
            && cachedPathIdentity.Equals(pathIdentity))
        {
            return cachedRemoteEndPoint;
        }

        IPEndPoint remoteEndPoint = CreateRemoteEndPoint(pathIdentity);
        cachedRemoteAddressPathIdentity = pathIdentity;
        cachedRemoteEndPoint = remoteEndPoint;
        cachedRemoteSocketAddress = null;
        return remoteEndPoint;
    }

    private SocketAddress GetRemoteSocketAddress(QuicConnectionPathIdentity pathIdentity)
    {
        if (cachedRemoteSocketAddress is not null
            && cachedRemoteAddressPathIdentity is QuicConnectionPathIdentity cachedPathIdentity
            && cachedPathIdentity.Equals(pathIdentity))
        {
            return cachedRemoteSocketAddress;
        }

        IPEndPoint remoteEndPoint = GetRemoteEndPoint(pathIdentity);
        SocketAddress socketAddress = remoteEndPoint.Serialize();
        cachedRemoteSocketAddress = socketAddress;
        return socketAddress;
    }

    private static QuicConnectionPathIdentity CreatePathIdentity(IPEndPoint remoteEndPoint, IPEndPoint localEndPoint)
    {
        return new QuicConnectionPathIdentity(
            QuicAddressFormatting.Format(remoteEndPoint.Address),
            QuicAddressFormatting.Format(localEndPoint.Address),
            remoteEndPoint.Port,
            localEndPoint.Port);
    }

    private static IPEndPoint? CreateLocalEndPoint(QuicConnectionPathIdentity pathIdentity, IPEndPoint fallback)
    {
        if (pathIdentity.LocalAddress is string localAddress && pathIdentity.LocalPort is int localPort)
        {
            return new IPEndPoint(IPAddress.Parse(localAddress), localPort);
        }

        return fallback;
    }

    internal static bool TryResolvePacketInformationSourceAddress(
        IPEndPoint socketLocalEndPoint,
        AddressFamily socketAddressFamily,
        QuicConnectionPathIdentity pathIdentity,
        out IPAddress sourceAddress)
    {
        ArgumentNullException.ThrowIfNull(socketLocalEndPoint);

        sourceAddress = IPAddress.None;
        if (!IsWildcardAddress(socketLocalEndPoint.Address)
            || pathIdentity.LocalAddress is not string localAddress
            || pathIdentity.LocalPort != socketLocalEndPoint.Port
            || !IPAddress.TryParse(localAddress, out IPAddress? parsedAddress)
            || IsWildcardAddress(parsedAddress))
        {
            return false;
        }

        if (socketAddressFamily == AddressFamily.InterNetworkV6
            && parsedAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            sourceAddress = parsedAddress;
            return true;
        }

        if (socketAddressFamily == AddressFamily.InterNetwork
            && parsedAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            sourceAddress = parsedAddress;
            return true;
        }

        return false;
    }

    private static bool IsWildcardAddress(IPAddress address)
    {
        return address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
    }

    private static bool PathIdentityEquals(QuicConnectionPathIdentity left, QuicConnectionPathIdentity right)
    {
        return string.Equals(left.RemoteAddress, right.RemoteAddress, StringComparison.Ordinal)
            && string.Equals(left.LocalAddress, right.LocalAddress, StringComparison.Ordinal)
            && left.RemotePort == right.RemotePort
            && left.LocalPort == right.LocalPort;
    }

    private static Socket CreateSocket(IPEndPoint localEndPoint)
    {
        Socket socket = new(localEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (socket.AddressFamily == AddressFamily.InterNetworkV6)
        {
            socket.DualMode = true;
        }

        QuicSocketFragmentationControl.TryEnableDontFragmentIfPossible(socket);
        QuicSocketPacketInformationControl.TryEnablePacketInformationIfPossible(socket);

        try
        {
            socket.Bind(localEndPoint);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionEndpointHost));
        }
    }
}

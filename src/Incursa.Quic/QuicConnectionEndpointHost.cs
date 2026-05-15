using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Bridges one runtime-owned connection endpoint through a real UDP socket.
/// </summary>
internal sealed class QuicConnectionEndpointHost : IAsyncDisposable, IDisposable
{
    private readonly QuicConnectionRuntimeEndpoint endpoint;
    private readonly Action<QuicConnectionIngressResult>? ingressObserver;
    private readonly Action<ReadOnlyMemory<byte>, QuicConnectionIngressResult>? ingressDatagramObserver;
    private readonly Action<QuicConnectionTransitionResult>? transitionObserver;
    private readonly Action<QuicConnectionEffect>? effectObserver;
    private readonly int receiveBufferBytes;
    private readonly object socketGate = new();
    private readonly CancellationTokenSource shutdown = new();
    private readonly uint flowLabelSeed;

    private Socket socket;
    private QuicConnectionPathIdentity peerPathIdentity;
    private Task? runningTask;
    private CancellationTokenSource? linkedCancellation;
    private int disposed;

    public QuicConnectionEndpointHost(
        QuicConnectionRuntimeEndpoint endpoint,
        Socket socket,
        QuicConnectionPathIdentity peerPathIdentity,
        Action<QuicConnectionIngressResult>? ingressObserver = null,
        Action<QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionEffect>? effectObserver = null,
        int receiveBufferBytes = 4096,
        Action<ReadOnlyMemory<byte>, QuicConnectionIngressResult>? ingressDatagramObserver = null)
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
        this.transitionObserver = transitionObserver;
        this.effectObserver = effectObserver;
        this.receiveBufferBytes = receiveBufferBytes;
        flowLabelSeed = unchecked((uint)RandomNumberGenerator.GetInt32(1, int.MaxValue));

        // Keep the socket open to migrated source endpoints. Outbound effects still use the
        // current path identity, but ingress must not be pinned to the original connected peer.
        IPEndPoint localEndPoint = (IPEndPoint)this.socket.LocalEndPoint!;
        Socket connectedSocket = this.socket;
        connectedSocket.Dispose();
        this.socket = CreateSocket(localEndPoint);
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
            hostCancellation);

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

        try
        {
            Socket socketToDispose;
            lock (socketGate)
            {
                socketToDispose = socket;
            }

            socketToDispose.Dispose();
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

        linkedCancellation?.Dispose();
        shutdown.Dispose();
    }

    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

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
        byte[] buffer = QuicBufferPool.RentBytes(receiveBufferBytes);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                GetSocketBinding(out Socket currentSocket);
                EndPoint remoteEndPoint = currentSocket.AddressFamily == AddressFamily.InterNetworkV6
                    ? new IPEndPoint(IPAddress.IPv6Any, 0)
                    : new IPEndPoint(IPAddress.Any, 0);

                try
                {
                    SocketReceiveMessageFromResult receiveResult = await currentSocket.ReceiveMessageFromAsync(
                        buffer.AsMemory(0, receiveBufferBytes),
                        SocketFlags.None,
                        remoteEndPoint,
                        cancellationToken).ConfigureAwait(false);

                    if (receiveResult.ReceivedBytes <= 0)
                    {
                        continue;
                    }

                    IPEndPoint receivedFrom = (IPEndPoint)receiveResult.RemoteEndPoint;
                    IPEndPoint localEndPoint = QuicSocketPacketInformationControl.ResolveLocalEndPoint(
                        (IPEndPoint)currentSocket.LocalEndPoint!,
                        receiveResult.PacketInformation.Address);
                    QuicConnectionPathIdentity currentPathIdentity = CreatePathIdentity(receivedFrom, localEndPoint);

                    byte[] datagram = buffer.AsSpan(0, receiveResult.ReceivedBytes).ToArray();
                    QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(datagram, currentPathIdentity);
                    if (ingressResult.Disposition is not QuicConnectionIngressDisposition.RoutedToConnection
                        and not QuicConnectionIngressDisposition.EndpointHandling
                        and not QuicConnectionIngressDisposition.Dropped)
                    {
                        SendStatelessResetResponse(currentSocket, datagram, currentPathIdentity);
                    }

                    ingressDatagramObserver?.Invoke(datagram, ingressResult);
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
                    continue;
                }
                catch (SocketException)
                {
                    continue;
                }
            }
        }
        finally
        {
            QuicBufferPool.ReturnBytes(buffer);
        }
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
                IPEndPoint remoteEndPoint = CreateRemoteEndPoint(pathIdentity);
                int bytesSent = socket.SendTo(reset.Datagram.Span, SocketFlags.None, remoteEndPoint);
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
        catch (SocketException)
        {
            // Best-effort reset emission only.
        }
        catch (IOException)
        {
            // Best-effort reset emission only.
        }
    }

    private bool TrySendDatagram(QuicConnectionSendDatagramEffect sendDatagramEffect)
    {
        try
        {
            lock (socketGate)
            {
                _ = QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, sendDatagramEffect.EcnMarking);
                IPEndPoint localEndPoint = (IPEndPoint)socket.LocalEndPoint!;
                IPEndPoint remoteEndPoint = CreateRemoteEndPoint(sendDatagramEffect.PathIdentity);
                int bytesSent;
                if (TryResolvePacketInformationSourceAddress(
                    localEndPoint,
                    socket.AddressFamily,
                    sendDatagramEffect.PathIdentity,
                    out IPAddress sourceAddress))
                {
                    bool usePacketInformationSender = socket.AddressFamily == AddressFamily.InterNetworkV6
                        || !sourceAddress.Equals(localEndPoint.Address);
                    uint flowLabel = sourceAddress.AddressFamily == AddressFamily.InterNetworkV6
                        ? QuicSocketPacketInformationSender.CreateIpv6FlowLabel(flowLabelSeed, sendDatagramEffect.PathIdentity)
                        : 0;

                    if (!QuicSocketPacketInformationSender.TrySendTo(
                        socket,
                        sendDatagramEffect.Datagram.Span,
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
                    bytesSent = socket.SendTo(sendDatagramEffect.Datagram.Span, SocketFlags.None, remoteEndPoint);
                }

                if (bytesSent != sendDatagramEffect.Datagram.Length)
                {
                    throw new IOException("Failed to send the complete QUIC datagram.");
                }
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

        return false;
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

    private static IPEndPoint CreateRemoteEndPoint(QuicConnectionPathIdentity pathIdentity)
    {
        return new IPEndPoint(
            IPAddress.Parse(pathIdentity.RemoteAddress),
            pathIdentity.RemotePort ?? throw new InvalidOperationException("The endpoint path is missing a remote port."));
    }

    private static QuicConnectionPathIdentity CreatePathIdentity(IPEndPoint remoteEndPoint, IPEndPoint localEndPoint)
    {
        return new QuicConnectionPathIdentity(
            remoteEndPoint.Address.ToString(),
            localEndPoint.Address.ToString(),
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

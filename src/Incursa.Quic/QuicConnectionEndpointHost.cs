using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic;

/// <summary>
/// Bridges one runtime-owned connection endpoint through a real connected UDP socket.
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
                GetSocketBinding(out Socket currentSocket, out QuicConnectionPathIdentity currentPathIdentity);

                int bytesReceived;
                try
                {
                    bytesReceived = await currentSocket.ReceiveAsync(
                        buffer.AsMemory(0, receiveBufferBytes),
                        SocketFlags.None,
                        cancellationToken).ConfigureAwait(false);
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
                catch (SocketException)
                {
                    continue;
                }

                if (bytesReceived <= 0)
                {
                    continue;
                }

                byte[] datagram = buffer.AsSpan(0, bytesReceived).ToArray();
                QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(datagram, currentPathIdentity);
                if (ingressResult.Disposition is not QuicConnectionIngressDisposition.RoutedToConnection
                    and not QuicConnectionIngressDisposition.EndpointHandling
                    and not QuicConnectionIngressDisposition.Dropped)
                {
                    SendStatelessResetResponse(currentSocket, datagram, currentPathIdentity);
                }

                ingressDatagramObserver?.Invoke(datagram, ingressResult);
                ingressObserver?.Invoke(ingressResult);
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
                int bytesSent = socket.Send(reset.Datagram.Span, SocketFlags.None);
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
                int bytesSent = socket.Send(sendDatagramEffect.Datagram.Span, SocketFlags.None);
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
            IPEndPoint currentRemoteEndPoint = (IPEndPoint)socket.RemoteEndPoint!;
            IPEndPoint remoteEndPoint = CreateRemoteEndPoint(pathIdentity, currentRemoteEndPoint);
            IPEndPoint? localEndPoint = CreateLocalEndPoint(pathIdentity, currentLocalEndPoint);

            if (PathIdentityEquals(peerPathIdentity, pathIdentity))
            {
                return true;
            }

            if (localEndPoint is null || AreEndPointsEqual(currentLocalEndPoint, localEndPoint))
            {
                socket.Connect(remoteEndPoint);
                peerPathIdentity = pathIdentity;
                return true;
            }

            Socket previousSocket = socket;
            socket = CreateSocket(remoteEndPoint, localEndPoint);
            peerPathIdentity = pathIdentity;
            previousSocket.Dispose();
            return true;
        }
    }

    private void GetSocketBinding(out Socket currentSocket, out QuicConnectionPathIdentity currentPathIdentity)
    {
        lock (socketGate)
        {
            currentSocket = socket;
            currentPathIdentity = peerPathIdentity;
        }
    }

    private static IPEndPoint CreateRemoteEndPoint(QuicConnectionPathIdentity pathIdentity, IPEndPoint fallback)
    {
        if (pathIdentity.RemotePort is int remotePort)
        {
            return new IPEndPoint(IPAddress.Parse(pathIdentity.RemoteAddress), remotePort);
        }

        return fallback;
    }

    private static IPEndPoint? CreateLocalEndPoint(QuicConnectionPathIdentity pathIdentity, IPEndPoint fallback)
    {
        if (pathIdentity.LocalAddress is string localAddress && pathIdentity.LocalPort is int localPort)
        {
            return new IPEndPoint(IPAddress.Parse(localAddress), localPort);
        }

        return fallback;
    }

    private static bool PathIdentityEquals(QuicConnectionPathIdentity left, QuicConnectionPathIdentity right)
    {
        return string.Equals(left.RemoteAddress, right.RemoteAddress, StringComparison.Ordinal)
            && string.Equals(left.LocalAddress, right.LocalAddress, StringComparison.Ordinal)
            && left.RemotePort == right.RemotePort
            && left.LocalPort == right.LocalPort;
    }

    private static bool AreEndPointsEqual(IPEndPoint left, IPEndPoint right)
    {
        return left.Address.Equals(right.Address) && left.Port == right.Port;
    }

    private static Socket CreateSocket(IPEndPoint remoteEndPoint, IPEndPoint? localEndPoint = null)
    {
        Socket socket = new(remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        QuicSocketFragmentationControl.TryEnableDontFragmentIfPossible(socket);

        try
        {
            if (localEndPoint is not null)
            {
                socket.Bind(localEndPoint);
            }

            socket.Connect(remoteEndPoint);
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

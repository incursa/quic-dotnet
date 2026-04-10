using System.Buffers;
using System.Net.Sockets;

namespace Incursa.Quic;

/// <summary>
/// Bridges one runtime-owned connection endpoint through a real connected UDP socket.
/// </summary>
internal sealed class QuicConnectionEndpointHost : IAsyncDisposable, IDisposable
{
    private readonly QuicConnectionRuntimeEndpoint endpoint;
    private readonly Socket socket;
    private readonly QuicConnectionPathIdentity peerPathIdentity;
    private readonly Action<QuicConnectionIngressResult>? ingressObserver;
    private readonly Action<QuicConnectionTransitionResult>? transitionObserver;
    private readonly Action<QuicConnectionEffect>? effectObserver;
    private readonly int receiveBufferBytes;
    private readonly CancellationTokenSource shutdown = new();

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
        int receiveBufferBytes = 4096)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(socket);

        if (receiveBufferBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(receiveBufferBytes));
        }

        this.endpoint = endpoint;
        this.socket = socket;
        this.peerPathIdentity = peerPathIdentity;
        this.ingressObserver = ingressObserver;
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

                if (effect is QuicConnectionSendDatagramEffect sendDatagramEffect)
                {
                    SendDatagram(sendDatagramEffect);
                }

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
            socket.Dispose();
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

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(receiveBufferBytes);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int bytesReceived;
                try
                {
                    bytesReceived = await socket.ReceiveAsync(
                        buffer.AsMemory(0, receiveBufferBytes),
                        SocketFlags.None,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                if (bytesReceived <= 0)
                {
                    continue;
                }

                byte[] datagram = buffer.AsSpan(0, bytesReceived).ToArray();
                QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(datagram, peerPathIdentity);
                ingressObserver?.Invoke(ingressResult);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void SendDatagram(QuicConnectionSendDatagramEffect sendDatagramEffect)
    {
        try
        {
            int bytesSent = socket.Send(sendDatagramEffect.Datagram.Span, SocketFlags.None);
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

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionEndpointHost));
        }
    }
}

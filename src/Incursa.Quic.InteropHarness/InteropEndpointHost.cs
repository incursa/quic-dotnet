using Incursa.Quic;
using System.Net.Sockets;

namespace Incursa.Quic.InteropHarness;

/// <summary>
/// Thin harness-owned shell that composes the library-owned endpoint host.
/// </summary>
internal sealed class InteropEndpointHost : IAsyncDisposable, IDisposable
{
    private readonly QuicConnectionEndpointHost host;

    public InteropEndpointHost(
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

        host = new QuicConnectionEndpointHost(
            endpoint,
            socket,
            peerPathIdentity,
            ingressObserver,
            transitionObserver,
            effectObserver,
            receiveBufferBytes);
    }

    public Task RunAsync(CancellationToken cancellationToken = default)
    {
        return host.RunAsync(cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        return host.DisposeAsync();
    }

    public void Dispose()
    {
        host.Dispose();
    }
}

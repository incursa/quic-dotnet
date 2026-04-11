using System.Net.Security;

namespace Incursa.Quic;

/// <summary>
/// Consumer-facing listener facade over the internal runtime shell.
/// </summary>
public sealed class QuicListener : IAsyncDisposable
{
    private readonly QuicListenerHost host;
    private int disposed;

    private QuicListener(QuicListenerHost host)
    {
        this.host = host ?? throw new ArgumentNullException(nameof(host));
    }

    /// <summary>
    /// Creates and starts a listener.
    /// </summary>
    public static ValueTask<QuicListener> ListenAsync(QuicListenerOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate(nameof(options));
        cancellationToken.ThrowIfCancellationRequested();

        QuicListenerHost host = new(
            options.ListenEndPoint,
            options.ApplicationProtocols,
            options.ConnectionOptionsCallback,
            options.ListenBacklog);

        try
        {
            host.RunAsync(cancellationToken);
            return ValueTask.FromResult(new QuicListener(host));
        }
        catch
        {
            host.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Accepts the next connection handed to the listener shell.
    /// </summary>
    public ValueTask<QuicConnection> AcceptConnectionAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return host.AcceptConnectionAsync(cancellationToken);
    }

    /// <summary>
    /// Disposes the listener.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await host.DisposeAsync().ConfigureAwait(false);
    }

    internal ValueTask<QuicConnection> EnqueueIncomingConnectionAsync(
        SslClientHelloInfo clientHello,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return host.EnqueueIncomingConnectionAsync(clientHello, cancellationToken);
    }
}

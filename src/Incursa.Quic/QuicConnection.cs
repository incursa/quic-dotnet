using System.Threading;

namespace Incursa.Quic;

/// <summary>
/// Consumer-facing connection facade over the internal runtime.
/// </summary>
public sealed class QuicConnection : IAsyncDisposable
{
    private const long MaximumErrorCodeValue = (1L << 62) - 1;

    private readonly QuicConnectionRuntime runtime;
    private readonly QuicConnectionOptions options;
    private readonly IAsyncDisposable? lifetimeOwner;
    private int disposed;

    internal QuicConnection(QuicConnectionRuntime runtime, QuicConnectionOptions options, IAsyncDisposable? lifetimeOwner = null)
    {
        this.runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.lifetimeOwner = lifetimeOwner;
    }

    /// <summary>
    /// Creates and starts a client-side connection shell and completes only when the supported establishment boundary is reached.
    /// </summary>
    public static ValueTask<QuicConnection> ConnectAsync(QuicClientConnectionOptions options, CancellationToken cancellationToken = default)
    {
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(options, nameof(options));
        cancellationToken.ThrowIfCancellationRequested();
        return new QuicClientConnectionHost(settings).ConnectAsync(cancellationToken);
    }

    /// <summary>
    /// Closes the connection with the provided application error code.
    /// </summary>
    public ValueTask CloseAsync(long errorCode, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ValidateErrorCode(errorCode);
        cancellationToken.ThrowIfCancellationRequested();

        if (runtime.TerminalState is not null)
        {
            return ValueTask.CompletedTask;
        }

        runtime.Transition(new QuicConnectionLocalCloseRequestedEvent(
            runtime.Clock.Ticks,
            new QuicConnectionCloseMetadata(
                TransportErrorCode: null,
                ApplicationErrorCode: (ulong)errorCode,
                TriggeringFrameType: null,
                ReasonPhrase: null)));

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Disposes the connection.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        if (runtime.TerminalState is null && options.DefaultCloseErrorCode >= 0)
        {
            ValidateErrorCode(options.DefaultCloseErrorCode);
            runtime.Transition(new QuicConnectionLocalCloseRequestedEvent(
                runtime.Clock.Ticks,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: null,
                    ApplicationErrorCode: (ulong)options.DefaultCloseErrorCode,
                    TriggeringFrameType: null,
                    ReasonPhrase: null)));
        }

        if (lifetimeOwner is not null)
        {
            await lifetimeOwner.DisposeAsync().ConfigureAwait(false);
            return;
        }

        await runtime.DisposeAsync().ConfigureAwait(false);
    }

    private static void ValidateErrorCode(long errorCode)
    {
        if (errorCode < 0 || errorCode > MaximumErrorCodeValue)
        {
            throw new ArgumentOutOfRangeException(nameof(errorCode));
        }
    }
}

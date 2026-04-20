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
    private Action<QuicConnection, QuicStreamCapacityChangedArgs>? streamCapacityCallback;
    private int disposed;

    internal QuicConnection(QuicConnectionRuntime runtime, QuicConnectionOptions options, IAsyncDisposable? lifetimeOwner = null)
    {
        this.runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.lifetimeOwner = lifetimeOwner;
        streamCapacityCallback = options.StreamCapacityCallback;
        runtime.SetStreamCapacityObserver(OnRuntimeStreamCapacityIncreased);
    }

    /// <summary>
    /// Gets whether the current runtime supports the repository's managed QUIC loopback slice.
    /// </summary>
    public static bool IsSupported => QuicRuntimeSupport.IsSupported;

    /// <summary>
    /// Creates and starts a client-side connection shell and completes only when the supported establishment boundary is reached.
    /// </summary>
    public static ValueTask<QuicConnection> ConnectAsync(QuicClientConnectionOptions options, CancellationToken cancellationToken = default)
    {
        return ConnectAsync(
            options,
            detachedResumptionTicketSnapshot: null,
            cancellationToken: cancellationToken,
            diagnosticsSink: null);
    }

    internal static ValueTask<QuicConnection> ConnectAsync(
        QuicClientConnectionOptions options,
        QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot,
        CancellationToken cancellationToken = default,
        IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            options,
            nameof(options),
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);
        cancellationToken.ThrowIfCancellationRequested();
        return new QuicClientConnectionHost(
            settings,
            diagnosticsSink is null ? null : () => diagnosticsSink).ConnectAsync(cancellationToken);
    }

    /// <summary>
    /// Accepts the next inbound stream exposed by the supported active connection path.
    /// </summary>
    public ValueTask<QuicStream> AcceptInboundStreamAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return runtime.AcceptInboundStreamAsync(cancellationToken);
    }

    /// <summary>
    /// Opens a new outbound stream on the supported active connection path.
    /// </summary>
    public ValueTask<QuicStream> OpenOutboundStreamAsync(QuicStreamType streamType, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return runtime.OpenOutboundStreamAsync(streamType, cancellationToken);
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
            await runtime.DisposeAsync().ConfigureAwait(false);
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

    internal void UpdateStreamCapacityCallback(Action<QuicConnection, QuicStreamCapacityChangedArgs>? callback)
    {
        streamCapacityCallback = callback;
    }

    private async void OnRuntimeStreamCapacityIncreased(int bidirectionalIncrement, int unidirectionalIncrement)
    {
        Action<QuicConnection, QuicStreamCapacityChangedArgs>? callback = streamCapacityCallback;
        if (callback is null || (bidirectionalIncrement == 0 && unidirectionalIncrement == 0))
        {
            return;
        }

        await Task.Yield();

        if (Volatile.Read(ref disposed) != 0)
        {
            return;
        }

        try
        {
            callback(
                this,
                new QuicStreamCapacityChangedArgs
                {
                    BidirectionalIncrement = bidirectionalIncrement,
                    UnidirectionalIncrement = unidirectionalIncrement,
                });
        }
        catch
        {
            // Callback failures remain local to the consumer callback boundary.
        }
    }
}

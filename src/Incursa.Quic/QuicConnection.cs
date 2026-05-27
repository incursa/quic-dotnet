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

    internal QuicConnectionRuntime Runtime => runtime;

    /// <summary>
    /// Gets whether the current runtime supports the repository's managed QUIC loopback slice.
    /// </summary>
    public static bool IsSupported => QuicRuntimeSupport.IsSupported;

    /// <summary>
    /// Creates and starts a client-side connection shell and completes only when the supported establishment boundary is reached.
    /// </summary>
    /// <remarks>
    /// This public entry point does not expose application 0-RTT. Applications that later enable early data must
    /// define replay-safe request semantics before sending application bytes before handshake completion.
    /// </remarks>
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
        IQuicDiagnosticsSink? diagnosticsSink = null,
        ReadOnlyMemory<byte> localHandshakePrivateKey = default,
        QuicClientAddressValidationToken? addressValidationToken = null,
        bool allowClientPeerInitialReplacementBeforeTranscript = false,
        Action<QuicTlsKeyLogSecret>? tlsKeyLogSecretObserver = null,
        uint[]? supportedVersions = null)
    {
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            options,
            nameof(options),
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot,
            localHandshakePrivateKey: localHandshakePrivateKey,
            addressValidationToken: addressValidationToken,
            supportedVersions: supportedVersions) with
        {
            AllowClientPeerInitialReplacementBeforeTranscript = allowClientPeerInitialReplacementBeforeTranscript,
        };
        cancellationToken.ThrowIfCancellationRequested();
        return new QuicClientConnectionHost(
            settings,
            diagnosticsSink is null ? null : () => diagnosticsSink,
            tlsKeyLogSecretObserver).ConnectAsync(cancellationToken);
    }

    /// <summary>
    /// Accepts the next inbound stream exposed by the supported active connection path.
    /// </summary>
    /// <remarks>
    /// QUIC streams are ordered, reliable byte streams. Application protocols are responsible for mapping
    /// control streams, request streams, and any higher-level message boundaries onto accepted streams.
    /// </remarks>
    public ValueTask<QuicStream> AcceptInboundStreamAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return runtime.AcceptInboundStreamAsync(cancellationToken);
    }

    /// <summary>
    /// Opens a new outbound stream on the supported active connection path.
    /// </summary>
    /// <remarks>
    /// Stream opening is subject to the peer's stream limits. Use <see cref="QuicConnectionOptions.StreamCapacityCallback"/>
    /// for application backpressure instead of assuming immediate stream availability.
    /// </remarks>
    public ValueTask<QuicStream> OpenOutboundStreamAsync(QuicStreamType streamType, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return runtime.OpenOutboundStreamAsync(streamType, cancellationToken);
    }

    /// <summary>
    /// Sends one unreliable QUIC DATAGRAM payload on the supported active connection path.
    /// </summary>
    /// <remarks>
    /// This is the RFC 9221 QUIC DATAGRAM transport surface. It is not HTTP Datagrams, CONNECT-UDP, or MASQUE.
    /// </remarks>
    public ValueTask SendDatagramAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return runtime.SendDatagramAsync(datagram, cancellationToken);
    }

    /// <summary>
    /// Receives one unreliable QUIC DATAGRAM payload from the supported active connection path.
    /// </summary>
    /// <remarks>
    /// Application protocols are responsible for any datagram payload format, loss tolerance, and multiplexing policy.
    /// </remarks>
    public ValueTask<ReadOnlyMemory<byte>> ReceiveDatagramAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return runtime.ReceiveDatagramAsync(cancellationToken);
    }

    internal bool TryInitiateOneRttKeyUpdate()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return runtime.TryInitiateOneRttKeyUpdate();
    }

    internal bool HasObservedOneRttKeyUpdate
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            return runtime.HasObservedOneRttKeyUpdate;
        }
    }

    internal bool TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return runtime.TryExportDetachedResumptionTicketSnapshot(out detachedResumptionTicketSnapshot);
    }

    internal QuicTlsResumptionAttemptDisposition ResumptionAttemptDisposition
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            return runtime.ResumptionAttemptDisposition;
        }
    }

    /// <summary>
    /// Closes the connection with the provided application error code.
    /// </summary>
    /// <remarks>
    /// The error code is delivered as application close metadata. It is intended for the protocol layered over QUIC
    /// and is distinct from QUIC transport error codes.
    /// </remarks>
    public ValueTask CloseAsync(long errorCode, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ValidateErrorCode(errorCode);
        cancellationToken.ThrowIfCancellationRequested();

        if (runtime.TerminalState is not null)
        {
            return ValueTask.CompletedTask;
        }

        QuicConnectionLocalCloseRequestedEvent closeEvent = new(
            runtime.Clock.Ticks,
            new QuicConnectionCloseMetadata(
                TransportErrorCode: null,
                ApplicationErrorCode: (ulong)errorCode,
                TriggeringFrameType: null,
                ReasonPhrase: null));

        runtime.ProjectLocalCloseRequested(closeEvent, runtime.Clock.Ticks);
        _ = runtime.TryPostLocalApiEvent(closeEvent);

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
            QuicConnectionLocalCloseRequestedEvent closeEvent = new(
                runtime.Clock.Ticks,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: null,
                    ApplicationErrorCode: (ulong)options.DefaultCloseErrorCode,
                    TriggeringFrameType: null,
                    ReasonPhrase: null));

            runtime.ProjectLocalCloseRequested(closeEvent, runtime.Clock.Ticks);
            _ = runtime.TryPostLocalApiEvent(closeEvent);
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

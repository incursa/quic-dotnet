namespace Incursa.Quic.Dns;

/// <summary>
/// Minimal DNS over QUIC server adapter.
/// </summary>
public sealed class DoqServer : IAsyncDisposable
{
    private readonly QuicListener listener;
    private readonly IDoqQueryHandler handler;
    private readonly DoqServerOptions options;
    private readonly List<Task> connectionTasks = [];
    private int disposed;

    private DoqServer(QuicListener listener, IDoqQueryHandler handler, DoqServerOptions? options)
    {
        this.listener = listener ?? throw new ArgumentNullException(nameof(listener));
        this.handler = handler ?? throw new ArgumentNullException(nameof(handler));
        this.options = options ?? new DoqServerOptions();
    }

    /// <summary>
    /// Starts a QUIC listener configured for DNS over QUIC.
    /// </summary>
    public static async ValueTask<DoqServer> ListenAsync(
        QuicListenerOptions options,
        IDoqQueryHandler handler,
        CancellationToken cancellationToken = default)
        => await ListenAsync(options, handler, serverOptions: null, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Starts a QUIC listener configured for DNS over QUIC.
    /// </summary>
    public static async ValueTask<DoqServer> ListenAsync(
        QuicListenerOptions options,
        IDoqQueryHandler handler,
        DoqServerOptions? serverOptions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handler);
        DoqDefaults.EnsureListenerOptions(options);
        QuicListener listener = await QuicListener.ListenAsync(options, cancellationToken).ConfigureAwait(false);
        return new DoqServer(listener, handler, serverOptions);
    }

    /// <summary>
    /// Attaches the DoQ server adapter to an existing QUIC listener.
    /// </summary>
    public static DoqServer Attach(QuicListener listener, IDoqQueryHandler handler)
        => Attach(listener, handler, serverOptions: null);

    /// <summary>
    /// Attaches the DoQ server adapter to an existing QUIC listener.
    /// </summary>
    public static DoqServer Attach(QuicListener listener, IDoqQueryHandler handler, DoqServerOptions? serverOptions)
        => new(listener, handler, serverOptions);

    /// <summary>
    /// Accepts connections and dispatches inbound DoQ query streams until cancellation or disposal.
    /// </summary>
    public async Task ServeAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

        while (!cancellationToken.IsCancellationRequested)
        {
            QuicConnection connection;
            try
            {
                connection = await listener.AcceptConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException) when (Volatile.Read(ref disposed) != 0)
            {
                break;
            }

            Task connectionTask = HandleConnectionAsync(connection, cancellationToken);
            lock (connectionTasks)
            {
                connectionTasks.Add(connectionTask);
            }
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await listener.DisposeAsync().ConfigureAwait(false);

        Task[] tasks;
        lock (connectionTasks)
        {
            tasks = [.. connectionTasks];
        }

        if (tasks.Length != 0)
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
    }

    private async Task HandleConnectionAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        List<Task> streamTasks = [];
        ConnectionResourceState resourceState = new(options);
        using CancellationTokenSource connectionCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        CancellationToken connectionToken = connectionCancellation.Token;
        await using (connection.ConfigureAwait(false))
        {
            while (!connectionToken.IsCancellationRequested)
            {
                QuicStream stream;
                try
                {
                    stream = await connection.AcceptInboundStreamAsync(connectionToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (connectionToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (QuicException)
                {
                    break;
                }

                if (stream.Type != QuicStreamType.Bidirectional)
                {
                    await CloseConnectionAsync(connection, DoqErrorCode.ProtocolError, CancellationToken.None).ConfigureAwait(false);
                    await Task.Yield();
                    await connectionCancellation.CancelAsync().ConfigureAwait(false);
                    await stream.DisposeAsync().ConfigureAwait(false);
                    break;
                }

                if (!resourceState.TryRegisterDanglingStream())
                {
                    await CloseConnectionAsync(connection, DoqErrorCode.ExcessiveLoad, CancellationToken.None).ConfigureAwait(false);
                    await connectionCancellation.CancelAsync().ConfigureAwait(false);
                    await stream.DisposeAsync().ConfigureAwait(false);
                    break;
                }

                streamTasks.Add(HandleQueryStreamAsync(connection, stream, resourceState, connectionCancellation));
            }
        }

        if (streamTasks.Count != 0)
        {
            await Task.WhenAll(streamTasks).ConfigureAwait(false);
        }
    }

    private async Task HandleQueryStreamAsync(
        QuicConnection connection,
        QuicStream stream,
        ConnectionResourceState resourceState,
        CancellationTokenSource connectionCancellation)
    {
        CancellationToken cancellationToken = connectionCancellation.Token;
        await using (stream.ConfigureAwait(false))
        {
            try
            {
                DoqMessage query = await DoqStream.ReadSingleMessageUntilFinAsync(stream, cancellationToken).ConfigureAwait(false);
                ValidateZeroMessageId(query.Payload.Span, "query");
                DoqQueryResult result = await handler
                    .HandleAsync(new DoqQueryContext(stream.Id, query.Payload), cancellationToken)
                    .ConfigureAwait(false);
                await DoqStream.WriteMessageAndCompleteAsync(stream, result.Response, cancellationToken).ConfigureAwait(false);
            }
            catch (DoqException exception)
            {
                AbortStreamWrite(stream, exception.ErrorCode);

                if (exception.ErrorCode == DoqErrorCode.ProtocolError)
                {
                    await CloseConnectionAsync(connection, DoqErrorCode.ProtocolError, CancellationToken.None).ConfigureAwait(false);
                    await Task.Yield();
                    await connectionCancellation.CancelAsync().ConfigureAwait(false);
                }
            }
            catch (QuicException exception) when (exception.QuicError is QuicError.StreamAborted or QuicError.OperationAborted)
            {
                if (!resourceState.TryRegisterCancellation())
                {
                    await CloseConnectionAsync(connection, DoqErrorCode.ExcessiveLoad, CancellationToken.None).ConfigureAwait(false);
                    await connectionCancellation.CancelAsync().ConfigureAwait(false);
                }

                AbortStreamWrite(stream, DoqErrorCode.RequestCancelled);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                AbortStreamWrite(stream, DoqErrorCode.InternalError);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                SuppressExpectedAbortException(new OperationCanceledException(cancellationToken));
            }
            finally
            {
                resourceState.ReleaseDanglingStream();
            }
        }
    }

    private static async ValueTask CloseConnectionAsync(
        QuicConnection connection,
        DoqErrorCode errorCode,
        CancellationToken cancellationToken)
    {
        try
        {
            await connection.CloseAsync((long)errorCode, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ObjectDisposedException or QuicException)
        {
            SuppressExpectedAbortException(exception);
        }
    }

    private static void AbortStreamWrite(QuicStream stream, DoqErrorCode errorCode)
    {
        try
        {
            stream.Abort(QuicAbortDirection.Write, (long)errorCode);
        }
        catch (Exception exception) when (exception is InvalidOperationException or NotSupportedException or QuicException)
        {
            SuppressExpectedAbortException(exception);
        }
    }

    private static void SuppressExpectedAbortException(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
    }

    private static void ValidateZeroMessageId(ReadOnlySpan<byte> dnsMessage, string messageKind)
    {
        if (dnsMessage.Length < 2)
        {
            throw new DoqException(
                DoqErrorCode.ProtocolError,
                $"The DoQ {messageKind} did not contain the two-octet DNS Message ID field.");
        }

        if (dnsMessage[0] != 0 || dnsMessage[1] != 0)
        {
            throw new DoqException(
                DoqErrorCode.ProtocolError,
                $"The DoQ {messageKind} contained a non-zero DNS Message ID.");
        }
    }

    private sealed class ConnectionResourceState
    {
        private readonly DoqServerOptions options;
        private int danglingStreams;
        private int cancellationRequests;

        public ConnectionResourceState(DoqServerOptions options)
        {
            this.options = options;
        }

        public bool TryRegisterDanglingStream()
        {
            int count = Interlocked.Increment(ref danglingStreams);
            return options.MaxDanglingStreams == 0 || count <= options.MaxDanglingStreams;
        }

        public void ReleaseDanglingStream()
        {
            Interlocked.Decrement(ref danglingStreams);
        }

        public bool TryRegisterCancellation()
        {
            int count = Interlocked.Increment(ref cancellationRequests);
            return options.MaxCancellationRequests == 0 || count <= options.MaxCancellationRequests;
        }
    }
}

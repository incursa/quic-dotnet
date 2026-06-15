// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Dns;

/// <summary>
/// Minimal DNS over QUIC client adapter.
/// </summary>
public sealed class DoqClient : IAsyncDisposable
{
    private const string QueryConnectionFailedMessage = "The DoQ connection failed while a query was in progress.";

    private readonly SemaphoreSlim connectionGate = new(1, 1);
    private readonly bool ownsConnection;
    private readonly QuicClientConnectionOptions? reconnectOptions;
    private readonly string? endpoint;
    private QuicConnection connection;
    private TimeSpan? advertisedIdleTimeout;
    private CancellationTokenSource? inboundMonitorCts;
    private Task? inboundMonitorTask;
    private CancellationTokenSource connectionFailureCts = new();
    private int disposed;
    private int unsolicitedResetCount;
    private long lastActivityTicks;
    private int activeQueryCount;

    /// <summary>
    /// Gets or sets the maximum number of unsolicited RESET_STREAM frames tolerated
    /// on the connection before it is closed. A value of zero (the default) closes the
    /// connection immediately on any unsolicited RESET_STREAM, preserving backward
    /// compatibility with earlier slices.
    /// </summary>
    public int MaxUnsolicitedResets { get; set; }

    /// <summary>
    /// Gets or sets the identity of the local network connectivity used for this connection.
    /// When set, the client compares this value before reusing the connection for a new query.
    /// A mismatch causes <see cref="QueryAsync"/> to throw <see cref="DoqException"/>
    /// so the caller can establish a fresh connection.
    /// Set to a string that describes the local network interface (e.g. the local IP address
    /// or a network interface name).
    /// </summary>
    public string? ConnectivityId { get; set; }

    /// <summary>
    /// Gets or sets the connectivity identity from when the connection was first established.
    /// If <see cref="ConnectivityId"/> differs from this value, the connection is considered
    /// to have experienced a connectivity change.
    /// </summary>
    public string? PriorConnectivityId { get; set; }

    /// <summary>
    /// Gets a value indicating whether a resumption ticket has already been used on this client.
    /// Per RFC 9250 section 5.5.3, clients SHOULD use resumption tickets only once.
    /// This property is set by the caller or by future transport integration.
    /// </summary>
    public bool IsTicketUsed { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether address validation tokens should only be used
    /// together with session resumption. Defaults to <c>true</c>.
    /// </summary>
    public bool UseAddressValidationWithResumptionOnly { get; set; } = true;

    /// <summary>
    /// Gets or sets the DoQ usage profile. <see cref="DoqClientProfile.Strict"/> (default)
    /// fails hard on DoQ errors. <see cref="DoqClientProfile.Opportunistic"/> records
    /// failures and backs off from repeated DoQ attempts.
    /// </summary>
    public DoqClientProfile Profile { get; set; }

    /// <summary>
    /// Gets or sets the fallback cache used by Opportunistic profile to track DoQ failures.
    /// If null, a default cache with a 5-minute backoff is created lazily.
    /// </summary>
    public DoqFallbackCache? FallbackCache { get; set; }

    /// <summary>
    /// Gets the set of endpoints that are key-pinned. For key-pinned endpoints,
    /// the backoff period is shortened (1 minute instead of the configured period).
    /// </summary>
    public HashSet<string> KeyPinnedEndpoints { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the margin used to decide whether the connection is too close to its idle
    /// timeout to be safely reused for a new query. When the idle time exceeds
    /// (advertised idle timeout - margin), QueryAsync throws <see cref="DoqException"/>
    /// instead of reusing the connection.
    /// A value of <see cref="TimeSpan.Zero"/> disables the check.
    /// </summary>
    public TimeSpan IdleTimeoutMargin { get; set; } = DoqDefaults.DefaultIdleTimeoutMargin;

    internal QuicConnection CurrentConnection => connection;

    private DoqClient(
        QuicConnection connection,
        bool ownsConnection,
        TimeSpan? advertisedIdleTimeout = null,
        string? endpoint = null,
        QuicClientConnectionOptions? reconnectOptions = null)
    {
        this.connection = connection ?? throw new ArgumentNullException(nameof(connection));
        this.ownsConnection = ownsConnection;
        this.advertisedIdleTimeout = advertisedIdleTimeout;
        this.endpoint = endpoint;
        this.reconnectOptions = reconnectOptions;
        lastActivityTicks = Stopwatch.GetTimestamp();
    }

    /// <summary>
    /// Opens a QUIC connection configured for DNS over QUIC.
    /// </summary>
    public static async ValueTask<DoqClient> ConnectAsync(
        QuicClientConnectionOptions options,
        CancellationToken cancellationToken = default)
    {
        DoqDefaults.EnsureClientConnectionOptions(options);
        DoqDefaults.EnsureIdleTimeout(options);
        TimeSpan advertisedTimeout = options.IdleTimeout;
        string? endpoint = options.RemoteEndPoint?.ToString();
        QuicConnection connection = await QuicConnection.ConnectAsync(options, cancellationToken).ConfigureAwait(false);
        DoqClient client = new(connection, ownsConnection: true, advertisedTimeout, endpoint, options);
        client.StartInboundStreamMonitor();
        return client;
    }

    /// <summary>
    /// Attaches the DoQ adapter to an established QUIC connection.
    /// </summary>
    public static DoqClient Attach(QuicConnection connection)
        => new(connection, ownsConnection: false);

    /// <summary>
    /// Returns a value indicating whether an address validation token may be used for
    /// a connection attempt with the given session-resumption state.
    /// </summary>
    public bool CanUseAddressValidationToken(bool usingSessionResumption)
        => !UseAddressValidationWithResumptionOnly || usingSessionResumption;

    /// <summary>
    /// Gets or sets the maximum time to wait for the server STREAM FIN after the response payload has been received.
    /// A value of null disables the timeout and waits indefinitely.
    /// </summary>
    public TimeSpan? StreamFinTimeout { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the client may use QUIC 0-RTT for
    /// replayable transactions (OPCODE 0 = QUERY, 4 = NOTIFY).
    /// When <c>true</c>, non-replayable opcodes are rejected before sending.
    /// Defaults to <c>false</c>.
    /// </summary>
    public bool AllowZeroRtt { get; set; }

    /// <summary>
    /// Sends one DNS query on a fresh client-initiated bidirectional stream and reads the response from the same stream.
    /// </summary>
    public async ValueTask<DoqQueryResult> QueryAsync(
        ReadOnlyMemory<byte> query,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

        QuicConnection activeConnection = await EnsureConnectionSafeOrReconnectAsync(cancellationToken).ConfigureAwait(false);

        if (AllowZeroRtt && !DoqDefaults.IsReplayableQuery(query.Span))
        {
            throw new DoqException(
                DoqErrorCode.InternalError,
                "A non-replayable DNS transaction (OPCODE) cannot be sent using 0-RTT.");
        }

        if (IsTicketUsed)
        {
            throw new DoqException(
                DoqErrorCode.InternalError,
                "The resumption ticket has already been used. Create a new DoqClient to obtain a fresh ticket.");
        }

        if (ConnectivityId is not null && PriorConnectivityId is not null &&
            !string.Equals(ConnectivityId, PriorConnectivityId, StringComparison.Ordinal))
        {
            throw new DoqException(
                DoqErrorCode.InternalError,
                "Connectivity has changed since the connection was established. Create a new DoqClient.");
        }

        if (Profile == DoqClientProfile.Opportunistic)
        {
            EnsureNotBackedOff();
        }

        CancellationTokenSource activeConnectionFailureCts = connectionFailureCts;
        ThrowIfConnectionFailed(activeConnectionFailureCts, this);
        using CancellationTokenSource queryCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            activeConnectionFailureCts.Token);
        CancellationToken queryCancellationToken = queryCts.Token;

        await using QuicStream stream = await activeConnection
            .OpenOutboundStreamAsync(QuicStreamType.Bidirectional, queryCancellationToken)
            .ConfigureAwait(false);

        Interlocked.Increment(ref activeQueryCount);
        try
        {
            byte[] outboundQuery = NormalizeQueryMessageId(query);
            outboundQuery = DoqPadding.PadMessage(outboundQuery, DoqDefaults.PaddingBlockSize);
            await DoqStream.WriteMessageAndCompleteAsync(stream, outboundQuery, queryCancellationToken).ConfigureAwait(false);

            ValueTask<DoqMessage> readTask = DoqStream.ReadSingleMessageUntilFinAsync(stream, queryCancellationToken);
            DoqMessage response = await ReadResponseOrConnectionFailureAsync(
                activeConnection,
                readTask,
                StreamFinTimeout,
                queryCancellationToken).ConfigureAwait(false);

            ValidateZeroMessageId(response.Payload.Span, "response");
            lastActivityTicks = Stopwatch.GetTimestamp();
            return new DoqQueryResult(response.Payload);
        }
        catch (TimeoutException) when (StreamFinTimeout.HasValue)
        {
            await CloseConnectionAsync(activeConnection, DoqErrorCode.ProtocolError, CancellationToken.None).ConfigureAwait(false);
            throw new DoqException(
                DoqErrorCode.ProtocolError,
                "The DoQ server did not signal STREAM FIN within the configured timeout after the response payload was received.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            AbortStreamRead(stream, DoqErrorCode.RequestCancelled);
            throw;
        }
        catch (OperationCanceledException) when (activeConnectionFailureCts.IsCancellationRequested)
        {
            throw new DoqException(
                DoqErrorCode.InternalError,
                QueryConnectionFailedMessage);
        }
        catch (QuicException exception) when (exception.QuicError is QuicError.StreamAborted or QuicError.OperationAborted)
        {
            int count = Interlocked.Increment(ref unsolicitedResetCount);
            if (MaxUnsolicitedResets == 0 || count > MaxUnsolicitedResets)
            {
                await CloseConnectionAsync(activeConnection, DoqErrorCode.ProtocolError, CancellationToken.None).ConfigureAwait(false);
            }

            throw new DoqException(DoqErrorCode.ProtocolError, "The DoQ response stream was aborted by the peer.");
        }
        catch (DoqException exception) when (exception.ErrorCode == DoqErrorCode.ProtocolError)
        {
            await CloseConnectionAsync(activeConnection, DoqErrorCode.ProtocolError, cancellationToken).ConfigureAwait(false);
            throw;
        }
        finally
        {
            Interlocked.Decrement(ref activeQueryCount);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await connectionGate.WaitAsync().ConfigureAwait(false);
        try
        {
            QuicConnection currentConnection = connection;
            if (ownsConnection && Volatile.Read(ref activeQueryCount) > 0)
            {
                SignalConnectionFailure();
                await AttemptNoErrorCloseAsync(currentConnection).ConfigureAwait(false);
            }

            await StopInboundStreamMonitorAsync().ConfigureAwait(false);

            if (ownsConnection)
            {
                await currentConnection.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            connectionGate.Release();
        }
    }

    /// <summary>
    /// Starts monitoring for inbound server-initiated streams and treats any as a fatal protocol error.
    /// </summary>
    public void StartInboundStreamMonitor()
    {
        if (inboundMonitorCts is not null)
        {
            return;
        }

        inboundMonitorCts = new CancellationTokenSource();
        QuicConnection monitoredConnection = connection;
        inboundMonitorTask = Task.Run(() => MonitorInboundStreamsAsync(monitoredConnection, inboundMonitorCts.Token));
    }

    private async ValueTask<QuicConnection> EnsureConnectionSafeOrReconnectAsync(CancellationToken cancellationToken)
    {
        if (!IsTooCloseToIdleTimeout())
        {
            return connection;
        }

        if (!ownsConnection || reconnectOptions is not { } options)
        {
            ThrowConnectionTooCloseToIdleTimeout();
            throw new InvalidOperationException("The DoQ idle-time reconnect guard did not throw.");
        }

        await connectionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

            if (!IsTooCloseToIdleTimeout())
            {
                return connection;
            }

            QuicConnection oldConnection = connection;
            await StopInboundStreamMonitorAsync().ConfigureAwait(false);
            await oldConnection.DisposeAsync().ConfigureAwait(false);

            QuicConnection newConnection = await QuicConnection.ConnectAsync(options, cancellationToken).ConfigureAwait(false);
            connection = newConnection;
            advertisedIdleTimeout = options.IdleTimeout;
            CancellationTokenSource previousFailureCts = connectionFailureCts;
            connectionFailureCts = new CancellationTokenSource();
            previousFailureCts.Dispose();
            Volatile.Write(ref lastActivityTicks, Stopwatch.GetTimestamp());
            Interlocked.Exchange(ref unsolicitedResetCount, 0);
            StartInboundStreamMonitor();
            return newConnection;
        }
        finally
        {
            connectionGate.Release();
        }
    }

    private bool IsTooCloseToIdleTimeout()
    {
        if (IdleTimeoutMargin <= TimeSpan.Zero)
        {
            return false;
        }

        if (!advertisedIdleTimeout.HasValue || advertisedIdleTimeout.Value <= TimeSpan.Zero)
        {
            return false;
        }

        long elapsedTicks = Stopwatch.GetTimestamp() - Volatile.Read(ref lastActivityTicks);
        TimeSpan elapsed = TimeSpan.FromTicks(elapsedTicks * TimeSpan.TicksPerSecond / Stopwatch.Frequency);
        TimeSpan remaining = advertisedIdleTimeout.Value - elapsed;

        return remaining <= IdleTimeoutMargin;
    }

    private void ThrowConnectionTooCloseToIdleTimeout()
    {
        TimeSpan remaining = TimeSpan.Zero;
        if (advertisedIdleTimeout.HasValue && advertisedIdleTimeout.Value > TimeSpan.Zero)
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - Volatile.Read(ref lastActivityTicks);
            TimeSpan elapsed = TimeSpan.FromTicks(elapsedTicks * TimeSpan.TicksPerSecond / Stopwatch.Frequency);
            remaining = advertisedIdleTimeout.Value - elapsed;
        }

        throw new DoqException(
            DoqErrorCode.InternalError,
            $"The DoQ connection is too close to its idle timeout ({remaining.TotalMilliseconds:F0}ms remaining, margin {IdleTimeoutMargin.TotalMilliseconds:F0}ms), and this client cannot establish a replacement connection.");
    }

    private void EnsureNotBackedOff()
    {
        if (string.IsNullOrEmpty(endpoint) || FallbackCache is null)
        {
            return;
        }

        TimeSpan remaining = FallbackCache.GetRemainingBackoff(endpoint);
        if (remaining <= TimeSpan.Zero)
        {
            return;
        }

        if (KeyPinnedEndpoints.Contains(endpoint))
        {
            TimeSpan shortBackoff = TimeSpan.FromMinutes(1);
            if (remaining <= shortBackoff)
            {
                return;
            }
        }

        throw new DoqException(
            DoqErrorCode.InternalError,
            $"DoQ is temporarily backed off for {endpoint}. Remaining backoff: {remaining.TotalSeconds:F0}s.");
    }

    private async ValueTask AttemptNoErrorCloseAsync(QuicConnection targetConnection)
    {
        try
        {
            await targetConnection.CloseAsync((long)DoqErrorCode.NoError, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ObjectDisposedException or QuicException)
        {
            SuppressExpectedAbortException(exception);
        }
    }

    private static byte[] NormalizeQueryMessageId(ReadOnlyMemory<byte> query)
    {
        if (query.Length < 2)
        {
            throw new ArgumentException("A DNS query must contain at least the two-octet Message ID field.", nameof(query));
        }

        byte[] normalized = query.ToArray();
        normalized[0] = 0;
        normalized[1] = 0;
        return normalized;
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

    private async ValueTask CloseConnectionAsync(QuicConnection targetConnection, DoqErrorCode errorCode, CancellationToken cancellationToken)
    {
        if (ReferenceEquals(targetConnection, connection))
        {
            SignalConnectionFailure();
        }

        try
        {
            await targetConnection.CloseAsync((long)errorCode, cancellationToken).ConfigureAwait(false);
            await targetConnection.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ObjectDisposedException or QuicException)
        {
            SuppressExpectedAbortException(exception);
        }
    }

    private async ValueTask<DoqMessage> ReadResponseOrConnectionFailureAsync(
        QuicConnection activeConnection,
        ValueTask<DoqMessage> readTask,
        TimeSpan? streamFinTimeout,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource terminalWaitCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task<DoqMessage> responseTask = readTask.AsTask();
        Task connectionFailureTask = WaitForConnectionFailureStateAsync(
            activeConnection,
            terminalWaitCts.Token);
        Task delayTask = streamFinTimeout.HasValue
            ? Task.Delay(streamFinTimeout.Value, terminalWaitCts.Token)
            : Task.Delay(Timeout.InfiniteTimeSpan, terminalWaitCts.Token);

        Task completedTask = await Task
            .WhenAny(responseTask, connectionFailureTask, delayTask)
            .ConfigureAwait(false);

        if (completedTask == connectionFailureTask)
        {
            await connectionFailureTask.ConfigureAwait(false);
            SignalConnectionFailure();
            throw new DoqException(
                DoqErrorCode.InternalError,
                QueryConnectionFailedMessage);
        }

        if (completedTask == delayTask)
        {
            await delayTask.ConfigureAwait(false);
            throw new TimeoutException();
        }

        try
        {
            return await responseTask.ConfigureAwait(false);
        }
        catch (QuicException exception) when (exception.QuicError == QuicError.ConnectionAborted)
        {
            SignalConnectionFailure();
            throw new DoqException(
                DoqErrorCode.InternalError,
                QueryConnectionFailedMessage,
                exception);
        }
        finally
        {
            await terminalWaitCts.CancelAsync().ConfigureAwait(false);
        }
    }

    private async Task MonitorInboundStreamsAsync(QuicConnection monitoredConnection, CancellationToken cancellationToken)
    {
        try
        {
            Task<QuicStream> acceptInboundStreamTask = monitoredConnection
                .AcceptInboundStreamAsync(cancellationToken)
                .AsTask();
            Task connectionFailureTask = WaitForConnectionFailureStateAsync(
                monitoredConnection,
                cancellationToken);

            Task completedTask = await Task
                .WhenAny(acceptInboundStreamTask, connectionFailureTask)
                .ConfigureAwait(false);
            if (completedTask == connectionFailureTask)
            {
                await connectionFailureTask.ConfigureAwait(false);
                SignalConnectionFailure();
                return;
            }

            QuicStream inboundStream = await acceptInboundStreamTask.ConfigureAwait(false);

            await CloseConnectionAsync(monitoredConnection, DoqErrorCode.ProtocolError, CancellationToken.None).ConfigureAwait(false);
            await inboundStream.DisposeAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
        {
            SuppressExpectedAbortException(exception);
        }
        catch (ObjectDisposedException exception)
        {
            SuppressExpectedAbortException(exception);
        }
        catch (QuicException exception)
        {
            SuppressExpectedAbortException(exception);
        }
    }

    private async ValueTask StopInboundStreamMonitorAsync()
    {
        if (inboundMonitorCts is not null)
        {
            await inboundMonitorCts.CancelAsync().ConfigureAwait(false);
        }

        if (inboundMonitorTask is not null)
        {
            try
            {
                await inboundMonitorTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException exception)
            {
                SuppressExpectedAbortException(exception);
            }
        }

        inboundMonitorCts?.Dispose();
        inboundMonitorCts = null;
        inboundMonitorTask = null;
    }

    private static async Task WaitForConnectionFailureStateAsync(
        QuicConnection monitoredConnection,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (monitoredConnection.Runtime.IsDisposed
                || monitoredConnection.Runtime.TerminalState is not null
                || monitoredConnection.Runtime.Phase is QuicConnectionPhase.Closing
                    or QuicConnectionPhase.Draining
                    or QuicConnectionPhase.Discarded)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken).ConfigureAwait(false);
        }
    }

    private void SignalConnectionFailure()
    {
        try
        {
            connectionFailureCts.Cancel();
        }
        catch (ObjectDisposedException exception)
        {
            SuppressExpectedAbortException(exception);
        }
    }

    private static void ThrowIfConnectionFailed(CancellationTokenSource failureCts, DoqClient client)
    {
        ObjectDisposedException.ThrowIf(failureCts.IsCancellationRequested, client);
    }

    private static void AbortStreamRead(QuicStream stream, DoqErrorCode errorCode)
    {
        try
        {
            stream.Abort(QuicAbortDirection.Read, (long)errorCode);
        }
        catch (Exception exception) when (exception is InvalidOperationException or NotSupportedException)
        {
            SuppressExpectedAbortException(exception);
        }
    }

    private static void SuppressExpectedAbortException(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
    }
}

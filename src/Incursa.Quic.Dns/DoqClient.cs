namespace Incursa.Quic.Dns;

/// <summary>
/// Minimal DNS over QUIC client adapter.
/// </summary>
public sealed class DoqClient : IAsyncDisposable
{
    private readonly QuicConnection connection;
    private readonly bool ownsConnection;
    private int disposed;

    private DoqClient(QuicConnection connection, bool ownsConnection)
    {
        this.connection = connection ?? throw new ArgumentNullException(nameof(connection));
        this.ownsConnection = ownsConnection;
    }

    /// <summary>
    /// Opens a QUIC connection configured for DNS over QUIC.
    /// </summary>
    public static async ValueTask<DoqClient> ConnectAsync(
        QuicClientConnectionOptions options,
        CancellationToken cancellationToken = default)
    {
        DoqDefaults.EnsureClientConnectionOptions(options);
        QuicConnection connection = await QuicConnection.ConnectAsync(options, cancellationToken).ConfigureAwait(false);
        return new DoqClient(connection, ownsConnection: true);
    }

    /// <summary>
    /// Attaches the DoQ adapter to an established QUIC connection.
    /// </summary>
    public static DoqClient Attach(QuicConnection connection)
        => new(connection, ownsConnection: false);

    /// <summary>
    /// Sends one DNS query on a fresh client-initiated bidirectional stream and reads the response from the same stream.
    /// </summary>
    public async ValueTask<DoqQueryResult> QueryAsync(
        ReadOnlyMemory<byte> query,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

        await using QuicStream stream = await connection
            .OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken)
            .ConfigureAwait(false);

        try
        {
            byte[] outboundQuery = NormalizeQueryMessageId(query);
            await DoqStream.WriteMessageAndCompleteAsync(stream, outboundQuery, cancellationToken).ConfigureAwait(false);
            DoqMessage response = await DoqStream.ReadSingleMessageUntilFinAsync(stream, cancellationToken).ConfigureAwait(false);
            ValidateZeroMessageId(response.Payload.Span, "response");
            return new DoqQueryResult(response.Payload);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            AbortStreamRead(stream, DoqErrorCode.RequestCancelled);
            throw;
        }
        catch (DoqException exception) when (exception.ErrorCode == DoqErrorCode.ProtocolError)
        {
            await CloseConnectionAsync(DoqErrorCode.ProtocolError, cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        if (ownsConnection)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
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

    private async ValueTask CloseConnectionAsync(DoqErrorCode errorCode, CancellationToken cancellationToken)
    {
        try
        {
            await connection.CloseAsync((long)errorCode, cancellationToken).ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ObjectDisposedException or QuicException)
        {
            SuppressExpectedAbortException(exception);
        }
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

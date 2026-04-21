using Incursa.Quic;
using Incursa.Qlog;
using Incursa.Qlog.Serialization.Json;

namespace Incursa.Quic.Qlog;

/// <summary>
/// Captures qlog output for a caller that opts into host-facing collection above the transport core.
/// </summary>
public sealed class QuicQlogCapture
{
    private readonly object gate = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="QuicQlogCapture"/> class.
    /// </summary>
    /// <param name="title">Optional file title for the captured qlog envelope.</param>
    /// <param name="description">Optional file description for the captured qlog envelope.</param>
    public QuicQlogCapture(string? title = null, string? description = null)
    {
        File = new QlogFile
        {
            Title = title,
            Description = description,
        };
    }

    /// <summary>
    /// Gets the captured qlog file envelope.
    /// </summary>
    public QlogFile File { get; }

    /// <summary>
    /// Gets a value indicating whether the capture has at least one trace component.
    /// </summary>
    public bool HasTraces
    {
        get
        {
            lock (gate)
            {
                return File.Traces.Count > 0;
            }
        }
    }

    /// <summary>
    /// Connects a client using a connection-scoped qlog capture sink.
    /// </summary>
    public ValueTask<QuicConnection> ConnectAsync(
        QuicClientConnectionOptions options,
        CancellationToken cancellationToken = default)
    {
        return ConnectAsync(options, localHandshakePrivateKey: default, cancellationToken);
    }

    internal ValueTask<QuicConnection> ConnectAsync(
        QuicClientConnectionOptions options,
        ReadOnlyMemory<byte> localHandshakePrivateKey,
        CancellationToken cancellationToken = default)
    {
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            options,
            nameof(options),
            localHandshakePrivateKey: localHandshakePrivateKey);
        cancellationToken.ThrowIfCancellationRequested();

        return new QuicClientConnectionHost(settings, CreateClientSink).ConnectAsync(cancellationToken);
    }

    /// <summary>
    /// Starts a listener that creates one qlog trace per accepted connection.
    /// </summary>
    public ValueTask<QuicListener> ListenAsync(
        QuicListenerOptions options,
        CancellationToken cancellationToken = default)
    {
        return QuicListener.ListenAsync(options, cancellationToken, CreateServerSink);
    }

    internal Func<IQuicDiagnosticsSink> CreateClientDiagnosticsSinkFactory()
    {
        return CreateClientSink;
    }

    internal Func<IQuicDiagnosticsSink> CreateServerDiagnosticsSinkFactory()
    {
        return CreateServerSink;
    }

    /// <summary>
    /// Serializes the captured file to contained qlog JSON.
    /// </summary>
    public string ToJson(bool indented = false)
    {
        lock (gate)
        {
            return QlogJsonSerializer.Serialize(File, indented);
        }
    }

    /// <summary>
    /// Serializes the captured file to a contained qlog JSON stream.
    /// </summary>
    public void WriteJson(Stream stream, bool indented = false)
    {
        lock (gate)
        {
            QlogJsonSerializer.Serialize(stream, File, indented);
        }
    }

    private QuicQlogDiagnosticsSink CreateClientSink()
    {
        return CreateSink(isServer: false);
    }

    private IQuicDiagnosticsSink CreateServerSink()
    {
        return CreateSink(isServer: true);
    }

    private QuicQlogDiagnosticsSink CreateSink(bool isServer)
    {
        lock (gate)
        {
            QuicQlogDiagnosticsSink sink = new(isServer, gate);
            File.Traces.Add(sink.Trace);
            return sink;
        }
    }
}

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
        QlogFile snapshot = CreateSnapshot();
        return QlogJsonSerializer.Serialize(snapshot, indented);
    }

    /// <summary>
    /// Serializes the captured file to a contained qlog JSON stream.
    /// </summary>
    public void WriteJson(Stream stream, bool indented = false)
    {
        QlogFile snapshot = CreateSnapshot();
        QlogJsonSerializer.Serialize(stream, snapshot, indented);
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

    private QlogFile CreateSnapshot()
    {
        lock (gate)
        {
            return CloneFile(File);
        }
    }

    private static QlogFile CloneFile(QlogFile source)
    {
        ArgumentNullException.ThrowIfNull(source);

        QlogFile clone = new()
        {
            FileSchema = new Uri(source.FileSchema.OriginalString, UriKind.Absolute),
            SerializationFormat = source.SerializationFormat,
            Title = source.Title,
            Description = source.Description,
        };

        CopyEntries(source.ExtensionData, clone.ExtensionData);

        foreach (QlogTraceComponent traceComponent in source.Traces)
        {
            clone.Traces.Add(CloneTraceComponent(traceComponent));
        }

        return clone;
    }

    private static QlogTraceComponent CloneTraceComponent(QlogTraceComponent source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return source switch
        {
            QlogTrace trace => CloneTrace(trace),
            QlogTraceError traceError => CloneTraceError(traceError),
            _ => throw new NotSupportedException($"Unsupported qlog trace component '{source.GetType().FullName}'."),
        };
    }

    private static QlogTrace CloneTrace(QlogTrace source)
    {
        QlogTrace clone = new()
        {
            Title = source.Title,
            Description = source.Description,
            CommonFields = CloneCommonFields(source.CommonFields),
            VantagePoint = CloneVantagePoint(source.VantagePoint),
        };

        foreach (Uri eventSchema in source.EventSchemas)
        {
            clone.EventSchemas.Add(new Uri(eventSchema.OriginalString, UriKind.Absolute));
        }

        foreach (QlogEvent qlogEvent in source.Events)
        {
            clone.Events.Add(CloneEvent(qlogEvent));
        }

        CopyEntries(source.ExtensionData, clone.ExtensionData);
        return clone;
    }

    private static QlogTraceError CloneTraceError(QlogTraceError source)
    {
        QlogTraceError clone = new()
        {
            ErrorDescription = source.ErrorDescription,
            Uri = source.Uri,
            VantagePoint = CloneVantagePoint(source.VantagePoint),
        };

        CopyEntries(source.ExtensionData, clone.ExtensionData);
        return clone;
    }

    private static QlogCommonFields? CloneCommonFields(QlogCommonFields? source)
    {
        if (source is null)
        {
            return null;
        }

        QlogCommonFields clone = new()
        {
            Tuple = source.Tuple,
            TimeFormat = source.TimeFormat,
            GroupId = source.GroupId,
            ReferenceTime = CloneReferenceTime(source.ReferenceTime),
        };

        CopyEntries(source.ExtensionData, clone.ExtensionData);
        return clone;
    }

    private static QlogReferenceTime? CloneReferenceTime(QlogReferenceTime? source)
    {
        if (source is null)
        {
            return null;
        }

        QlogReferenceTime clone = new()
        {
            ClockType = source.ClockType,
            Epoch = source.Epoch,
            WallClockTime = source.WallClockTime,
        };

        CopyEntries(source.ExtensionData, clone.ExtensionData);
        return clone;
    }

    private static QlogVantagePoint? CloneVantagePoint(QlogVantagePoint? source)
    {
        if (source is null)
        {
            return null;
        }

        QlogVantagePoint clone = new()
        {
            Name = source.Name,
            Type = source.Type,
            Flow = source.Flow,
        };

        CopyEntries(source.ExtensionData, clone.ExtensionData);
        return clone;
    }

    private static QlogEvent CloneEvent(QlogEvent source)
    {
        ArgumentNullException.ThrowIfNull(source);

        QlogEvent clone = new()
        {
            Time = source.Time,
            Name = source.Name,
            Tuple = source.Tuple,
            TimeFormat = source.TimeFormat,
            GroupId = source.GroupId,
            SystemInfo = source.SystemInfo is null
                ? null
                : new Dictionary<string, QlogValue>(source.SystemInfo, StringComparer.Ordinal),
        };

        CopyEntries(source.Data, clone.Data);
        CopyEntries(source.ExtensionData, clone.ExtensionData);
        return clone;
    }

    private static void CopyEntries(
        IEnumerable<KeyValuePair<string, QlogValue>> source,
        IDictionary<string, QlogValue> destination)
    {
        foreach (KeyValuePair<string, QlogValue> entry in source)
        {
            destination[entry.Key] = entry.Value;
        }
    }
}

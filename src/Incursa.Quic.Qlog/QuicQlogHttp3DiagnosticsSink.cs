using Incursa.Qlog;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Qlog;

/// <summary>
/// Adapts optional HTTP/3 diagnostics into contained qlog events.
/// </summary>
public sealed class QuicQlogHttp3DiagnosticsSink : IHttp3DiagnosticsSink
{
    private readonly QuicQlogCapture capture;
    private readonly bool isServer;

    /// <summary>
    /// Initializes a new instance of the <see cref="QuicQlogHttp3DiagnosticsSink" /> class.
    /// </summary>
    public QuicQlogHttp3DiagnosticsSink(QuicQlogCapture capture, bool isServer)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
        this.isServer = isServer;
    }

    /// <inheritdoc />
    public bool IsEnabled => true;

    /// <inheritdoc />
    public void Emit(Http3DiagnosticEvent diagnosticEvent)
    {
        ArgumentNullException.ThrowIfNull(diagnosticEvent);
        Dictionary<string, QlogValue> data = new(StringComparer.Ordinal)
        {
            ["event"] = QlogValue.FromString(ToSnakeCase(diagnosticEvent.Kind.ToString())),
            ["role"] = QlogValue.FromString(diagnosticEvent.Role ?? (isServer ? "server" : "client")),
        };

        AddNumber(data, "stream_id", diagnosticEvent.StreamId);
        AddString(data, "stream_kind", diagnosticEvent.StreamKind?.ToString());
        AddString(data, "frame_type", diagnosticEvent.FrameType?.ToString());
        AddNumber(data, "raw_frame_type", diagnosticEvent.RawFrameType);
        AddNumber(data, "payload_length", diagnosticEvent.PayloadLength);
        AddString(data, "qpack_instruction", diagnosticEvent.QPackInstruction);
        AddString(data, "method", diagnosticEvent.Method);
        AddString(data, "path", diagnosticEvent.Path);
        AddNumber(data, "status_code", diagnosticEvent.StatusCode);
        AddString(data, "error_code", diagnosticEvent.ErrorCode);
        AddString(data, "message", diagnosticEvent.Message);

        capture.RecordApplicationEvent(
            isServer,
            "http3:" + ToSnakeCase(diagnosticEvent.Kind.ToString()),
            data);
    }

    private static void AddString(Dictionary<string, QlogValue> data, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[name] = QlogValue.FromString(value);
        }
    }

    private static void AddNumber(Dictionary<string, QlogValue> data, string name, long? value)
    {
        if (value.HasValue)
        {
            data[name] = QlogValue.FromNumber(value.Value);
        }
    }

    private static void AddNumber(Dictionary<string, QlogValue> data, string name, int? value)
    {
        if (value.HasValue)
        {
            data[name] = QlogValue.FromNumber(value.Value);
        }
    }

    private static void AddNumber(Dictionary<string, QlogValue> data, string name, ulong? value)
    {
        if (value.HasValue && value.Value <= long.MaxValue)
        {
            data[name] = QlogValue.FromNumber((long)value.Value);
        }
    }

    private static string ToSnakeCase(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        Span<char> buffer = stackalloc char[value.Length * 2];
        int written = 0;
        for (int index = 0; index < value.Length; index++)
        {
            char current = value[index];
            if (char.IsUpper(current))
            {
                if (index != 0)
                {
                    buffer[written++] = '_';
                }

                buffer[written++] = char.ToLowerInvariant(current);
                continue;
            }

            buffer[written++] = current;
        }

        return new string(buffer[..written]);
    }
}

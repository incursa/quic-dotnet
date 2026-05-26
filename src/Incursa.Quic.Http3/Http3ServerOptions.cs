namespace Incursa.Quic.Http3;

/// <summary>
/// Configures the minimal HTTP/3 server facade.
/// </summary>
public sealed class Http3ServerOptions
{
    private const int DefaultReadBufferSize = 16 * 1024;

    /// <summary>
    /// Gets or sets the local HTTP/3 SETTINGS sent on the server control stream.
    /// </summary>
    public Http3Settings Settings { get; set; } = new();

    /// <summary>
    /// Gets or sets the request-stream read buffer size.
    /// </summary>
    public int ReadBufferSize { get; set; } = DefaultReadBufferSize;

    /// <summary>
    /// Gets or sets an optional diagnostics sink for HTTP/3 and QPACK stream events.
    /// </summary>
    public IHttp3DiagnosticsSink? DiagnosticsSink { get; set; }
}

namespace Incursa.Quic.Http3;

/// <summary>
/// Receives optional HTTP/3 diagnostics without coupling the HTTP/3 layer to a concrete telemetry backend.
/// </summary>
public interface IHttp3DiagnosticsSink
{
    /// <summary>
    /// Gets a value indicating whether the sink is currently accepting events.
    /// </summary>
    bool IsEnabled { get; }

    /// <summary>
    /// Emits one HTTP/3 diagnostic event.
    /// </summary>
    void Emit(Http3DiagnosticEvent diagnosticEvent);
}

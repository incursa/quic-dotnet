namespace Incursa.Quic;

/// <summary>
/// Severity for transport-visible diagnostics.
/// </summary>
internal enum QuicDiagnosticSeverity
{
    Trace = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
}

/// <summary>
/// A structured diagnostic event emitted by the transport.
/// </summary>
/// <param name="Category">The stable category for the event.</param>
/// <param name="Name">The stable event name.</param>
/// <param name="Message">A human-readable summary.</param>
/// <param name="Severity">The event severity.</param>
internal readonly record struct QuicDiagnosticEvent(
    string Category,
    string Name,
    string Message,
    QuicDiagnosticSeverity Severity = QuicDiagnosticSeverity.Info);

/// <summary>
/// Accepts transport-visible diagnostic events.
/// </summary>
internal interface IQuicDiagnosticsSink
{
    /// <summary>
    /// Gets a value indicating whether the sink is enabled.
    /// </summary>
    bool IsEnabled { get; }

    /// <summary>
    /// Emits one diagnostic event.
    /// </summary>
    /// <param name="diagnosticEvent">The event to emit.</param>
    void Emit(QuicDiagnosticEvent diagnosticEvent);
}

/// <summary>
/// A disabled diagnostics sink.
/// </summary>
internal sealed class QuicNullDiagnosticsSink : IQuicDiagnosticsSink
{
    /// <summary>
    /// Gets the singleton disabled sink instance.
    /// </summary>
    public static QuicNullDiagnosticsSink Instance { get; } = new();

    private QuicNullDiagnosticsSink()
    {
    }

    /// <inheritdoc />
    public bool IsEnabled => false;

    /// <inheritdoc />
    public void Emit(QuicDiagnosticEvent diagnosticEvent)
    {
        _ = diagnosticEvent;
    }
}

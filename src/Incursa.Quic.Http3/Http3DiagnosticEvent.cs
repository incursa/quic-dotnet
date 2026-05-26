namespace Incursa.Quic.Http3;

/// <summary>
/// Carries a low-allocation HTTP/3 diagnostic event for optional observability sinks.
/// </summary>
public sealed record Http3DiagnosticEvent(Http3DiagnosticKind Kind)
{
    /// <summary>
    /// Gets the endpoint role that emitted the event.
    /// </summary>
    public string? Role { get; init; }

    /// <summary>
    /// Gets the QUIC stream identifier when the event is stream scoped.
    /// </summary>
    public long? StreamId { get; init; }

    /// <summary>
    /// Gets the HTTP/3 stream kind when known.
    /// </summary>
    public Http3StreamKind? StreamKind { get; init; }

    /// <summary>
    /// Gets the known HTTP/3 frame type when the frame type is registered.
    /// </summary>
    public Http3FrameType? FrameType { get; init; }

    /// <summary>
    /// Gets the raw HTTP/3 frame type value.
    /// </summary>
    public ulong? RawFrameType { get; init; }

    /// <summary>
    /// Gets the frame or field-section payload length when known.
    /// </summary>
    public int? PayloadLength { get; init; }

    /// <summary>
    /// Gets the QPACK instruction name when the event describes a QPACK stream instruction.
    /// </summary>
    public string? QPackInstruction { get; init; }

    /// <summary>
    /// Gets the request method when the event describes a request lifecycle transition.
    /// </summary>
    public string? Method { get; init; }

    /// <summary>
    /// Gets the request path when the event describes a request lifecycle transition.
    /// </summary>
    public string? Path { get; init; }

    /// <summary>
    /// Gets the response status code when the event describes a response lifecycle transition.
    /// </summary>
    public int? StatusCode { get; init; }

    /// <summary>
    /// Gets the HTTP/3 or QPACK error code name when available.
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// Gets a diagnostic message for error and lifecycle events.
    /// </summary>
    public string? Message { get; init; }
}

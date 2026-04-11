namespace Incursa.Quic;

/// <summary>
/// Describes why a peer transport-parameter connection-ID binding check failed.
/// </summary>
internal enum QuicConnectionIdBindingValidationError
{
    /// <summary>
    /// The peer transport parameters matched the observed connection IDs.
    /// </summary>
    None = 0,

    /// <summary>
    /// The peer omitted the original_destination_connection_id transport parameter.
    /// </summary>
    MissingOriginalDestinationConnectionId = 1,

    /// <summary>
    /// The peer omitted the initial_source_connection_id transport parameter.
    /// </summary>
    MissingInitialSourceConnectionId = 2,

    /// <summary>
    /// The peer omitted the retry_source_connection_id transport parameter when Retry was used.
    /// </summary>
    MissingRetrySourceConnectionId = 3,

    /// <summary>
    /// The peer's original_destination_connection_id value did not match the observed connection ID.
    /// </summary>
    OriginalDestinationConnectionIdMismatch = 4,

    /// <summary>
    /// The peer's initial_source_connection_id value did not match the observed connection ID.
    /// </summary>
    InitialSourceConnectionIdMismatch = 5,

    /// <summary>
    /// The peer's retry_source_connection_id value did not match the observed connection ID.
    /// </summary>
    RetrySourceConnectionIdMismatch = 6,

    /// <summary>
    /// The peer included retry_source_connection_id when Retry was not used.
    /// </summary>
    UnexpectedRetrySourceConnectionId = 7,
}


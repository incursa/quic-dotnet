namespace Incursa.Quic;

/// <summary>
/// A parsed QUIC transport-parameter set.
/// </summary>
internal sealed class QuicTransportParameters
{
    /// <summary>
    /// Gets or sets the original_destination_connection_id transport parameter value.
    /// </summary>
    internal byte[]? OriginalDestinationConnectionId { get; set; }

    /// <summary>
    /// Gets or sets the max_idle_timeout transport parameter value.
    /// </summary>
    internal ulong? MaxIdleTimeout { get; set; }

    /// <summary>
    /// Gets or sets the stateless_reset_token transport parameter value.
    /// </summary>
    internal byte[]? StatelessResetToken { get; set; }

    /// <summary>
    /// Gets or sets the max_udp_payload_size transport parameter value.
    /// </summary>
    internal ulong? MaxUdpPayloadSize { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_data transport parameter value.
    /// </summary>
    internal ulong? InitialMaxData { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_stream_data_bidi_local transport parameter value.
    /// </summary>
    internal ulong? InitialMaxStreamDataBidiLocal { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_stream_data_bidi_remote transport parameter value.
    /// </summary>
    internal ulong? InitialMaxStreamDataBidiRemote { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_stream_data_uni transport parameter value.
    /// </summary>
    internal ulong? InitialMaxStreamDataUni { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_streams_bidi transport parameter value.
    /// </summary>
    internal ulong? InitialMaxStreamsBidi { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_streams_uni transport parameter value.
    /// </summary>
    internal ulong? InitialMaxStreamsUni { get; set; }

    /// <summary>
    /// Gets or sets the max_ack_delay transport parameter value.
    /// </summary>
    internal ulong? MaxAckDelay { get; set; }

    /// <summary>
    /// Gets or sets whether disable_active_migration is present.
    /// </summary>
    internal bool DisableActiveMigration { get; set; }

    /// <summary>
    /// Gets or sets the preferred_address transport parameter value.
    /// </summary>
    internal QuicPreferredAddress? PreferredAddress { get; set; }

    /// <summary>
    /// Gets or sets the active_connection_id_limit transport parameter value.
    /// </summary>
    internal ulong? ActiveConnectionIdLimit { get; set; }

    /// <summary>
    /// Gets or sets the initial_source_connection_id transport parameter value.
    /// </summary>
    internal byte[]? InitialSourceConnectionId { get; set; }

    /// <summary>
    /// Gets or sets the retry_source_connection_id transport parameter value.
    /// </summary>
    internal byte[]? RetrySourceConnectionId { get; set; }
}


namespace Incursa.Quic;

/// <summary>
/// A parsed QUIC transport-parameter set.
/// </summary>
public sealed class QuicTransportParameters
{
    /// <summary>
    /// Gets or sets the original_destination_connection_id transport parameter value.
    /// </summary>
    public byte[]? OriginalDestinationConnectionId { get; set; }

    /// <summary>
    /// Gets or sets the max_idle_timeout transport parameter value.
    /// </summary>
    public ulong? MaxIdleTimeout { get; set; }

    /// <summary>
    /// Gets or sets the stateless_reset_token transport parameter value.
    /// </summary>
    public byte[]? StatelessResetToken { get; set; }

    /// <summary>
    /// Gets or sets the max_udp_payload_size transport parameter value.
    /// </summary>
    public ulong? MaxUdpPayloadSize { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_data transport parameter value.
    /// </summary>
    public ulong? InitialMaxData { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_stream_data_bidi_local transport parameter value.
    /// </summary>
    public ulong? InitialMaxStreamDataBidiLocal { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_stream_data_bidi_remote transport parameter value.
    /// </summary>
    public ulong? InitialMaxStreamDataBidiRemote { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_stream_data_uni transport parameter value.
    /// </summary>
    public ulong? InitialMaxStreamDataUni { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_streams_bidi transport parameter value.
    /// </summary>
    public ulong? InitialMaxStreamsBidi { get; set; }

    /// <summary>
    /// Gets or sets the initial_max_streams_uni transport parameter value.
    /// </summary>
    public ulong? InitialMaxStreamsUni { get; set; }

    /// <summary>
    /// Gets or sets the max_ack_delay transport parameter value.
    /// </summary>
    public ulong? MaxAckDelay { get; set; }

    /// <summary>
    /// Gets or sets whether disable_active_migration is present.
    /// </summary>
    public bool DisableActiveMigration { get; set; }

    /// <summary>
    /// Gets or sets the preferred_address transport parameter value.
    /// </summary>
    public QuicPreferredAddress? PreferredAddress { get; set; }

    /// <summary>
    /// Gets or sets the active_connection_id_limit transport parameter value.
    /// </summary>
    public ulong? ActiveConnectionIdLimit { get; set; }

    /// <summary>
    /// Gets or sets the initial_source_connection_id transport parameter value.
    /// </summary>
    public byte[]? InitialSourceConnectionId { get; set; }

    /// <summary>
    /// Gets or sets the retry_source_connection_id transport parameter value.
    /// </summary>
    public byte[]? RetrySourceConnectionId { get; set; }
}

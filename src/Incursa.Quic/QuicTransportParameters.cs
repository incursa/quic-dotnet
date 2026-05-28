// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// A parsed QUIC transport-parameter set.
/// </summary>
internal sealed class QuicTransportParameters
{
    /// <summary>
    /// Gets the default max_udp_payload_size value when the transport parameter is absent.
    /// </summary>
    internal const ulong DefaultMaxUdpPayloadSize = 65527;

    /// <summary>
    /// Gets the minimum valid max_udp_payload_size value for QUIC version 1.
    /// </summary>
    internal const ulong MinimumMaxUdpPayloadSize = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;

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
    /// Gets or sets the max_datagram_frame_size transport parameter value.
    /// </summary>
    internal ulong? MaxDatagramFrameSize { get; set; }

    /// <summary>
    /// Gets or sets whether grease_quic_bit was advertised.
    /// </summary>
    internal bool GreaseQuicBit { get; set; }

    /// <summary>
    /// Gets or sets version_information when negotiated version support is enabled.
    /// </summary>
    internal QuicVersionInformation? VersionInformation { get; set; }

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

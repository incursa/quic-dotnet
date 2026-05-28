// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicTransportParameterRegistryProofSupport
{
    internal static readonly (ulong ParameterId, string ParameterName)[] PermanentTransportParameters =
    [
        (0x00UL, "original_destination_connection_id"),
        (0x01UL, "max_idle_timeout"),
        (0x02UL, "stateless_reset_token"),
        (0x03UL, "max_udp_payload_size"),
        (0x04UL, "initial_max_data"),
        (0x05UL, "initial_max_stream_data_bidi_local"),
        (0x06UL, "initial_max_stream_data_bidi_remote"),
        (0x07UL, "initial_max_stream_data_uni"),
        (0x08UL, "initial_max_streams_bidi"),
        (0x09UL, "initial_max_streams_uni"),
        (0x0BUL, "max_ack_delay"),
        (0x0CUL, "disable_active_migration"),
        (0x0DUL, "preferred_address"),
        (0x0EUL, "active_connection_id_limit"),
        (0x0FUL, "initial_source_connection_id"),
        (0x10UL, "retry_source_connection_id"),
    ];
}

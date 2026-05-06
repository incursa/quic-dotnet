namespace Incursa.Quic;

internal enum QuicZeroRttTransportParameterMemoryRequirement
{
    Mandatory = 0,
    Optional = 1,
    Prohibited = 2,
}

internal readonly record struct QuicZeroRttTransportParameterDefinition(
    ulong Id,
    string Name,
    QuicZeroRttTransportParameterMemoryRequirement MemoryRequirement);

internal static class QuicZeroRttTransportParameterPolicy
{
    internal const ulong OriginalDestinationConnectionIdId = 0x00;
    internal const ulong MaxIdleTimeoutId = 0x01;
    internal const ulong StatelessResetTokenId = 0x02;
    internal const ulong MaxUdpPayloadSizeId = 0x03;
    internal const ulong InitialMaxDataId = 0x04;
    internal const ulong InitialMaxStreamDataBidiLocalId = 0x05;
    internal const ulong InitialMaxStreamDataBidiRemoteId = 0x06;
    internal const ulong InitialMaxStreamDataUniId = 0x07;
    internal const ulong InitialMaxStreamsBidiId = 0x08;
    internal const ulong InitialMaxStreamsUniId = 0x09;
    internal const ulong AckDelayExponentId = 0x0A;
    internal const ulong MaxAckDelayId = 0x0B;
    internal const ulong DisableActiveMigrationId = 0x0C;
    internal const ulong PreferredAddressId = 0x0D;
    internal const ulong ActiveConnectionIdLimitId = 0x0E;
    internal const ulong InitialSourceConnectionIdId = 0x0F;
    internal const ulong RetrySourceConnectionIdId = 0x10;

    internal static readonly QuicZeroRttTransportParameterDefinition[] KnownDefinitions =
    [
        new(OriginalDestinationConnectionIdId, "original_destination_connection_id", QuicZeroRttTransportParameterMemoryRequirement.Prohibited),
        new(MaxIdleTimeoutId, "max_idle_timeout", QuicZeroRttTransportParameterMemoryRequirement.Optional),
        new(StatelessResetTokenId, "stateless_reset_token", QuicZeroRttTransportParameterMemoryRequirement.Prohibited),
        new(MaxUdpPayloadSizeId, "max_udp_payload_size", QuicZeroRttTransportParameterMemoryRequirement.Optional),
        new(InitialMaxDataId, "initial_max_data", QuicZeroRttTransportParameterMemoryRequirement.Mandatory),
        new(InitialMaxStreamDataBidiLocalId, "initial_max_stream_data_bidi_local", QuicZeroRttTransportParameterMemoryRequirement.Mandatory),
        new(InitialMaxStreamDataBidiRemoteId, "initial_max_stream_data_bidi_remote", QuicZeroRttTransportParameterMemoryRequirement.Mandatory),
        new(InitialMaxStreamDataUniId, "initial_max_stream_data_uni", QuicZeroRttTransportParameterMemoryRequirement.Mandatory),
        new(InitialMaxStreamsBidiId, "initial_max_streams_bidi", QuicZeroRttTransportParameterMemoryRequirement.Mandatory),
        new(InitialMaxStreamsUniId, "initial_max_streams_uni", QuicZeroRttTransportParameterMemoryRequirement.Mandatory),
        new(AckDelayExponentId, "ack_delay_exponent", QuicZeroRttTransportParameterMemoryRequirement.Prohibited),
        new(MaxAckDelayId, "max_ack_delay", QuicZeroRttTransportParameterMemoryRequirement.Prohibited),
        new(DisableActiveMigrationId, "disable_active_migration", QuicZeroRttTransportParameterMemoryRequirement.Optional),
        new(PreferredAddressId, "preferred_address", QuicZeroRttTransportParameterMemoryRequirement.Prohibited),
        new(ActiveConnectionIdLimitId, "active_connection_id_limit", QuicZeroRttTransportParameterMemoryRequirement.Mandatory),
        new(InitialSourceConnectionIdId, "initial_source_connection_id", QuicZeroRttTransportParameterMemoryRequirement.Prohibited),
        new(RetrySourceConnectionIdId, "retry_source_connection_id", QuicZeroRttTransportParameterMemoryRequirement.Prohibited),
    ];

    internal static bool TryGetKnownDefinition(
        ulong id,
        out QuicZeroRttTransportParameterDefinition definition)
    {
        foreach (QuicZeroRttTransportParameterDefinition candidate in KnownDefinitions)
        {
            if (candidate.Id == id)
            {
                definition = candidate;
                return true;
            }
        }

        definition = default;
        return false;
    }

    internal static QuicTransportParameters? CreateRememberedTransportParametersForClientZeroRtt(
        QuicTransportParameters? peerTransportParameters)
    {
        if (peerTransportParameters is null)
        {
            return null;
        }

        QuicTransportParameters remembered = new()
        {
            MaxIdleTimeout = peerTransportParameters.MaxIdleTimeout,
            MaxUdpPayloadSize = peerTransportParameters.MaxUdpPayloadSize,
            InitialMaxData = peerTransportParameters.InitialMaxData,
            InitialMaxStreamDataBidiLocal = peerTransportParameters.InitialMaxStreamDataBidiLocal,
            InitialMaxStreamDataBidiRemote = peerTransportParameters.InitialMaxStreamDataBidiRemote,
            InitialMaxStreamDataUni = peerTransportParameters.InitialMaxStreamDataUni,
            InitialMaxStreamsBidi = peerTransportParameters.InitialMaxStreamsBidi,
            InitialMaxStreamsUni = peerTransportParameters.InitialMaxStreamsUni,
            DisableActiveMigration = peerTransportParameters.DisableActiveMigration,
            ActiveConnectionIdLimit = peerTransportParameters.ActiveConnectionIdLimit,
        };

        return HasRememberedValue(remembered) ? remembered : null;
    }

    private static bool HasRememberedValue(QuicTransportParameters parameters)
    {
        return parameters.MaxIdleTimeout.HasValue
            || parameters.MaxUdpPayloadSize.HasValue
            || parameters.InitialMaxData.HasValue
            || parameters.InitialMaxStreamDataBidiLocal.HasValue
            || parameters.InitialMaxStreamDataBidiRemote.HasValue
            || parameters.InitialMaxStreamDataUni.HasValue
            || parameters.InitialMaxStreamsBidi.HasValue
            || parameters.InitialMaxStreamsUni.HasValue
            || parameters.DisableActiveMigration
            || parameters.ActiveConnectionIdLimit.HasValue;
    }
}

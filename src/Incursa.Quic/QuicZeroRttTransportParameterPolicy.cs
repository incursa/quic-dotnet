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

internal enum QuicZeroRttTransportParameterAcceptanceFailure
{
    None = 0,
    MissingRememberedParameters = 1,
    MissingCurrentParameters = 2,
    ReducedRequiredLimit = 3,
    ReducedOptionalValue = 4,
}

internal enum QuicZeroRttTransportParameterValueSource
{
    Unknown = 0,
    Remembered = 1,
    UpdatedFromHandshake = 2,
    UpdatedFromOneRttFrame = 3,
}

internal enum QuicZeroRttTransportParameterUseFailure
{
    None = 0,
    MissingRememberedValue = 1,
    UpdatedHandshakeValueInZeroRtt = 2,
    UpdatedOneRttFrameValueInZeroRtt = 3,
    UpdatedValueOutsideOneRtt = 4,
}

internal readonly record struct QuicZeroRttTransportParameterAcceptanceDecision(
    bool CanAccept,
    QuicZeroRttTransportParameterAcceptanceFailure Failure,
    string? ParameterName)
{
    internal static QuicZeroRttTransportParameterAcceptanceDecision Accept { get; } =
        new(true, QuicZeroRttTransportParameterAcceptanceFailure.None, null);

    internal static QuicZeroRttTransportParameterAcceptanceDecision Reject(
        QuicZeroRttTransportParameterAcceptanceFailure failure,
        string parameterName)
    {
        return new(false, failure, parameterName);
    }
}

internal readonly record struct QuicZeroRttTransportParameterUseDecision(
    bool CanUse,
    QuicZeroRttTransportParameterUseFailure Failure,
    QuicTransportErrorCode? ErrorCode)
{
    internal static QuicZeroRttTransportParameterUseDecision Accept { get; } =
        new(true, QuicZeroRttTransportParameterUseFailure.None, null);

    internal static QuicZeroRttTransportParameterUseDecision Reject(
        QuicZeroRttTransportParameterUseFailure failure,
        QuicTransportErrorCode? errorCode = null)
    {
        return new(false, failure, errorCode);
    }
}

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

    internal static QuicZeroRttTransportParameterAcceptanceDecision EvaluateServerZeroRttAcceptance(
        QuicTransportParameters? rememberedTransportParameters,
        QuicTransportParameters? currentServerTransportParameters)
    {
        if (rememberedTransportParameters is null)
        {
            return QuicZeroRttTransportParameterAcceptanceDecision.Reject(
                QuicZeroRttTransportParameterAcceptanceFailure.MissingRememberedParameters,
                "remembered_transport_parameters");
        }

        if (currentServerTransportParameters is null)
        {
            return QuicZeroRttTransportParameterAcceptanceDecision.Reject(
                QuicZeroRttTransportParameterAcceptanceFailure.MissingCurrentParameters,
                "current_server_transport_parameters");
        }

        QuicZeroRttTransportParameterAcceptanceDecision requiredDecision =
            RejectIfRequiredLimitReduced(
                "active_connection_id_limit",
                EffectiveActiveConnectionIdLimit(rememberedTransportParameters),
                EffectiveActiveConnectionIdLimit(currentServerTransportParameters));
        if (!requiredDecision.CanAccept)
        {
            return requiredDecision;
        }

        requiredDecision = RejectIfRequiredLimitReduced(
            "initial_max_data",
            rememberedTransportParameters.InitialMaxData ?? 0,
            currentServerTransportParameters.InitialMaxData ?? 0);
        if (!requiredDecision.CanAccept)
        {
            return requiredDecision;
        }

        requiredDecision = RejectIfRequiredLimitReduced(
            "initial_max_stream_data_bidi_local",
            rememberedTransportParameters.InitialMaxStreamDataBidiLocal ?? 0,
            currentServerTransportParameters.InitialMaxStreamDataBidiLocal ?? 0);
        if (!requiredDecision.CanAccept)
        {
            return requiredDecision;
        }

        requiredDecision = RejectIfRequiredLimitReduced(
            "initial_max_stream_data_bidi_remote",
            rememberedTransportParameters.InitialMaxStreamDataBidiRemote ?? 0,
            currentServerTransportParameters.InitialMaxStreamDataBidiRemote ?? 0);
        if (!requiredDecision.CanAccept)
        {
            return requiredDecision;
        }

        requiredDecision = RejectIfRequiredLimitReduced(
            "initial_max_stream_data_uni",
            rememberedTransportParameters.InitialMaxStreamDataUni ?? 0,
            currentServerTransportParameters.InitialMaxStreamDataUni ?? 0);
        if (!requiredDecision.CanAccept)
        {
            return requiredDecision;
        }

        requiredDecision = RejectIfRequiredLimitReduced(
            "initial_max_streams_bidi",
            rememberedTransportParameters.InitialMaxStreamsBidi ?? 0,
            currentServerTransportParameters.InitialMaxStreamsBidi ?? 0);
        if (!requiredDecision.CanAccept)
        {
            return requiredDecision;
        }

        requiredDecision = RejectIfRequiredLimitReduced(
            "initial_max_streams_uni",
            rememberedTransportParameters.InitialMaxStreamsUni ?? 0,
            currentServerTransportParameters.InitialMaxStreamsUni ?? 0);
        if (!requiredDecision.CanAccept)
        {
            return requiredDecision;
        }

        QuicZeroRttTransportParameterAcceptanceDecision optionalDecision =
            RejectIfRememberedOptionalValueReduced(
                "max_idle_timeout",
                rememberedTransportParameters.MaxIdleTimeout,
                currentServerTransportParameters.MaxIdleTimeout ?? 0);
        if (!optionalDecision.CanAccept)
        {
            return optionalDecision;
        }

        optionalDecision = RejectIfRememberedOptionalValueReduced(
            "max_udp_payload_size",
            rememberedTransportParameters.MaxUdpPayloadSize,
            currentServerTransportParameters.MaxUdpPayloadSize ?? QuicTransportParameters.DefaultMaxUdpPayloadSize);
        if (!optionalDecision.CanAccept)
        {
            return optionalDecision;
        }

        if (rememberedTransportParameters.DisableActiveMigration
            && !currentServerTransportParameters.DisableActiveMigration)
        {
            return QuicZeroRttTransportParameterAcceptanceDecision.Reject(
                QuicZeroRttTransportParameterAcceptanceFailure.ReducedOptionalValue,
                "disable_active_migration");
        }

        return QuicZeroRttTransportParameterAcceptanceDecision.Accept;
    }

    internal static QuicTransportParameters ResolveClientHandshakeValuesForProhibitedZeroRttParameters(
        QuicTransportParameters? rememberedTransportParameters,
        QuicTransportParameters? handshakeTransportParameters)
    {
        _ = rememberedTransportParameters;

        return new QuicTransportParameters
        {
            OriginalDestinationConnectionId = CloneBytes(handshakeTransportParameters?.OriginalDestinationConnectionId),
            StatelessResetToken = CloneBytes(handshakeTransportParameters?.StatelessResetToken),
            MaxAckDelay = handshakeTransportParameters?.MaxAckDelay ?? QuicMaxAckDelayPolicy.DefaultMaxAckDelayMicros,
            PreferredAddress = ClonePreferredAddress(handshakeTransportParameters?.PreferredAddress),
            InitialSourceConnectionId = CloneBytes(handshakeTransportParameters?.InitialSourceConnectionId),
            RetrySourceConnectionId = CloneBytes(handshakeTransportParameters?.RetrySourceConnectionId),
        };
    }

    internal static bool HasNonZeroClientApplicationDataAllowance(QuicTransportParameters transportParameters)
    {
        ArgumentNullException.ThrowIfNull(transportParameters);

        if ((transportParameters.InitialMaxData ?? 0) == 0)
        {
            return false;
        }

        bool bidirectionalClientDataAllowed =
            (transportParameters.InitialMaxStreamsBidi ?? 0) > 0
            && (transportParameters.InitialMaxStreamDataBidiRemote ?? 0) > 0;
        bool unidirectionalClientDataAllowed =
            (transportParameters.InitialMaxStreamsUni ?? 0) > 0
            && (transportParameters.InitialMaxStreamDataUni ?? 0) > 0;
        return bidirectionalClientDataAllowed || unidirectionalClientDataAllowed;
    }

    internal static QuicZeroRttTransportParameterUseDecision EvaluateClientTransportParameterUseForPacket(
        QuicTlsEncryptionLevel packetProtectionLevel,
        QuicZeroRttTransportParameterValueSource valueSource)
    {
        if (packetProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt)
        {
            return valueSource == QuicZeroRttTransportParameterValueSource.Remembered
                ? QuicZeroRttTransportParameterUseDecision.Accept
                : RejectZeroRttUpdatedValue(valueSource);
        }

        if (valueSource is QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake
            or QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame)
        {
            return packetProtectionLevel == QuicTlsEncryptionLevel.OneRtt
                ? QuicZeroRttTransportParameterUseDecision.Accept
                : QuicZeroRttTransportParameterUseDecision.Reject(
                    QuicZeroRttTransportParameterUseFailure.UpdatedValueOutsideOneRtt,
                    QuicTransportErrorCode.ProtocolViolation);
        }

        return valueSource == QuicZeroRttTransportParameterValueSource.Remembered
            ? QuicZeroRttTransportParameterUseDecision.Accept
            : QuicZeroRttTransportParameterUseDecision.Reject(
                QuicZeroRttTransportParameterUseFailure.MissingRememberedValue);
    }

    internal static QuicTransportErrorCode? GetServerZeroRttTransportParameterUseError(
        QuicZeroRttTransportParameterValueSource valueSource)
    {
        return valueSource is QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake
            or QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame
            ? QuicTransportErrorCode.ProtocolViolation
            : null;
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

    private static QuicZeroRttTransportParameterUseDecision RejectZeroRttUpdatedValue(
        QuicZeroRttTransportParameterValueSource valueSource)
    {
        QuicZeroRttTransportParameterUseFailure failure = valueSource switch
        {
            QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake
                => QuicZeroRttTransportParameterUseFailure.UpdatedHandshakeValueInZeroRtt,
            QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame
                => QuicZeroRttTransportParameterUseFailure.UpdatedOneRttFrameValueInZeroRtt,
            _ => QuicZeroRttTransportParameterUseFailure.MissingRememberedValue,
        };

        return QuicZeroRttTransportParameterUseDecision.Reject(
            failure,
            valueSource == QuicZeroRttTransportParameterValueSource.Unknown
                ? null
                : QuicTransportErrorCode.ProtocolViolation);
    }

    private static QuicZeroRttTransportParameterAcceptanceDecision RejectIfRequiredLimitReduced(
        string parameterName,
        ulong rememberedValue,
        ulong currentValue)
    {
        return currentValue < rememberedValue
            ? QuicZeroRttTransportParameterAcceptanceDecision.Reject(
                QuicZeroRttTransportParameterAcceptanceFailure.ReducedRequiredLimit,
                parameterName)
            : QuicZeroRttTransportParameterAcceptanceDecision.Accept;
    }

    private static QuicZeroRttTransportParameterAcceptanceDecision RejectIfRememberedOptionalValueReduced(
        string parameterName,
        ulong? rememberedValue,
        ulong currentValue)
    {
        return rememberedValue.HasValue && currentValue < rememberedValue.Value
            ? QuicZeroRttTransportParameterAcceptanceDecision.Reject(
                QuicZeroRttTransportParameterAcceptanceFailure.ReducedOptionalValue,
                parameterName)
            : QuicZeroRttTransportParameterAcceptanceDecision.Accept;
    }

    private static ulong EffectiveActiveConnectionIdLimit(QuicTransportParameters parameters)
    {
        return parameters.ActiveConnectionIdLimit ?? QuicConnectionPeerConnectionIdState.DefaultActiveConnectionIdLimit;
    }

    private static QuicPreferredAddress? ClonePreferredAddress(QuicPreferredAddress? preferredAddress)
    {
        if (preferredAddress is null)
        {
            return null;
        }

        return new QuicPreferredAddress
        {
            IPv4Address = CloneBytes(preferredAddress.IPv4Address) ?? [],
            IPv4Port = preferredAddress.IPv4Port,
            IPv6Address = CloneBytes(preferredAddress.IPv6Address) ?? [],
            IPv6Port = preferredAddress.IPv6Port,
            ConnectionId = CloneBytes(preferredAddress.ConnectionId) ?? [],
            StatelessResetToken = CloneBytes(preferredAddress.StatelessResetToken) ?? [],
        };
    }

    private static byte[]? CloneBytes(byte[]? bytes)
    {
        return bytes?.ToArray();
    }
}

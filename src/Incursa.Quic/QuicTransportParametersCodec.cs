using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// Parses and formats QUIC transport parameters as extension bytes.
/// </summary>
internal static class QuicTransportParametersCodec
{
    /// <summary>
    /// The TLS extension type codepoint for quic_transport_parameters.
    /// </summary>
    internal const ushort QuicTransportParametersExtensionType = 57;

    /// <summary>
    /// Gets whether the registry marks quic_transport_parameters as recommended.
    /// </summary>
    internal const bool QuicTransportParametersRecommended = true;

    /// <summary>
    /// Gets whether the registry lists quic_transport_parameters for ClientHello.
    /// </summary>
    internal const bool QuicTransportParametersClientHello = true;

    /// <summary>
    /// Gets whether the registry lists quic_transport_parameters for EncryptedExtensions.
    /// </summary>
    internal const bool QuicTransportParametersEncryptedExtensions = true;

    // RFC 9000 transport-parameter IDs handled by this codec.
    // 0x00 original_destination_connection_id, 0x01 max_idle_timeout, 0x02 stateless_reset_token,
    // 0x03 max_udp_payload_size, 0x04 initial_max_data, 0x05 initial_max_stream_data_bidi_local,
    // 0x06 initial_max_stream_data_bidi_remote, 0x07 initial_max_stream_data_uni,
    // 0x08 initial_max_streams_bidi, 0x09 initial_max_streams_uni, 0x0B max_ack_delay,
    // 0x0C disable_active_migration, 0x0D preferred_address, 0x0E active_connection_id_limit,
    // 0x0F initial_source_connection_id, 0x10 retry_source_connection_id.
    private const ulong OriginalDestinationConnectionIdId = 0x00;
    private const ulong MaxIdleTimeoutId = 0x01;
    private const ulong StatelessResetTokenId = 0x02;
    private const ulong MaxUdpPayloadSizeId = 0x03;
    private const ulong InitialMaxDataId = 0x04;
    private const ulong InitialMaxStreamDataBidiLocalId = 0x05;
    private const ulong InitialMaxStreamDataBidiRemoteId = 0x06;
    private const ulong InitialMaxStreamDataUniId = 0x07;
    private const ulong InitialMaxStreamsBidiId = 0x08;
    private const ulong InitialMaxStreamsUniId = 0x09;
    private const ulong MaxAckDelayId = 0x0B;
    private const ulong DisableActiveMigrationId = 0x0C;
    private const ulong PreferredAddressId = 0x0D;
    private const ulong ActiveConnectionIdLimitId = 0x0E;
    private const ulong InitialSourceConnectionIdId = 0x0F;
    private const ulong RetrySourceConnectionIdId = 0x10;

    /// <summary>
    /// Varint stream-count parameters can only use the low 60 bits.
    /// </summary>
    private const int MaximumStreamLimitBitCount = 60;

    /// <summary>
    /// The maximum stream-count parameter value accepted by this codec.
    /// </summary>
    private const ulong MaximumStreamLimit = 1UL << MaximumStreamLimitBitCount;

    /// <summary>
    /// RFC 9000 sets the minimum active_connection_id_limit to 2.
    /// </summary>
    private const ulong MinimumActiveConnectionIdLimit = 2;

    /// <summary>
    /// Preferred-address IPv4 addresses are 4 bytes.
    /// </summary>
    private const int IPv4AddressLength = 4;

    /// <summary>
    /// Preferred-address ports are 2 bytes.
    /// </summary>
    private const int PortLength = 2;

    /// <summary>
    /// Preferred-address IPv6 addresses are 16 bytes.
    /// </summary>
    private const int IPv6AddressLength = 16;

    /// <summary>
    /// Preferred-address connection-ID lengths are encoded in a single byte.
    /// </summary>
    private const int ConnectionIdLengthLength = 1;

    /// <summary>
    /// The fixed preferred-address prefix before the variable-length connection ID.
    /// </summary>
    private const int PreferredAddressMinimumLength = IPv4AddressLength + PortLength + IPv6AddressLength + PortLength + ConnectionIdLengthLength + StatelessResetTokenLength;

    /// <summary>
    /// RFC 9000 caps the preferred-address connection ID at 20 bytes.
    /// </summary>
    private const int PreferredAddressMaximumConnectionIdLength = 20;

    /// <summary>
    /// RFC 9000 stateless reset tokens are 16 bytes.
    /// </summary>
    private const int StatelessResetTokenLength = 16;

    /// <summary>
    /// Parses a transport-parameter extension value into a structured view.
    /// </summary>
    internal static bool TryParseTransportParameters(
        ReadOnlySpan<byte> encoded,
        QuicTransportParameterRole receiverRole,
        out QuicTransportParameters parameters)
    {
        parameters = new QuicTransportParameters();
        List<ulong> seenParameterIds = [];

        ReadOnlySpan<byte> remaining = encoded;
        while (!remaining.IsEmpty)
        {
            if (!QuicVariableLengthInteger.TryParse(remaining, out ulong id, out int idBytes))
            {
                return false;
            }

            remaining = remaining[idBytes..];

            if (!QuicVariableLengthInteger.TryParse(remaining, out ulong length, out int lengthBytes))
            {
                return false;
            }

            remaining = remaining[lengthBytes..];
            if (length > (ulong)remaining.Length)
            {
                return false;
            }

            ReadOnlySpan<byte> value = remaining[..(int)length];
            remaining = remaining[(int)length..];

            if (!TryTrackTransportParameterId(seenParameterIds, id)
                || !TryApplyTransportParameter(parameters, id, value, receiverRole))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Formats a structured transport-parameter view into an extension value.
    /// </summary>
    internal static bool TryFormatTransportParameters(
        QuicTransportParameters parameters,
        QuicTransportParameterRole senderRole,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        int index = 0;
        if (!TryWriteServerOnlyParameter(OriginalDestinationConnectionIdId, parameters.OriginalDestinationConnectionId, senderRole, destination, ref index))
        {
            return false;
        }

        if (parameters.MaxIdleTimeout is ulong maxIdleTimeout
            && !TryWriteVarintParameter(MaxIdleTimeoutId, maxIdleTimeout, destination, ref index))
        {
            return false;
        }

        if (!TryWriteServerOnlyParameter(StatelessResetTokenId, parameters.StatelessResetToken, senderRole, destination, ref index))
        {
            return false;
        }

        if (parameters.MaxUdpPayloadSize is ulong maxUdpPayloadSize
            && !TryWriteVarintParameter(MaxUdpPayloadSizeId, maxUdpPayloadSize, destination, ref index))
        {
            return false;
        }

        if (parameters.InitialMaxData is ulong initialMaxData
            && !TryWriteVarintParameter(InitialMaxDataId, initialMaxData, destination, ref index))
        {
            return false;
        }

        if (parameters.InitialMaxStreamDataBidiLocal is ulong initialMaxStreamDataBidiLocal
            && !TryWriteVarintParameter(InitialMaxStreamDataBidiLocalId, initialMaxStreamDataBidiLocal, destination, ref index))
        {
            return false;
        }

        if (parameters.InitialMaxStreamDataBidiRemote is ulong initialMaxStreamDataBidiRemote
            && !TryWriteVarintParameter(InitialMaxStreamDataBidiRemoteId, initialMaxStreamDataBidiRemote, destination, ref index))
        {
            return false;
        }

        if (parameters.InitialMaxStreamDataUni is ulong initialMaxStreamDataUni
            && !TryWriteVarintParameter(InitialMaxStreamDataUniId, initialMaxStreamDataUni, destination, ref index))
        {
            return false;
        }

        if (parameters.InitialMaxStreamsBidi is ulong initialMaxStreamsBidi)
        {
            if (initialMaxStreamsBidi > MaximumStreamLimit
                || !TryWriteVarintParameter(InitialMaxStreamsBidiId, initialMaxStreamsBidi, destination, ref index))
            {
                return false;
            }
        }

        if (parameters.InitialMaxStreamsUni is ulong initialMaxStreamsUni)
        {
            if (initialMaxStreamsUni > MaximumStreamLimit
                || !TryWriteVarintParameter(InitialMaxStreamsUniId, initialMaxStreamsUni, destination, ref index))
            {
                return false;
            }
        }

        if (parameters.MaxAckDelay is ulong maxAckDelay
            && !TryWriteVarintParameter(MaxAckDelayId, maxAckDelay, destination, ref index))
        {
            return false;
        }

        if (parameters.DisableActiveMigration
            && !TryWriteEmptyParameter(DisableActiveMigrationId, destination, ref index))
        {
            return false;
        }

        if (parameters.PreferredAddress is not null
            && !TryWritePreferredAddressParameter(parameters.PreferredAddress, senderRole, destination, ref index))
        {
            return false;
        }

        if (parameters.ActiveConnectionIdLimit is ulong activeConnectionIdLimit
            && !TryWriteVarintParameter(ActiveConnectionIdLimitId, activeConnectionIdLimit, destination, ref index))
        {
            return false;
        }

        if (parameters.InitialSourceConnectionId is not null
            && !TryWriteOpaqueParameter(InitialSourceConnectionIdId, parameters.InitialSourceConnectionId, destination, ref index))
        {
            return false;
        }

        if (!TryWriteServerOnlyParameter(RetrySourceConnectionIdId, parameters.RetrySourceConnectionId, senderRole, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Validates that peer transport parameters match the connection IDs observed during handshake.
    /// </summary>
    internal static bool TryValidateConnectionIdBindings(
        QuicTransportParameterRole receiverRole,
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        bool usedRetry,
        ReadOnlySpan<byte> retrySourceConnectionId,
        QuicTransportParameters peerParameters,
        out QuicConnectionIdBindingValidationError validationError)
    {
        validationError = QuicConnectionIdBindingValidationError.None;

        if (peerParameters is null)
        {
            return false;
        }

        if (receiverRole == QuicTransportParameterRole.Client)
        {
            if (peerParameters.OriginalDestinationConnectionId is null)
            {
                validationError = QuicConnectionIdBindingValidationError.MissingOriginalDestinationConnectionId;
                return false;
            }

            if (!peerParameters.OriginalDestinationConnectionId.AsSpan().SequenceEqual(initialDestinationConnectionId))
            {
                validationError = QuicConnectionIdBindingValidationError.OriginalDestinationConnectionIdMismatch;
                return false;
            }

            if (peerParameters.InitialSourceConnectionId is null)
            {
                validationError = QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId;
                return false;
            }

            if (!peerParameters.InitialSourceConnectionId.AsSpan().SequenceEqual(initialSourceConnectionId))
            {
                validationError = QuicConnectionIdBindingValidationError.InitialSourceConnectionIdMismatch;
                return false;
            }

            if (peerParameters.RetrySourceConnectionId is null)
            {
                if (usedRetry)
                {
                    validationError = QuicConnectionIdBindingValidationError.MissingRetrySourceConnectionId;
                    return false;
                }
            }
            else
            {
                if (!usedRetry)
                {
                    validationError = QuicConnectionIdBindingValidationError.UnexpectedRetrySourceConnectionId;
                    return false;
                }

                if (!peerParameters.RetrySourceConnectionId.AsSpan().SequenceEqual(retrySourceConnectionId))
                {
                    validationError = QuicConnectionIdBindingValidationError.RetrySourceConnectionIdMismatch;
                    return false;
                }
            }

            return true;
        }

        if (peerParameters.InitialSourceConnectionId is null)
        {
            validationError = QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId;
            return false;
        }

        if (!peerParameters.InitialSourceConnectionId.AsSpan().SequenceEqual(initialSourceConnectionId))
        {
            validationError = QuicConnectionIdBindingValidationError.InitialSourceConnectionIdMismatch;
            return false;
        }

        return true;
    }

    private static bool TryApplyTransportParameter(
        QuicTransportParameters parameters,
        ulong id,
        ReadOnlySpan<byte> value,
        QuicTransportParameterRole receiverRole)
    {
        switch (id)
        {
            case OriginalDestinationConnectionIdId:
                if (receiverRole == QuicTransportParameterRole.Server)
                {
                    return false;
                }

                parameters.OriginalDestinationConnectionId = value.ToArray();
                return true;

            case MaxIdleTimeoutId:
                if (!TryParseVarintValue(value, out ulong maxIdleTimeout))
                {
                    return false;
                }

                parameters.MaxIdleTimeout = maxIdleTimeout;
                return true;

            case StatelessResetTokenId:
                if (receiverRole == QuicTransportParameterRole.Server || value.Length != StatelessResetTokenLength)
                {
                    return false;
                }

                parameters.StatelessResetToken = value.ToArray();
                return true;

            case MaxUdpPayloadSizeId:
                if (!TryParseVarintValue(value, out ulong maxUdpPayloadSize))
                {
                    return false;
                }

                parameters.MaxUdpPayloadSize = maxUdpPayloadSize;
                return true;

            case InitialMaxDataId:
                if (!TryParseVarintValue(value, out ulong initialMaxData))
                {
                    return false;
                }

                parameters.InitialMaxData = initialMaxData;
                return true;

            case InitialMaxStreamDataBidiLocalId:
                if (!TryParseVarintValue(value, out ulong initialMaxStreamDataBidiLocal))
                {
                    return false;
                }

                parameters.InitialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal;
                return true;

            case InitialMaxStreamDataBidiRemoteId:
                if (!TryParseVarintValue(value, out ulong initialMaxStreamDataBidiRemote))
                {
                    return false;
                }

                parameters.InitialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote;
                return true;

            case InitialMaxStreamDataUniId:
                if (!TryParseVarintValue(value, out ulong initialMaxStreamDataUni))
                {
                    return false;
                }

                parameters.InitialMaxStreamDataUni = initialMaxStreamDataUni;
                return true;

            case InitialMaxStreamsBidiId:
                if (!TryParseVarintValue(value, out ulong initialMaxStreamsBidi))
                {
                    return false;
                }

                if (initialMaxStreamsBidi > MaximumStreamLimit)
                {
                    return false;
                }

                parameters.InitialMaxStreamsBidi = initialMaxStreamsBidi;
                return true;

            case InitialMaxStreamsUniId:
                if (!TryParseVarintValue(value, out ulong initialMaxStreamsUni))
                {
                    return false;
                }

                if (initialMaxStreamsUni > MaximumStreamLimit)
                {
                    return false;
                }

                parameters.InitialMaxStreamsUni = initialMaxStreamsUni;
                return true;

            case MaxAckDelayId:
                if (!TryParseVarintValue(value, out ulong maxAckDelay))
                {
                    return false;
                }

                parameters.MaxAckDelay = maxAckDelay;
                return true;

            case DisableActiveMigrationId:
                if (!value.IsEmpty)
                {
                    return false;
                }

                parameters.DisableActiveMigration = true;
                return true;

            case PreferredAddressId:
                if (receiverRole == QuicTransportParameterRole.Server)
                {
                    return false;
                }

                if (!TryParsePreferredAddress(value, out QuicPreferredAddress? preferredAddress))
                {
                    return false;
                }

                parameters.PreferredAddress = preferredAddress;
                return true;

            case ActiveConnectionIdLimitId:
                if (!TryParseVarintValue(value, out ulong activeConnectionIdLimit))
                {
                    return false;
                }

        if (activeConnectionIdLimit < MinimumActiveConnectionIdLimit)
        {
            return false;
        }

                parameters.ActiveConnectionIdLimit = activeConnectionIdLimit;
                return true;

            case InitialSourceConnectionIdId:
                parameters.InitialSourceConnectionId = value.ToArray();
                return true;

            case RetrySourceConnectionIdId:
                if (receiverRole == QuicTransportParameterRole.Server)
                {
                    return false;
                }

                parameters.RetrySourceConnectionId = value.ToArray();
                return true;

            default:
                return true;
        }
    }

    private static bool TryTrackTransportParameterId(List<ulong> seenParameterIds, ulong id)
    {
        foreach (ulong seenParameterId in seenParameterIds)
        {
            if (seenParameterId == id)
            {
                return false;
            }
        }

        seenParameterIds.Add(id);
        return true;
    }

    private static bool TryParseVarintValue(ReadOnlySpan<byte> value, out ulong parsedValue)
    {
        if (!QuicVariableLengthInteger.TryParse(value, out parsedValue, out int bytesConsumed) || bytesConsumed != value.Length)
        {
            return false;
        }

        return true;
    }

    private static bool TryParsePreferredAddress(ReadOnlySpan<byte> value, out QuicPreferredAddress? preferredAddress)
    {
        preferredAddress = null;

        if (value.Length < PreferredAddressMinimumLength)
        {
            return false;
        }

        int index = 0;
        byte[] ipv4Address = value.Slice(index, IPv4AddressLength).ToArray();
        index += IPv4AddressLength;

        ushort ipv4Port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(index, PortLength));
        index += PortLength;

        byte[] ipv6Address = value.Slice(index, IPv6AddressLength).ToArray();
        index += IPv6AddressLength;

        ushort ipv6Port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(index, PortLength));
        index += PortLength;

        int connectionIdLength = value[index++];
        if (connectionIdLength is 0 or > PreferredAddressMaximumConnectionIdLength)
        {
            return false;
        }

        int expectedLength = PreferredAddressMinimumLength + connectionIdLength;
        if (value.Length != expectedLength)
        {
            return false;
        }

        byte[] connectionId = value.Slice(index, connectionIdLength).ToArray();
        index += connectionIdLength;

        byte[] statelessResetToken = value.Slice(index, StatelessResetTokenLength).ToArray();

        preferredAddress = new QuicPreferredAddress
        {
            IPv4Address = ipv4Address,
            IPv4Port = ipv4Port,
            IPv6Address = ipv6Address,
            IPv6Port = ipv6Port,
            ConnectionId = connectionId,
            StatelessResetToken = statelessResetToken,
        };
        return true;
    }

    private static bool TryWriteServerOnlyParameter(
        ulong id,
        byte[]? value,
        QuicTransportParameterRole senderRole,
        Span<byte> destination,
        ref int index)
    {
        if (value is null)
        {
            return true;
        }

        if (senderRole == QuicTransportParameterRole.Client)
        {
            return false;
        }

        return TryWriteOpaqueParameter(id, value, destination, ref index);
    }

    private static bool TryWriteVarintParameter(
        ulong id,
        ulong value,
        Span<byte> destination,
        ref int index)
    {
        Span<byte> valueBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
        if (!QuicVariableLengthInteger.TryFormat(value, valueBuffer, out int valueBytes))
        {
            return false;
        }

        return TryWriteTuple(id, valueBuffer[..valueBytes], destination, ref index);
    }

    private static bool TryWriteEmptyParameter(
        ulong id,
        Span<byte> destination,
        ref int index)
    {
        return TryWriteTuple(id, ReadOnlySpan<byte>.Empty, destination, ref index);
    }

    private static bool TryWriteOpaqueParameter(
        ulong id,
        ReadOnlySpan<byte> value,
        Span<byte> destination,
        ref int index)
    {
        return TryWriteTuple(id, value, destination, ref index);
    }

    private static bool TryWritePreferredAddressParameter(
        QuicPreferredAddress preferredAddress,
        QuicTransportParameterRole senderRole,
        Span<byte> destination,
        ref int index)
    {
        if (senderRole == QuicTransportParameterRole.Client)
        {
            return false;
        }

        if (preferredAddress.IPv4Address is null
            || preferredAddress.IPv6Address is null
            || preferredAddress.ConnectionId is null
            || preferredAddress.StatelessResetToken is null
            || preferredAddress.IPv4Address.Length != IPv4AddressLength
            || preferredAddress.IPv6Address.Length != IPv6AddressLength
            || preferredAddress.ConnectionId.Length is 0 or > PreferredAddressMaximumConnectionIdLength
            || preferredAddress.StatelessResetToken.Length != StatelessResetTokenLength)
        {
            return false;
        }

        Span<byte> valueBuffer = stackalloc byte[PreferredAddressMinimumLength + PreferredAddressMaximumConnectionIdLength];
        int valueIndex = 0;

        preferredAddress.IPv4Address.CopyTo(valueBuffer);
        valueIndex += IPv4AddressLength;

        BinaryPrimitives.WriteUInt16BigEndian(valueBuffer.Slice(valueIndex, PortLength), preferredAddress.IPv4Port);
        valueIndex += PortLength;

        preferredAddress.IPv6Address.CopyTo(valueBuffer.Slice(valueIndex, IPv6AddressLength));
        valueIndex += IPv6AddressLength;

        BinaryPrimitives.WriteUInt16BigEndian(valueBuffer.Slice(valueIndex, PortLength), preferredAddress.IPv6Port);
        valueIndex += PortLength;

        valueBuffer[valueIndex++] = (byte)preferredAddress.ConnectionId.Length;
        preferredAddress.ConnectionId.CopyTo(valueBuffer.Slice(valueIndex));
        valueIndex += preferredAddress.ConnectionId.Length;

        preferredAddress.StatelessResetToken.CopyTo(valueBuffer.Slice(valueIndex, StatelessResetTokenLength));
        valueIndex += StatelessResetTokenLength;

        return TryWriteTuple(PreferredAddressId, valueBuffer[..valueIndex], destination, ref index);
    }

    private static bool TryWriteTuple(
        ulong id,
        ReadOnlySpan<byte> value,
        Span<byte> destination,
        ref int index)
    {
        Span<byte> idBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
        if (!QuicVariableLengthInteger.TryFormat(id, idBuffer, out int idBytes))
        {
            return false;
        }

        Span<byte> lengthBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
        if (!QuicVariableLengthInteger.TryFormat((ulong)value.Length, lengthBuffer, out int lengthBytes))
        {
            return false;
        }

        int tupleLength = idBytes + lengthBytes + value.Length;
        if (destination.Length - index < tupleLength)
        {
            return false;
        }

        idBuffer[..idBytes].CopyTo(destination.Slice(index));
        index += idBytes;

        lengthBuffer[..lengthBytes].CopyTo(destination.Slice(index));
        index += lengthBytes;

        value.CopyTo(destination.Slice(index));
        index += value.Length;
        return true;
    }
}


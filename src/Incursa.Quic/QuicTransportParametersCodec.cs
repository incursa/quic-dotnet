using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// Parses and formats QUIC transport parameters as extension bytes.
/// </summary>
public static class QuicTransportParametersCodec
{
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
    private const ulong MaximumStreamLimit = 1UL << 60;
    private const int PreferredAddressMinimumLength = 4 + 2 + 16 + 2 + 1 + 16;
    private const int PreferredAddressMaximumConnectionIdLength = 20;
    private const int StatelessResetTokenLength = 16;

    /// <summary>
    /// Parses a transport-parameter extension value into a structured view.
    /// </summary>
    public static bool TryParseTransportParameters(
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
    public static bool TryFormatTransportParameters(
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
    public static bool TryValidateConnectionIdBindings(
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

                if (activeConnectionIdLimit < 2)
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
        byte[] ipv4Address = value.Slice(index, 4).ToArray();
        index += 4;

        ushort ipv4Port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(index, 2));
        index += 2;

        byte[] ipv6Address = value.Slice(index, 16).ToArray();
        index += 16;

        ushort ipv6Port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(index, 2));
        index += 2;

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
        Span<byte> valueBuffer = stackalloc byte[8];
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
            || preferredAddress.IPv4Address.Length != 4
            || preferredAddress.IPv6Address.Length != 16
            || preferredAddress.ConnectionId.Length is 0 or > PreferredAddressMaximumConnectionIdLength
            || preferredAddress.StatelessResetToken.Length != StatelessResetTokenLength)
        {
            return false;
        }

        Span<byte> valueBuffer = stackalloc byte[PreferredAddressMinimumLength + PreferredAddressMaximumConnectionIdLength];
        int valueIndex = 0;

        preferredAddress.IPv4Address.CopyTo(valueBuffer);
        valueIndex += 4;

        BinaryPrimitives.WriteUInt16BigEndian(valueBuffer.Slice(valueIndex, 2), preferredAddress.IPv4Port);
        valueIndex += 2;

        preferredAddress.IPv6Address.CopyTo(valueBuffer.Slice(valueIndex, 16));
        valueIndex += 16;

        BinaryPrimitives.WriteUInt16BigEndian(valueBuffer.Slice(valueIndex, 2), preferredAddress.IPv6Port);
        valueIndex += 2;

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
        Span<byte> idBuffer = stackalloc byte[8];
        if (!QuicVariableLengthInteger.TryFormat(id, idBuffer, out int idBytes))
        {
            return false;
        }

        Span<byte> lengthBuffer = stackalloc byte[8];
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

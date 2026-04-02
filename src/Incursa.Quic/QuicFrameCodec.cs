namespace Incursa.Quic;

/// <summary>
/// Parses and formats selected QUIC frame encodings from packet payload slices.
/// </summary>
public static class QuicFrameCodec
{
    private const ulong PaddingFrameType = 0x00;
    private const ulong PingFrameType = 0x01;
    private const ulong AckFrameType = 0x02;
    private const ulong AckEcnFrameType = 0x03;
    private const ulong ConnectionCloseFrameType = 0x1C;
    private const ulong ResetStreamFrameType = 0x04;
    private const ulong StopSendingFrameType = 0x05;
    private const ulong CryptoFrameType = 0x06;
    private const ulong NewTokenFrameType = 0x07;
    private const ulong MaxDataFrameType = 0x10;
    private const ulong MaxStreamDataFrameType = 0x11;
    private const ulong MaxStreamsBidirectionalFrameType = 0x12;
    private const ulong MaxStreamsUnidirectionalFrameType = 0x13;
    private const ulong DataBlockedFrameType = 0x14;
    private const ulong StreamDataBlockedFrameType = 0x15;
    private const ulong StreamsBlockedBidirectionalFrameType = 0x16;
    private const ulong StreamsBlockedUnidirectionalFrameType = 0x17;
    private const ulong NewConnectionIdFrameType = 0x18;
    private const ulong RetireConnectionIdFrameType = 0x19;
    private const ulong PathChallengeFrameType = 0x1A;
    private const ulong PathResponseFrameType = 0x1B;
    private const ulong MaximumStreamLimit = 1UL << 60;
    private const int MaximumConnectionIdLength = 20;
    private const int StatelessResetTokenLength = 16;
    private const int PathFrameDataLength = 8;

    /// <summary>
    /// Parses a PADDING frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParsePaddingFrame(ReadOnlySpan<byte> packetPayload, out int bytesConsumed)
    {
        bytesConsumed = default;
        return TryParseFixedType(packetPayload, PaddingFrameType, out bytesConsumed);
    }

    /// <summary>
    /// Formats a PADDING frame.
    /// </summary>
    public static bool TryFormatPaddingFrame(Span<byte> destination, out int bytesWritten)
    {
        return TryWriteFixedType(PaddingFrameType, destination, out bytesWritten);
    }

    /// <summary>
    /// Parses a PING frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParsePingFrame(ReadOnlySpan<byte> packetPayload, out int bytesConsumed)
    {
        bytesConsumed = default;
        return TryParseFixedType(packetPayload, PingFrameType, out bytesConsumed);
    }

    /// <summary>
    /// Formats a PING frame.
    /// </summary>
    public static bool TryFormatPingFrame(Span<byte> destination, out int bytesWritten)
    {
        return TryWriteFixedType(PingFrameType, destination, out bytesWritten);
    }

    /// <summary>
    /// Determines whether the specified frame type should elicit an acknowledgment.
    /// </summary>
    public static bool IsAckElicitingFrameType(ulong frameType)
    {
        return frameType != PaddingFrameType
            && frameType != AckFrameType
            && frameType != AckEcnFrameType
            && frameType != ConnectionCloseFrameType;
    }

    /// <summary>
    /// Parses an ACK frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseAckFrame(ReadOnlySpan<byte> packetPayload, out QuicAckFrame frame, out int bytesConsumed)
    {
        frame = new QuicAckFrame();
        bytesConsumed = default;

        if (!QuicVariableLengthInteger.TryParse(packetPayload, out ulong frameTypeValue, out int index))
        {
            return false;
        }

        if (index != 1 || (frameTypeValue != AckFrameType && frameTypeValue != AckEcnFrameType))
        {
            return false;
        }

        if (!TryParseVarint(packetPayload, ref index, out ulong largestAcknowledged)
            || !TryParseVarint(packetPayload, ref index, out ulong ackDelay)
            || !TryParseVarint(packetPayload, ref index, out ulong ackRangeCount)
            || !TryParseVarint(packetPayload, ref index, out ulong firstAckRange))
        {
            return false;
        }

        if (firstAckRange > largestAcknowledged || ackRangeCount > int.MaxValue)
        {
            return false;
        }

        QuicAckRange[] additionalRanges = new QuicAckRange[(int)ackRangeCount];
        ulong previousSmallestAcknowledged = largestAcknowledged - firstAckRange;

        for (int rangeIndex = 0; rangeIndex < additionalRanges.Length; rangeIndex++)
        {
            if (!TryParseVarint(packetPayload, ref index, out ulong gap)
                || !TryParseVarint(packetPayload, ref index, out ulong ackRangeLength))
            {
                return false;
            }

            if (!TryComputeAckRange(previousSmallestAcknowledged, gap, ackRangeLength, out ulong smallestAcknowledged, out ulong largestRangeAcknowledged))
            {
                return false;
            }

            additionalRanges[rangeIndex] = new QuicAckRange(gap, ackRangeLength, smallestAcknowledged, largestRangeAcknowledged);
            previousSmallestAcknowledged = smallestAcknowledged;
        }

        QuicEcnCounts? ecnCounts = null;
        if (frameTypeValue == AckEcnFrameType)
        {
            if (!TryParseVarint(packetPayload, ref index, out ulong ect0Count)
                || !TryParseVarint(packetPayload, ref index, out ulong ect1Count)
                || !TryParseVarint(packetPayload, ref index, out ulong ecnCeCount))
            {
                return false;
            }

            ecnCounts = new QuicEcnCounts(ect0Count, ect1Count, ecnCeCount);
        }

        frame = new QuicAckFrame
        {
            FrameType = (byte)frameTypeValue,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = ackDelay,
            FirstAckRange = firstAckRange,
            AdditionalRanges = additionalRanges,
            EcnCounts = ecnCounts,
        };
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats an ACK frame.
    /// </summary>
    public static bool TryFormatAckFrame(QuicAckFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        if (frame is null)
        {
            return false;
        }

        if (frame.FrameType != AckFrameType && frame.FrameType != AckEcnFrameType)
        {
            return false;
        }

        if (frame.FirstAckRange > frame.LargestAcknowledged)
        {
            return false;
        }

        bool hasEcnCounts = frame.FrameType == AckEcnFrameType;
        if (hasEcnCounts != frame.EcnCounts.HasValue)
        {
            return false;
        }

        QuicAckRange[] additionalRanges = frame.AdditionalRanges ?? [];

        int index = 0;
        if (!TryWriteVarint(frame.FrameType, destination, ref index)
            || !TryWriteVarint(frame.LargestAcknowledged, destination, ref index)
            || !TryWriteVarint(frame.AckDelay, destination, ref index)
            || !TryWriteVarint((ulong)additionalRanges.Length, destination, ref index)
            || !TryWriteVarint(frame.FirstAckRange, destination, ref index))
        {
            return false;
        }

        ulong previousSmallestAcknowledged = frame.LargestAcknowledged - frame.FirstAckRange;

        for (int rangeIndex = 0; rangeIndex < additionalRanges.Length; rangeIndex++)
        {
            QuicAckRange range = additionalRanges[rangeIndex];
            if (!TryComputeAckRange(previousSmallestAcknowledged, range.Gap, range.AckRangeLength, out ulong smallestAcknowledged, out ulong largestRangeAcknowledged))
            {
                return false;
            }

            if (range.SmallestAcknowledged != smallestAcknowledged || range.LargestAcknowledged != largestRangeAcknowledged)
            {
                return false;
            }

            if (!TryWriteVarint(range.Gap, destination, ref index)
                || !TryWriteVarint(range.AckRangeLength, destination, ref index))
            {
                return false;
            }

            previousSmallestAcknowledged = smallestAcknowledged;
        }

        if (frame.EcnCounts is QuicEcnCounts ecnCounts
            && (!TryWriteVarint(ecnCounts.Ect0Count, destination, ref index)
                || !TryWriteVarint(ecnCounts.Ect1Count, destination, ref index)
                || !TryWriteVarint(ecnCounts.EcnCeCount, destination, ref index)))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a RESET_STREAM frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseResetStreamFrame(ReadOnlySpan<byte> packetPayload, out QuicResetStreamFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, ResetStreamFrameType, out int index))
        {
            return false;
        }

        if (!TryParseVarint(packetPayload, ref index, out ulong streamId)
            || !TryParseVarint(packetPayload, ref index, out ulong applicationProtocolErrorCode)
            || !TryParseVarint(packetPayload, ref index, out ulong finalSize))
        {
            return false;
        }

        frame = new QuicResetStreamFrame(streamId, applicationProtocolErrorCode, finalSize);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a RESET_STREAM frame.
    /// </summary>
    public static bool TryFormatResetStreamFrame(QuicResetStreamFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        int index = 0;
        if (!TryWriteVarint(ResetStreamFrameType, destination, ref index)
            || !TryWriteVarint(frame.StreamId, destination, ref index)
            || !TryWriteVarint(frame.ApplicationProtocolErrorCode, destination, ref index)
            || !TryWriteVarint(frame.FinalSize, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a STOP_SENDING frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseStopSendingFrame(ReadOnlySpan<byte> packetPayload, out QuicStopSendingFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, StopSendingFrameType, out int index))
        {
            return false;
        }

        if (!TryParseVarint(packetPayload, ref index, out ulong streamId)
            || !TryParseVarint(packetPayload, ref index, out ulong applicationProtocolErrorCode))
        {
            return false;
        }

        frame = new QuicStopSendingFrame(streamId, applicationProtocolErrorCode);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a STOP_SENDING frame.
    /// </summary>
    public static bool TryFormatStopSendingFrame(QuicStopSendingFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        int index = 0;
        if (!TryWriteVarint(StopSendingFrameType, destination, ref index)
            || !TryWriteVarint(frame.StreamId, destination, ref index)
            || !TryWriteVarint(frame.ApplicationProtocolErrorCode, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a CRYPTO frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseCryptoFrame(ReadOnlySpan<byte> packetPayload, out QuicCryptoFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, CryptoFrameType, out int index))
        {
            return false;
        }

        if (!TryParseVarint(packetPayload, ref index, out ulong offset)
            || !TryParseVarint(packetPayload, ref index, out ulong cryptoDataLength))
        {
            return false;
        }

        if (cryptoDataLength > (ulong)(packetPayload.Length - index))
        {
            return false;
        }

        if (offset > QuicVariableLengthInteger.MaxValue - cryptoDataLength)
        {
            return false;
        }

        frame = new QuicCryptoFrame(offset, packetPayload.Slice(index, (int)cryptoDataLength));
        bytesConsumed = index + (int)cryptoDataLength;
        return true;
    }

    /// <summary>
    /// Formats a CRYPTO frame.
    /// </summary>
    public static bool TryFormatCryptoFrame(QuicCryptoFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        ulong cryptoDataLength = (ulong)frame.CryptoData.Length;
        if (frame.Offset > QuicVariableLengthInteger.MaxValue - cryptoDataLength)
        {
            return false;
        }

        int index = 0;
        if (!TryWriteVarint(CryptoFrameType, destination, ref index)
            || !TryWriteVarint(frame.Offset, destination, ref index)
            || !TryWriteVarint(cryptoDataLength, destination, ref index))
        {
            return false;
        }

        if (destination.Length < index + frame.CryptoData.Length)
        {
            return false;
        }

        frame.CryptoData.CopyTo(destination[index..]);
        bytesWritten = index + frame.CryptoData.Length;
        return true;
    }

    /// <summary>
    /// Formats a STREAM frame.
    /// </summary>
    public static bool TryFormatStreamFrame(
        byte frameType,
        ulong streamId,
        ulong offset,
        ReadOnlySpan<byte> streamData,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (frameType is < 0x08 or > 0x0F)
        {
            return false;
        }

        bool hasOffset = (frameType & 0x04) != 0;
        bool hasLength = (frameType & 0x02) != 0;

        if (!hasOffset && offset != 0)
        {
            return false;
        }

        if (offset > QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length)
        {
            return false;
        }

        int index = 0;
        if (!TryWriteVarint(frameType, destination, ref index)
            || !TryWriteVarint(streamId, destination, ref index))
        {
            return false;
        }

        if (hasOffset && !TryWriteVarint(offset, destination, ref index))
        {
            return false;
        }

        if (hasLength && !TryWriteVarint((ulong)streamData.Length, destination, ref index))
        {
            return false;
        }

        if (destination.Length < index + streamData.Length)
        {
            return false;
        }

        streamData.CopyTo(destination[index..]);
        bytesWritten = index + streamData.Length;
        return true;
    }

    /// <summary>
    /// Parses a NEW_TOKEN frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseNewTokenFrame(ReadOnlySpan<byte> packetPayload, out QuicNewTokenFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, NewTokenFrameType, out int index))
        {
            return false;
        }

        if (!TryParseVarint(packetPayload, ref index, out ulong tokenLength) || tokenLength is 0)
        {
            return false;
        }

        if (tokenLength > (ulong)(packetPayload.Length - index))
        {
            return false;
        }

        frame = new QuicNewTokenFrame(packetPayload.Slice(index, (int)tokenLength));
        bytesConsumed = index + (int)tokenLength;
        return true;
    }

    /// <summary>
    /// Formats a NEW_TOKEN frame.
    /// </summary>
    public static bool TryFormatNewTokenFrame(QuicNewTokenFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        if (frame.Token.IsEmpty)
        {
            return false;
        }

        int index = 0;
        if (!TryWriteVarint(NewTokenFrameType, destination, ref index)
            || !TryWriteVarint((ulong)frame.Token.Length, destination, ref index))
        {
            return false;
        }

        if (destination.Length < index + frame.Token.Length)
        {
            return false;
        }

        frame.Token.CopyTo(destination[index..]);
        bytesWritten = index + frame.Token.Length;
        return true;
    }

    /// <summary>
    /// Parses a MAX_DATA frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseMaxDataFrame(ReadOnlySpan<byte> packetPayload, out QuicMaxDataFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, MaxDataFrameType, out int index)
            || !TryParseVarint(packetPayload, ref index, out ulong maximumData))
        {
            return false;
        }

        frame = new QuicMaxDataFrame(maximumData);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a MAX_DATA frame.
    /// </summary>
    public static bool TryFormatMaxDataFrame(QuicMaxDataFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        int index = 0;
        if (!TryWriteVarint(MaxDataFrameType, destination, ref index)
            || !TryWriteVarint(frame.MaximumData, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a DATA_BLOCKED frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseDataBlockedFrame(ReadOnlySpan<byte> packetPayload, out QuicDataBlockedFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, DataBlockedFrameType, out int index)
            || !TryParseVarint(packetPayload, ref index, out ulong maximumData))
        {
            return false;
        }

        frame = new QuicDataBlockedFrame(maximumData);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a DATA_BLOCKED frame.
    /// </summary>
    public static bool TryFormatDataBlockedFrame(QuicDataBlockedFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        int index = 0;
        if (!TryWriteVarint(DataBlockedFrameType, destination, ref index)
            || !TryWriteVarint(frame.MaximumData, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a STREAM_DATA_BLOCKED frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseStreamDataBlockedFrame(ReadOnlySpan<byte> packetPayload, out QuicStreamDataBlockedFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, StreamDataBlockedFrameType, out int index)
            || !TryParseVarint(packetPayload, ref index, out ulong streamId)
            || !TryParseVarint(packetPayload, ref index, out ulong maximumStreamData))
        {
            return false;
        }

        frame = new QuicStreamDataBlockedFrame(streamId, maximumStreamData);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a STREAM_DATA_BLOCKED frame.
    /// </summary>
    public static bool TryFormatStreamDataBlockedFrame(QuicStreamDataBlockedFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        int index = 0;
        if (!TryWriteVarint(StreamDataBlockedFrameType, destination, ref index)
            || !TryWriteVarint(frame.StreamId, destination, ref index)
            || !TryWriteVarint(frame.MaximumStreamData, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a MAX_STREAM_DATA frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseMaxStreamDataFrame(ReadOnlySpan<byte> packetPayload, out QuicMaxStreamDataFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, MaxStreamDataFrameType, out int index)
            || !TryParseVarint(packetPayload, ref index, out ulong streamId)
            || !TryParseVarint(packetPayload, ref index, out ulong maximumStreamData))
        {
            return false;
        }

        frame = new QuicMaxStreamDataFrame(streamId, maximumStreamData);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a MAX_STREAM_DATA frame.
    /// </summary>
    public static bool TryFormatMaxStreamDataFrame(QuicMaxStreamDataFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        int index = 0;
        if (!TryWriteVarint(MaxStreamDataFrameType, destination, ref index)
            || !TryWriteVarint(frame.StreamId, destination, ref index)
            || !TryWriteVarint(frame.MaximumStreamData, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a MAX_STREAMS frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseMaxStreamsFrame(ReadOnlySpan<byte> packetPayload, out QuicMaxStreamsFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseStreamLimitFrame(
                packetPayload,
                MaxStreamsBidirectionalFrameType,
                MaxStreamsUnidirectionalFrameType,
                out bool isBidirectional,
                out ulong maximumStreams,
                out int index))
        {
            return false;
        }

        frame = new QuicMaxStreamsFrame(isBidirectional, maximumStreams);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a MAX_STREAMS frame.
    /// </summary>
    public static bool TryFormatMaxStreamsFrame(QuicMaxStreamsFrame frame, Span<byte> destination, out int bytesWritten)
    {
        return TryFormatStreamLimitFrame(
            frame.IsBidirectional,
            frame.MaximumStreams,
            MaxStreamsBidirectionalFrameType,
            MaxStreamsUnidirectionalFrameType,
            destination,
            out bytesWritten);
    }

    /// <summary>
    /// Parses a STREAMS_BLOCKED frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseStreamsBlockedFrame(ReadOnlySpan<byte> packetPayload, out QuicStreamsBlockedFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseStreamLimitFrame(
                packetPayload,
                StreamsBlockedBidirectionalFrameType,
                StreamsBlockedUnidirectionalFrameType,
                out bool isBidirectional,
                out ulong maximumStreams,
                out int index))
        {
            return false;
        }

        frame = new QuicStreamsBlockedFrame(isBidirectional, maximumStreams);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a STREAMS_BLOCKED frame.
    /// </summary>
    public static bool TryFormatStreamsBlockedFrame(QuicStreamsBlockedFrame frame, Span<byte> destination, out int bytesWritten)
    {
        return TryFormatStreamLimitFrame(
            frame.IsBidirectional,
            frame.MaximumStreams,
            StreamsBlockedBidirectionalFrameType,
            StreamsBlockedUnidirectionalFrameType,
            destination,
            out bytesWritten);
    }

    /// <summary>
    /// Parses a NEW_CONNECTION_ID frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseNewConnectionIdFrame(ReadOnlySpan<byte> packetPayload, out QuicNewConnectionIdFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, NewConnectionIdFrameType, out int index)
            || !TryParseVarint(packetPayload, ref index, out ulong sequenceNumber)
            || !TryParseVarint(packetPayload, ref index, out ulong retirePriorTo)
            || !TryParseVarint(packetPayload, ref index, out ulong connectionIdLengthValue))
        {
            return false;
        }

        if (connectionIdLengthValue is 0 or > MaximumConnectionIdLength)
        {
            return false;
        }

        int connectionIdLength = (int)connectionIdLengthValue;
        int remainingLength = packetPayload.Length - index;
        if (remainingLength < connectionIdLength + StatelessResetTokenLength)
        {
            return false;
        }

        if (retirePriorTo > sequenceNumber)
        {
            return false;
        }

        ReadOnlySpan<byte> connectionId = packetPayload.Slice(index, connectionIdLength);
        index += connectionIdLength;
        ReadOnlySpan<byte> statelessResetToken = packetPayload.Slice(index, StatelessResetTokenLength);
        index += StatelessResetTokenLength;

        frame = new QuicNewConnectionIdFrame(sequenceNumber, retirePriorTo, connectionId, statelessResetToken);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a NEW_CONNECTION_ID frame.
    /// </summary>
    public static bool TryFormatNewConnectionIdFrame(QuicNewConnectionIdFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        if (frame.ConnectionId.Length is 0 or > MaximumConnectionIdLength
            || frame.StatelessResetToken.Length != StatelessResetTokenLength
            || frame.RetirePriorTo > frame.SequenceNumber)
        {
            return false;
        }

        int index = 0;
        if (!TryWriteVarint(NewConnectionIdFrameType, destination, ref index)
            || !TryWriteVarint(frame.SequenceNumber, destination, ref index)
            || !TryWriteVarint(frame.RetirePriorTo, destination, ref index))
        {
            return false;
        }

        if (destination.Length < index + 1 + frame.ConnectionId.Length + StatelessResetTokenLength)
        {
            return false;
        }

        destination[index++] = (byte)frame.ConnectionId.Length;
        frame.ConnectionId.CopyTo(destination[index..]);
        index += frame.ConnectionId.Length;
        frame.StatelessResetToken.CopyTo(destination[index..]);
        index += StatelessResetTokenLength;

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a RETIRE_CONNECTION_ID frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseRetireConnectionIdFrame(ReadOnlySpan<byte> packetPayload, out QuicRetireConnectionIdFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, RetireConnectionIdFrameType, out int index)
            || !TryParseVarint(packetPayload, ref index, out ulong sequenceNumber))
        {
            return false;
        }

        frame = new QuicRetireConnectionIdFrame(sequenceNumber);
        bytesConsumed = index;
        return true;
    }

    /// <summary>
    /// Formats a RETIRE_CONNECTION_ID frame.
    /// </summary>
    public static bool TryFormatRetireConnectionIdFrame(QuicRetireConnectionIdFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        int index = 0;
        if (!TryWriteVarint(RetireConnectionIdFrameType, destination, ref index)
            || !TryWriteVarint(frame.SequenceNumber, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    /// <summary>
    /// Parses a PATH_CHALLENGE frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParsePathChallengeFrame(ReadOnlySpan<byte> packetPayload, out QuicPathChallengeFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, PathChallengeFrameType, out int index))
        {
            return false;
        }

        if (packetPayload.Length - index < PathFrameDataLength)
        {
            return false;
        }

        frame = new QuicPathChallengeFrame(packetPayload.Slice(index, PathFrameDataLength));
        bytesConsumed = index + PathFrameDataLength;
        return true;
    }

    /// <summary>
    /// Formats a PATH_CHALLENGE frame.
    /// </summary>
    public static bool TryFormatPathChallengeFrame(QuicPathChallengeFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        if (frame.Data.Length != PathFrameDataLength)
        {
            return false;
        }

        int index = 0;
        if (!TryWriteVarint(PathChallengeFrameType, destination, ref index))
        {
            return false;
        }

        if (destination.Length < index + PathFrameDataLength)
        {
            return false;
        }

        frame.Data.CopyTo(destination[index..]);
        bytesWritten = index + PathFrameDataLength;
        return true;
    }

    /// <summary>
    /// Parses a PATH_RESPONSE frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParsePathResponseFrame(ReadOnlySpan<byte> packetPayload, out QuicPathResponseFrame frame, out int bytesConsumed)
    {
        frame = default;
        bytesConsumed = default;

        if (!TryParseFixedType(packetPayload, PathResponseFrameType, out int index))
        {
            return false;
        }

        if (packetPayload.Length - index < PathFrameDataLength)
        {
            return false;
        }

        frame = new QuicPathResponseFrame(packetPayload.Slice(index, PathFrameDataLength));
        bytesConsumed = index + PathFrameDataLength;
        return true;
    }

    /// <summary>
    /// Formats a PATH_RESPONSE frame.
    /// </summary>
    public static bool TryFormatPathResponseFrame(QuicPathResponseFrame frame, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        if (frame.Data.Length != PathFrameDataLength)
        {
            return false;
        }

        int index = 0;
        if (!TryWriteVarint(PathResponseFrameType, destination, ref index))
        {
            return false;
        }

        if (destination.Length < index + PathFrameDataLength)
        {
            return false;
        }

        frame.Data.CopyTo(destination[index..]);
        bytesWritten = index + PathFrameDataLength;
        return true;
    }

    private static bool TryParseFixedType(ReadOnlySpan<byte> packetPayload, ulong expectedTypeValue, out int bytesConsumed)
    {
        bytesConsumed = default;

        if (!QuicVariableLengthInteger.TryParse(packetPayload, out ulong frameTypeValue, out int index))
        {
            return false;
        }

        if (index != 1 || frameTypeValue != expectedTypeValue)
        {
            return false;
        }

        bytesConsumed = index;
        return true;
    }

    private static bool TryParseVarint(ReadOnlySpan<byte> packetPayload, ref int index, out ulong value)
    {
        if (!QuicVariableLengthInteger.TryParse(packetPayload[index..], out value, out int bytesConsumed))
        {
            return false;
        }

        index += bytesConsumed;
        return true;
    }

    private static bool TryWriteFixedType(ulong frameTypeValue, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;
        return TryWriteVarint(frameTypeValue, destination, ref bytesWritten);
    }

    private static bool TryParseStreamLimitFrame(
        ReadOnlySpan<byte> packetPayload,
        ulong bidirectionalFrameType,
        ulong unidirectionalFrameType,
        out bool isBidirectional,
        out ulong maximumStreams,
        out int bytesConsumed)
    {
        isBidirectional = default;
        maximumStreams = default;
        bytesConsumed = default;

        if (!QuicVariableLengthInteger.TryParse(packetPayload, out ulong frameTypeValue, out int index)
            || index != 1
            || (frameTypeValue != bidirectionalFrameType && frameTypeValue != unidirectionalFrameType))
        {
            return false;
        }

        if (!TryParseVarint(packetPayload, ref index, out maximumStreams) || maximumStreams > MaximumStreamLimit)
        {
            return false;
        }

        isBidirectional = frameTypeValue == bidirectionalFrameType;
        bytesConsumed = index;
        return true;
    }

    private static bool TryFormatStreamLimitFrame(
        bool isBidirectional,
        ulong maximumStreams,
        ulong bidirectionalFrameType,
        ulong unidirectionalFrameType,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (maximumStreams > MaximumStreamLimit)
        {
            return false;
        }

        int index = 0;
        ulong frameType = isBidirectional ? bidirectionalFrameType : unidirectionalFrameType;
        if (!TryWriteVarint(frameType, destination, ref index)
            || !TryWriteVarint(maximumStreams, destination, ref index))
        {
            return false;
        }

        bytesWritten = index;
        return true;
    }

    private static bool TryWriteVarint(ulong value, Span<byte> destination, ref int index)
    {
        if (!QuicVariableLengthInteger.TryFormat(value, destination[index..], out int bytesWritten))
        {
            return false;
        }

        index += bytesWritten;
        return true;
    }

    private static bool TryComputeAckRange(
        ulong previousSmallestAcknowledged,
        ulong gap,
        ulong ackRangeLength,
        out ulong smallestAcknowledged,
        out ulong largestAcknowledged)
    {
        smallestAcknowledged = default;
        largestAcknowledged = default;

        if (previousSmallestAcknowledged < gap + 2)
        {
            return false;
        }

        largestAcknowledged = previousSmallestAcknowledged - gap - 2;
        if (largestAcknowledged < ackRangeLength)
        {
            return false;
        }

        smallestAcknowledged = largestAcknowledged - ackRangeLength;
        return true;
    }
}

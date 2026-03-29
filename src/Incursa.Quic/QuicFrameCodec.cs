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
    private const ulong ResetStreamFrameType = 0x04;
    private const ulong StopSendingFrameType = 0x05;

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

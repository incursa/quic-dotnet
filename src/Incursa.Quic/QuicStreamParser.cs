namespace Incursa.Quic;

/// <summary>
/// Parses QUIC stream identifiers and STREAM frames from byte spans.
/// </summary>
public static class QuicStreamParser
{
    /// <summary>
    /// Parses a stream identifier from the start of a byte span.
    /// </summary>
    public static bool TryParseStreamIdentifier(ReadOnlySpan<byte> encoded, out QuicStreamId streamId, out int bytesConsumed)
    {
        if (!QuicVariableLengthInteger.TryParse(encoded, out ulong value, out bytesConsumed))
        {
            streamId = default;
            return false;
        }

        streamId = new QuicStreamId(value);
        return true;
    }

    /// <summary>
    /// Parses a STREAM frame from the start of a packet payload slice.
    /// </summary>
    public static bool TryParseStreamFrame(ReadOnlySpan<byte> packetPayload, out QuicStreamFrame frame)
    {
        frame = default;

        if (!QuicVariableLengthInteger.TryParse(packetPayload, out ulong frameTypeValue, out int index))
        {
            return false;
        }

        if (index != 1 || frameTypeValue < 0x08 || frameTypeValue > 0x0F)
        {
            return false;
        }

        byte frameType = (byte)frameTypeValue;

        if (!TryParseStreamIdentifier(packetPayload.Slice(index), out QuicStreamId streamId, out int streamIdBytes))
        {
            return false;
        }

        index += streamIdBytes;

        bool hasOffset = (frameType & 0x04) != 0;
        ulong offset = 0;
        if (hasOffset)
        {
            if (!QuicVariableLengthInteger.TryParse(packetPayload.Slice(index), out offset, out int offsetBytes))
            {
                return false;
            }

            index += offsetBytes;
        }

        bool hasLength = (frameType & 0x02) != 0;
        bool fin = (frameType & 0x01) != 0;
        ulong length = 0;
        ReadOnlySpan<byte> streamData;
        int consumedLength;

        if (hasLength)
        {
            if (!QuicVariableLengthInteger.TryParse(packetPayload.Slice(index), out length, out int lengthBytes))
            {
                return false;
            }

            index += lengthBytes;

            if (length > (ulong)(packetPayload.Length - index))
            {
                return false;
            }

            if (offset > QuicVariableLengthInteger.MaxValue - length)
            {
                return false;
            }

            streamData = packetPayload.Slice(index, (int)length);
            consumedLength = index + (int)length;
        }
        else
        {
            streamData = packetPayload.Slice(index);

            if (offset > QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length)
            {
                return false;
            }

            consumedLength = packetPayload.Length;
        }

        frame = new QuicStreamFrame(
            frameType,
            streamId,
            hasOffset,
            offset,
            hasLength,
            length,
            fin,
            streamData,
            consumedLength);
        return true;
    }
}

using System.Buffers;

namespace Incursa.Quic.Http3;

/// <summary>
/// Writes RFC 9114 HTTP/3 frames.
/// </summary>
public static class Http3FrameWriter
{
    /// <summary>
    /// Writes a DATA frame.
    /// </summary>
    public static byte[] WriteData(ReadOnlySpan<byte> data)
    {
        return WriteFrame((ulong)Http3FrameType.Data, data);
    }

    internal static void WriteData(IBufferWriter<byte> writer, ReadOnlySpan<byte> data)
    {
        WriteFrame(writer, (ulong)Http3FrameType.Data, data);
    }

    /// <summary>
    /// Writes a HEADERS frame.
    /// </summary>
    public static byte[] WriteHeaders(ReadOnlySpan<byte> encodedFieldSection)
    {
        return WriteFrame((ulong)Http3FrameType.Headers, encodedFieldSection);
    }

    internal static void WriteHeaders(IBufferWriter<byte> writer, ReadOnlySpan<byte> encodedFieldSection)
    {
        WriteFrame(writer, (ulong)Http3FrameType.Headers, encodedFieldSection);
    }

    /// <summary>
    /// Writes a SETTINGS frame.
    /// </summary>
    public static byte[] WriteSettings(IEnumerable<Http3Setting> settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        ArrayBufferWriter<byte> payload = new();
        HashSet<ulong> identifiers = [];
        foreach (Http3Setting setting in settings)
        {
            if (!identifiers.Add(setting.Identifier))
            {
                throw new ArgumentException("HTTP/3 SETTINGS identifiers must not be duplicated.", nameof(settings));
            }

            Http3SettingsParser.ValidateIdentifier(setting.Identifier);
            WriteVariableLengthInteger(payload, setting.Identifier);
            WriteVariableLengthInteger(payload, setting.Value);
        }

        return WriteFrame((ulong)Http3FrameType.Settings, payload.WrittenSpan);
    }

    /// <summary>
    /// Writes a GOAWAY frame.
    /// </summary>
    public static byte[] WriteGoAway(ulong streamOrPushId)
    {
        return WriteSingleIntegerFrame((ulong)Http3FrameType.GoAway, streamOrPushId);
    }

    /// <summary>
    /// Writes a CANCEL_PUSH frame.
    /// </summary>
    public static byte[] WriteCancelPush(ulong pushId)
    {
        return WriteSingleIntegerFrame((ulong)Http3FrameType.CancelPush, pushId);
    }

    /// <summary>
    /// Writes a MAX_PUSH_ID frame.
    /// </summary>
    public static byte[] WriteMaxPushId(ulong pushId)
    {
        return WriteSingleIntegerFrame((ulong)Http3FrameType.MaxPushId, pushId);
    }

    /// <summary>
    /// Writes a PUSH_PROMISE frame.
    /// </summary>
    public static byte[] WritePushPromise(ulong pushId, ReadOnlySpan<byte> encodedFieldSection)
    {
        ArrayBufferWriter<byte> payload = new();
        WriteVariableLengthInteger(payload, pushId);
        payload.Write(encodedFieldSection);
        return WriteFrame((ulong)Http3FrameType.PushPromise, payload.WrittenSpan);
    }

    /// <summary>
    /// Writes a frame with an arbitrary frame type and payload.
    /// </summary>
    public static byte[] WriteFrame(ulong frameType, ReadOnlySpan<byte> payload)
    {
        ArrayBufferWriter<byte> writer = new();
        WriteFrame(writer, frameType, payload);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Writes a frame with an arbitrary frame type and payload.
    /// </summary>
    public static void WriteFrame(IBufferWriter<byte> writer, ulong frameType, ReadOnlySpan<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(writer);
        WriteVariableLengthInteger(writer, frameType);
        WriteVariableLengthInteger(writer, checked((ulong)payload.Length));
        writer.Write(payload);
    }

    internal static int GetFrameLength(ulong frameType, int payloadLength)
    {
        if (payloadLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadLength));
        }

        return checked(
            Http3VariableLengthInteger.GetEncodedLength(frameType)
            + Http3VariableLengthInteger.GetEncodedLength((ulong)payloadLength)
            + payloadLength);
    }

    private static byte[] WriteSingleIntegerFrame(ulong frameType, ulong value)
    {
        ArrayBufferWriter<byte> payload = new();
        WriteVariableLengthInteger(payload, value);
        return WriteFrame(frameType, payload.WrittenSpan);
    }

    private static void WriteVariableLengthInteger(IBufferWriter<byte> writer, ulong value)
    {
        Span<byte> destination = writer.GetSpan(Http3VariableLengthInteger.MaxEncodedLength);
        if (!Http3VariableLengthInteger.TryFormat(value, destination, out int bytesWritten))
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        writer.Advance(bytesWritten);
    }
}

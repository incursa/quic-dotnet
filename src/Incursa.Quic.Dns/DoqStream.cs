namespace Incursa.Quic.Dns;

internal static class DoqStream
{
    private const int InitialBufferSize = 512;
    private const int MaximumFramedMessageLength = DoqMessageCodec.LengthPrefixSize + DoqMessageCodec.MaxPayloadLength;

    public static async ValueTask<DoqMessage> ReadMessageAsync(
        QuicStream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        byte[] readBuffer = new byte[InitialBufferSize];
        byte[] pending = [];

        while (true)
        {
            if (DoqMessageCodec.TryDecode(pending, out DoqMessage message, out int bytesConsumed))
            {
                if (bytesConsumed != pending.Length)
                {
                    throw new DoqException(
                        DoqErrorCode.ProtocolError,
                        "The DoQ stream contained trailing bytes after the DNS message.");
                }

                return message;
            }

            int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                throw new DoqException(
                    DoqErrorCode.ProtocolError,
                    "The DoQ stream ended before a complete DNS message was received.");
            }

            pending = Append(pending, readBuffer.AsSpan(0, bytesRead));
        }
    }

    public static async ValueTask<DoqMessage> ReadSingleMessageUntilFinAsync(
        QuicStream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        byte[] readBuffer = new byte[InitialBufferSize];
        byte[] pending = [];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                return DecodeExactlyOneMessage(pending);
            }

            pending = Append(pending, readBuffer.AsSpan(0, bytesRead));
            if (pending.Length > MaximumFramedMessageLength)
            {
                throw new DoqException(
                    DoqErrorCode.ProtocolError,
                    "The DoQ stream contained more data than one length-prefixed DNS message can carry.");
            }
        }
    }

    public static async ValueTask WriteMessageAndCompleteAsync(
        QuicStream stream,
        ReadOnlyMemory<byte> dnsMessage,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        byte[] encoded = DoqMessageCodec.Encode(dnsMessage.Span);
        await stream.WriteAsync(encoded, 0, encoded.Length, cancellationToken).ConfigureAwait(false);
        await stream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);
    }

    private static byte[] Append(byte[] pending, ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return pending;
        }

        byte[] combined = new byte[pending.Length + source.Length];
        pending.CopyTo(combined, 0);
        source.CopyTo(combined.AsSpan(pending.Length));
        return combined;
    }

    private static DoqMessage DecodeExactlyOneMessage(ReadOnlySpan<byte> source)
    {
        DoqMessage message = DoqMessageCodec.Decode(source, out int bytesConsumed);
        if (bytesConsumed != source.Length)
        {
            throw new DoqException(
                DoqErrorCode.ProtocolError,
                "The DoQ stream contained more than one DNS message.");
        }

        return message;
    }
}

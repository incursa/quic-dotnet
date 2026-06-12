// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
        Task writeAbortTask = stream.WaitForWriteAbortAsync(cancellationToken);
        Task readsClosedTask = stream.ReadsClosed;

        while (true)
        {
            if (writeAbortTask.IsCompleted)
            {
                await writeAbortTask.ConfigureAwait(false);
            }

            if (DoqMessageCodec.TryDecode(pending, out DoqMessage message, out int bytesConsumed))
            {
                if (bytesConsumed != pending.Length)
                {
                    throw new DoqException(
                        DoqErrorCode.ProtocolError,
                        "The DoQ stream contained trailing bytes after the DNS message.");
                }

                if (DoqMessageCodec.ContainsTcpKeepaliveEdnsOption(message.Payload.Span))
                {
                    throw new DoqException(
                        DoqErrorCode.ProtocolError,
                        "The DoQ message contains the forbidden edns-tcp-keepalive EDNS(0) option.");
                }

                return message;
            }

            if (readsClosedTask.IsCompleted)
            {
                await readsClosedTask.ConfigureAwait(false);
                throw new DoqException(
                    DoqErrorCode.ProtocolError,
                    "The DoQ stream ended before a complete DNS message was received.");
            }

            Task<int> readTask = stream.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken);
            Task completed = await Task.WhenAny(readTask, writeAbortTask, readsClosedTask).ConfigureAwait(false);
            if (completed == writeAbortTask)
            {
                await writeAbortTask.ConfigureAwait(false);
            }
            else if (completed == readsClosedTask)
            {
                await readsClosedTask.ConfigureAwait(false);
                throw new DoqException(
                    DoqErrorCode.ProtocolError,
                    "The DoQ stream ended before a complete DNS message was received.");
            }

            int bytesRead = await readTask.ConfigureAwait(false);
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
        Task writeAbortTask = stream.WaitForWriteAbortAsync(cancellationToken);

        while (true)
        {
            if (writeAbortTask.IsCompleted)
            {
                await writeAbortTask.ConfigureAwait(false);
            }

            Task<int> readTask = stream.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken);
            Task completed = await Task.WhenAny(readTask, writeAbortTask).ConfigureAwait(false);

            if (completed == writeAbortTask)
            {
                await writeAbortTask.ConfigureAwait(false);
            }

            int bytesRead = await readTask.ConfigureAwait(false);

            if (bytesRead == 0)
            {
                DoqMessage message = DecodeExactlyOneMessage(pending);
                if (writeAbortTask.IsCompleted)
                {
                    await writeAbortTask.ConfigureAwait(false);
                }

                if (DoqMessageCodec.ContainsTcpKeepaliveEdnsOption(message.Payload.Span))
                {
                    throw new DoqException(
                        DoqErrorCode.ProtocolError,
                        "The DoQ message contains the forbidden edns-tcp-keepalive EDNS(0) option.");
                }

                return message;
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

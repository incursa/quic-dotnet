// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Dns;

/// <summary>
/// Encodes and decodes the two-octet DNS message length prefix used by DNS over QUIC.
/// </summary>
public static class DoqMessageCodec
{
    /// <summary>
    /// The number of bytes in the DoQ length prefix.
    /// </summary>
    public const int LengthPrefixSize = 2;

    /// <summary>
    /// The largest DNS message payload representable by the DoQ length prefix.
    /// </summary>
    public const int MaxPayloadLength = ushort.MaxValue;

    /// <summary>
    /// Encodes one DNS message with the two-octet length prefix.
    /// </summary>
    public static byte[] Encode(ReadOnlySpan<byte> dnsMessage)
    {
        if (dnsMessage.Length > MaxPayloadLength)
        {
            throw new ArgumentOutOfRangeException(nameof(dnsMessage), dnsMessage.Length, "A DoQ DNS message cannot exceed 65535 bytes.");
        }

        byte[] encoded = new byte[LengthPrefixSize + dnsMessage.Length];
        if (!TryEncode(dnsMessage, encoded, out _))
        {
            throw new InvalidOperationException("The DoQ message buffer was too small.");
        }

        return encoded;
    }

    /// <summary>
    /// Attempts to encode one DNS message into the supplied destination.
    /// </summary>
    public static bool TryEncode(ReadOnlySpan<byte> dnsMessage, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (dnsMessage.Length > MaxPayloadLength)
        {
            return false;
        }

        int requiredLength = LengthPrefixSize + dnsMessage.Length;
        if (destination.Length < requiredLength)
        {
            return false;
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, checked((ushort)dnsMessage.Length));
        dnsMessage.CopyTo(destination[LengthPrefixSize..]);
        bytesWritten = requiredLength;
        return true;
    }

    /// <summary>
    /// Attempts to decode one complete DoQ-framed DNS message from the supplied source.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> source, out DoqMessage message, out int bytesConsumed)
    {
        message = default;
        bytesConsumed = 0;
        if (source.Length < LengthPrefixSize)
        {
            return false;
        }

        int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(source);
        int requiredLength = LengthPrefixSize + payloadLength;
        if (source.Length < requiredLength)
        {
            return false;
        }

        message = new DoqMessage(source.Slice(LengthPrefixSize, payloadLength).ToArray());
        bytesConsumed = requiredLength;
        return true;
    }

    /// <summary>
    /// Decodes one complete DoQ-framed DNS message from the supplied source.
    /// </summary>
    public static DoqMessage Decode(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        if (TryDecode(source, out DoqMessage message, out bytesConsumed))
        {
            return message;
        }

        throw new DoqException(DoqErrorCode.ProtocolError, "The DoQ DNS message frame is incomplete.");
    }
}

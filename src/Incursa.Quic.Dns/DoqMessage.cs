// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents one DNS message payload carried by DNS over QUIC framing.
/// </summary>
public readonly struct DoqMessage
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DoqMessage"/> struct.
    /// </summary>
    public DoqMessage(ReadOnlyMemory<byte> payload)
    {
        Payload = payload;
    }

    private const int MessageIdByteShift = 8;

    /// <summary>
    /// Gets the DNS message payload without the DoQ length prefix.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// Returns a new byte array with the DNS Message ID (first two octets) set to zero.
    /// Use when forwarding a DNS message from another transport into DoQ.
    /// </summary>
    public static byte[] NormalizeToDoq(ReadOnlySpan<byte> message)
    {
        if (message.Length < 2)
        {
            throw new ArgumentException("A DNS message must contain at least the two-octet Message ID field.", nameof(message));
        }

        byte[] copy = message.ToArray();
        copy[0] = 0;
        copy[1] = 0;
        return copy;
    }

    /// <summary>
    /// Returns a new byte array with the DNS Message ID (first two octets) set to the specified value.
    /// Use when forwarding a DNS message from DoQ into another transport that requires a Message ID.
    /// </summary>
    public static byte[] GenerateMessageId(ReadOnlySpan<byte> message, ushort messageId)
    {
        if (message.Length < 2)
        {
            throw new ArgumentException("A DNS message must contain at least the two-octet Message ID field.", nameof(message));
        }

        byte[] copy = message.ToArray();
        copy[0] = (byte)(messageId >> MessageIdByteShift);
        copy[1] = (byte)messageId;
        return copy;
    }
}

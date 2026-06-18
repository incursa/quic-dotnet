// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Buffers.Binary;

namespace Incursa.Quic.Http3;

/// <summary>
/// Formats WebSocket frames for RFC 9220 HTTP/3 tunnel streams.
/// </summary>
public static class Http3WebSocketFrameWriter
{
    private const byte FinalBitMask = 0x80;
    private const byte MaskBitMask = 0x80;
    private const byte PayloadLength16Marker = 126;
    private const byte PayloadLength64Marker = 127;
    private const int MaxControlPayloadLength = 125;
    private const int MaskingKeyLength = 4;
    private const int MaskingKeyIndexMask = 0x03;
    private const int SmallHeaderLength = 2;
    private const int Payload16HeaderLength = 4;
    private const int Payload64HeaderLength = 10;
    private const int Payload16LengthPrefixBytes = 3;
    private const int Payload64LengthPrefixBytes = 9;

    /// <summary>
    /// Formats an unmasked WebSocket frame.
    /// </summary>
    public static byte[] WriteUnmasked(Http3WebSocketOpcode opcode, ReadOnlySpan<byte> payload, bool final = true)
    {
        ArrayBufferWriter<byte> writer = new(GetFrameLength(payload.Length, masked: false));
        WriteFrame(writer, opcode, payload, final, masked: false, maskingKey: default);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Formats a masked WebSocket frame.
    /// </summary>
    public static byte[] WriteMasked(
        Http3WebSocketOpcode opcode,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> maskingKey,
        bool final = true)
    {
        if (maskingKey.Length != MaskingKeyLength)
        {
            throw new ArgumentException("A WebSocket masking key must be exactly four bytes.", nameof(maskingKey));
        }

        ArrayBufferWriter<byte> writer = new(GetFrameLength(payload.Length, masked: true));
        WriteFrame(writer, opcode, payload, final, masked: true, maskingKey);
        return writer.WrittenSpan.ToArray();
    }

    private static void WriteFrame(
        IBufferWriter<byte> writer,
        Http3WebSocketOpcode opcode,
        ReadOnlySpan<byte> payload,
        bool final,
        bool masked,
        ReadOnlySpan<byte> maskingKey)
    {
        ValidateOutboundFrame(opcode, payload.Length, final);

        Span<byte> first = writer.GetSpan(1);
        first[0] = (byte)((final ? FinalBitMask : 0x00) | (byte)opcode);
        writer.Advance(1);

        WriteLength(writer, payload.Length, masked);

        if (masked)
        {
            writer.Write(maskingKey);
            Span<byte> maskedPayload = writer.GetSpan(payload.Length);
            for (int index = 0; index < payload.Length; index++)
            {
                maskedPayload[index] = (byte)(payload[index] ^ maskingKey[index & MaskingKeyIndexMask]);
            }

            writer.Advance(payload.Length);
        }
        else
        {
            writer.Write(payload);
        }
    }

    private static void WriteLength(IBufferWriter<byte> writer, int payloadLength, bool masked)
    {
        byte maskBit = masked ? MaskBitMask : (byte)0x00;
        if (payloadLength <= MaxControlPayloadLength)
        {
            Span<byte> span = writer.GetSpan(1);
            span[0] = (byte)(maskBit | payloadLength);
            writer.Advance(1);
            return;
        }

        if (payloadLength <= ushort.MaxValue)
        {
            Span<byte> span = writer.GetSpan(Payload16LengthPrefixBytes);
            span[0] = (byte)(maskBit | PayloadLength16Marker);
            BinaryPrimitives.WriteUInt16BigEndian(span[1..], checked((ushort)payloadLength));
            writer.Advance(Payload16LengthPrefixBytes);
            return;
        }

        Span<byte> extended = writer.GetSpan(Payload64LengthPrefixBytes);
        extended[0] = (byte)(maskBit | PayloadLength64Marker);
        BinaryPrimitives.WriteUInt64BigEndian(extended[1..], checked((ulong)payloadLength));
        writer.Advance(Payload64LengthPrefixBytes);
    }

    private static void ValidateOutboundFrame(Http3WebSocketOpcode opcode, int payloadLength, bool final)
    {
        if (!Http3WebSocketMessageReader.IsKnownOpcode(opcode))
        {
            throw new ArgumentOutOfRangeException(nameof(opcode), "The WebSocket opcode is not registered.");
        }

        if (Http3WebSocketMessageReader.IsControlOpcode(opcode))
        {
            if (!final)
            {
                throw new ArgumentException("WebSocket control frames cannot be fragmented.", nameof(final));
            }

            if (payloadLength > MaxControlPayloadLength)
            {
                throw new ArgumentOutOfRangeException(nameof(payloadLength), "WebSocket control frames cannot exceed 125 bytes.");
            }
        }
    }

    private static int GetFrameLength(int payloadLength, bool masked)
    {
        int headerLength;
        if (payloadLength <= MaxControlPayloadLength)
        {
            headerLength = SmallHeaderLength;
        }
        else if (payloadLength <= ushort.MaxValue)
        {
            headerLength = Payload16HeaderLength;
        }
        else
        {
            headerLength = Payload64HeaderLength;
        }

        return headerLength + (masked ? MaskingKeyLength : 0) + payloadLength;
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Buffers.Binary;

namespace Incursa.Quic.Http3;

/// <summary>
/// Incrementally parses and reassembles WebSocket messages carried by an RFC 9220 HTTP/3 tunnel stream.
/// </summary>
public sealed class Http3WebSocketMessageReader
{
    private const byte FinalBitMask = 0x80;
    private const byte ReservedBitMask = 0x70;
    private const byte OpcodeBitMask = 0x0F;
    private const byte MaskBitMask = 0x80;
    private const byte PayloadLengthBitMask = 0x7F;
    private const byte PayloadLength16Marker = 126;
    private const byte PayloadLength64Marker = 127;
    private const int MaxControlPayloadLength = 125;
    private const int MinimumHeaderLength = 2;
    private const int Payload16LengthBytes = 2;
    private const int Payload64LengthBytes = 8;
    private const int MaskingKeyLength = 4;
    private const int MaskingKeyIndexMask = 0x03;

    private readonly Http3EndpointRole receivingEndpointRole;
    private byte[] pending = [];
    private Http3WebSocketOpcode? fragmentedOpcode;
    private ArrayBufferWriter<byte>? fragmentedPayload;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3WebSocketMessageReader" /> class.
    /// </summary>
    /// <param name="receivingEndpointRole">The endpoint role receiving peer WebSocket bytes.</param>
    public Http3WebSocketMessageReader(Http3EndpointRole receivingEndpointRole)
    {
        this.receivingEndpointRole = receivingEndpointRole;
    }

    /// <summary>
    /// Gets the number of buffered bytes that have not yet formed a complete WebSocket frame.
    /// </summary>
    public int PendingByteCount => pending.Length;

    /// <summary>
    /// Gets a value indicating whether a fragmented message is currently open.
    /// </summary>
    public bool HasOpenFragmentedMessage => fragmentedOpcode is not null;

    /// <summary>
    /// Parses all complete WebSocket messages available in <paramref name="source" />.
    /// </summary>
    public Http3WebSocketMessage[] Read(ReadOnlySpan<byte> source, bool endOfStream = false)
    {
        bool hadPending = pending.Length != 0;
        ReadOnlySpan<byte> readable;
        if (hadPending)
        {
            pending = Append(pending, source);
            readable = pending;
        }
        else
        {
            readable = source;
        }

        int index = 0;
        List<Http3WebSocketMessage> messages = [];

        while (index < readable.Length)
        {
            int frameStart = index;
            if (!TryReadFrame(readable, ref index, out Http3WebSocketFrame? frame))
            {
                index = frameStart;
                break;
            }

            ProcessFrame(frame!, messages);
        }

        if (index == readable.Length)
        {
            pending = [];
        }
        else if (hadPending)
        {
            pending = SlicePending(pending, index);
        }
        else
        {
            pending = readable[index..].ToArray();
        }

        if (endOfStream)
        {
            if (pending.Length != 0)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "The WebSocket stream ended with a truncated frame.");
            }

            if (fragmentedOpcode is not null)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "The WebSocket stream ended with an incomplete fragmented message.");
            }
        }

        return [.. messages];
    }

    /// <summary>
    /// Signals stream completion and fails if partial frame or message state remains buffered.
    /// </summary>
    public Http3WebSocketMessage[] Complete()
    {
        return Read([], endOfStream: true);
    }

    internal static bool IsControlOpcode(Http3WebSocketOpcode opcode)
    {
        return opcode is Http3WebSocketOpcode.Close or Http3WebSocketOpcode.Ping or Http3WebSocketOpcode.Pong;
    }

    internal static bool IsKnownOpcode(Http3WebSocketOpcode opcode)
    {
        return opcode is Http3WebSocketOpcode.Continuation
            or Http3WebSocketOpcode.Text
            or Http3WebSocketOpcode.Binary
            or Http3WebSocketOpcode.Close
            or Http3WebSocketOpcode.Ping
            or Http3WebSocketOpcode.Pong;
    }

    private bool TryReadFrame(ReadOnlySpan<byte> readable, ref int index, out Http3WebSocketFrame? frame)
    {
        frame = null;
        if (readable.Length - index < MinimumHeaderLength)
        {
            return false;
        }

        byte first = readable[index++];
        byte second = readable[index++];
        bool final = (first & FinalBitMask) != 0;
        bool hasReservedBits = (first & ReservedBitMask) != 0;
        Http3WebSocketOpcode opcode = (Http3WebSocketOpcode)(first & OpcodeBitMask);
        bool masked = (second & MaskBitMask) != 0;
        ulong payloadLength = (ulong)(second & PayloadLengthBitMask);

        if (hasReservedBits)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "WebSocket RSV bits are not supported on this RFC 9220 tunnel.");
        }

        if (!IsKnownOpcode(opcode))
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "The WebSocket frame opcode is not registered.");
        }

        if (payloadLength == PayloadLength16Marker)
        {
            if (readable.Length - index < Payload16LengthBytes)
            {
                return false;
            }

            payloadLength = BinaryPrimitives.ReadUInt16BigEndian(readable[index..]);
            index += Payload16LengthBytes;
            if (payloadLength <= MaxControlPayloadLength)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "The WebSocket frame used a non-minimal payload length encoding.");
            }
        }
        else if (payloadLength == PayloadLength64Marker)
        {
            if (readable.Length - index < Payload64LengthBytes)
            {
                return false;
            }

            payloadLength = BinaryPrimitives.ReadUInt64BigEndian(readable[index..]);
            index += Payload64LengthBytes;
            if (payloadLength <= ushort.MaxValue || payloadLength > int.MaxValue)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "The WebSocket frame payload length is invalid.");
            }
        }

        if (receivingEndpointRole == Http3EndpointRole.Server && !masked)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "Client WebSocket frames carried by RFC 9220 MUST be masked.");
        }

        if (receivingEndpointRole == Http3EndpointRole.Client && masked)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "Server WebSocket frames carried by RFC 9220 MUST NOT be masked.");
        }

        if (IsControlOpcode(opcode))
        {
            if (!final)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "WebSocket control frames cannot be fragmented.");
            }

            if (payloadLength > MaxControlPayloadLength)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "WebSocket control frame payloads cannot exceed 125 bytes.");
            }
        }

        Span<byte> maskingKey = stackalloc byte[MaskingKeyLength];
        if (masked)
        {
            if (readable.Length - index < MaskingKeyLength)
            {
                return false;
            }

            readable.Slice(index, MaskingKeyLength).CopyTo(maskingKey);
            index += MaskingKeyLength;
        }

        if (readable.Length - index < (int)payloadLength)
        {
            return false;
        }

        byte[] payload = readable.Slice(index, (int)payloadLength).ToArray();
        index += (int)payloadLength;

        if (masked)
        {
            for (int payloadIndex = 0; payloadIndex < payload.Length; payloadIndex++)
            {
                payload[payloadIndex] ^= maskingKey[payloadIndex & MaskingKeyIndexMask];
            }
        }

        frame = new Http3WebSocketFrame(final, opcode, payload, masked);
        return true;
    }

    private void ProcessFrame(Http3WebSocketFrame frame, List<Http3WebSocketMessage> messages)
    {
        if (IsControlOpcode(frame.Opcode))
        {
            messages.Add(new Http3WebSocketMessage(frame.Opcode, frame.Payload));
            return;
        }

        if (frame.Opcode == Http3WebSocketOpcode.Continuation)
        {
            if (fragmentedOpcode is null || fragmentedPayload is null)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "A WebSocket continuation frame arrived without an open fragmented message.");
            }

            fragmentedPayload.Write(frame.Payload.Span);
            if (frame.IsFinal)
            {
                messages.Add(new Http3WebSocketMessage(fragmentedOpcode.Value, fragmentedPayload.WrittenMemory.ToArray()));
                fragmentedOpcode = null;
                fragmentedPayload = null;
            }

            return;
        }

        if (fragmentedOpcode is not null)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "A new WebSocket data message started before the previous fragmented message completed.");
        }

        if (frame.IsFinal)
        {
            messages.Add(new Http3WebSocketMessage(frame.Opcode, frame.Payload));
            return;
        }

        fragmentedOpcode = frame.Opcode;
        fragmentedPayload = new ArrayBufferWriter<byte>(frame.Payload.Length);
        fragmentedPayload.Write(frame.Payload.Span);
    }

    private static byte[] Append(byte[] pendingBytes, ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return pendingBytes;
        }

        byte[] combined = new byte[pendingBytes.Length + source.Length];
        pendingBytes.CopyTo(combined, 0);
        source.CopyTo(combined.AsSpan(pendingBytes.Length));
        return combined;
    }

    private static byte[] SlicePending(byte[] pendingBytes, int consumed)
    {
        return consumed == 0 ? pendingBytes : pendingBytes.AsSpan(consumed).ToArray();
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Text;

namespace Incursa.Quic.Http3;

/// <summary>
/// Parses WebSocket close messages carried on RFC 9220 HTTP/3 tunnel streams.
/// </summary>
public static class Http3WebSocketCloseFrameParser
{
    private const int CloseStatusCodeLength = 2;
    private const int MaxClosePayloadLength = 125;
    private const ushort MinimumValidCloseStatusCode = 1000;
    private const ushort MaximumValidCloseStatusCode = 4999;
    private const ushort ReservedNoStatusReceived = 1005;
    private const ushort ReservedAbnormalClosure = 1006;
    private const ushort ReservedTlsHandshakeFailure = 1015;

    private static readonly Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Parses the status code and reason from a complete close message.
    /// </summary>
    public static Http3WebSocketCloseStatus Parse(Http3WebSocketMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.Opcode != Http3WebSocketOpcode.Close)
        {
            throw new ArgumentException("Only WebSocket close messages carry close status payloads.", nameof(message));
        }

        return ParsePayload(message.Payload.Span);
    }

    /// <summary>
    /// Parses the status code and reason from a close frame payload.
    /// </summary>
    public static Http3WebSocketCloseStatus ParsePayload(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
        {
            return new Http3WebSocketCloseStatus(null, null);
        }

        if (payload.Length < CloseStatusCodeLength)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "A WebSocket close payload cannot contain a partial status code.");
        }

        ushort statusCode = BinaryPrimitives.ReadUInt16BigEndian(payload);
        if (!IsValidCloseStatusCode(statusCode))
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "The WebSocket close status code is invalid for transmission.");
        }

        ReadOnlySpan<byte> reasonBytes = payload[CloseStatusCodeLength..];
        if (reasonBytes.IsEmpty)
        {
            return new Http3WebSocketCloseStatus(statusCode, null);
        }

        try
        {
            return new Http3WebSocketCloseStatus(statusCode, StrictUtf8.GetString(reasonBytes));
        }
        catch (DecoderFallbackException exception)
        {
            _ = exception.Message;
            throw new Http3Exception(Http3ErrorCode.MessageError, "A WebSocket close reason carried invalid UTF-8.");
        }
    }

    /// <summary>
    /// Formats a WebSocket close payload from an optional status code and reason.
    /// </summary>
    public static byte[] FormatPayload(ushort? statusCode, string? reason)
    {
        if (statusCode is null)
        {
            if (!string.IsNullOrEmpty(reason))
            {
                throw new ArgumentException("A WebSocket close reason requires a close status code.", nameof(reason));
            }

            return [];
        }

        byte[] reasonBytes = string.IsNullOrEmpty(reason)
            ? []
            : StrictUtf8.GetBytes(reason);
        int payloadLength = CloseStatusCodeLength + reasonBytes.Length;
        if (payloadLength > MaxClosePayloadLength)
        {
            throw new ArgumentOutOfRangeException(nameof(reason), "A WebSocket close payload cannot exceed 125 bytes.");
        }

        byte[] payload = new byte[payloadLength];
        BinaryPrimitives.WriteUInt16BigEndian(payload, statusCode.Value);
        reasonBytes.CopyTo(payload.AsSpan(CloseStatusCodeLength));
        _ = ParsePayload(payload);
        return payload;
    }

    private static bool IsValidCloseStatusCode(ushort statusCode)
    {
        if (statusCode < MinimumValidCloseStatusCode || statusCode > MaximumValidCloseStatusCode)
        {
            return false;
        }

        return statusCode is not ReservedNoStatusReceived
            and not ReservedAbnormalClosure
            and not ReservedTlsHandshakeFailure;
    }
}

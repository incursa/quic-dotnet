// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9298 UDP Proxying HTTP Datagram payload.
/// </summary>
public sealed class Http3ConnectUdpDatagram
{
    /// <summary>
    /// Gets the Context ID reserved for UDP packet payloads.
    /// </summary>
    public const ulong UdpPayloadContextId = 0;

    /// <summary>
    /// Gets the largest legal RFC 9298 Context ID value.
    /// </summary>
    public const ulong MaximumContextId = (1UL << 62) - 1;

    /// <summary>
    /// Gets the largest legal UDP Proxying Payload length for Context ID zero.
    /// </summary>
    public const int MaximumUdpPayloadLength = 65527;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ConnectUdpDatagram" /> class.
    /// </summary>
    public Http3ConnectUdpDatagram(ulong contextId, byte[] payload)
    {
        if (contextId > MaximumContextId)
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The CONNECT-UDP Context ID is too large.");
        }

        if (contextId == UdpPayloadContextId && payload is not null && payload.Length > MaximumUdpPayloadLength)
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "CONNECT-UDP UDP payloads with Context ID zero must not exceed 65527 bytes.");
        }

        ContextId = contextId;
        Payload = payload ?? throw new ArgumentNullException(nameof(payload));
    }

    /// <summary>
    /// Gets the UDP Proxying Context ID.
    /// </summary>
    public ulong ContextId { get; }

    /// <summary>
    /// Gets the UDP Proxying Payload.
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// Creates a Context ID zero UDP-payload datagram.
    /// </summary>
    public static Http3ConnectUdpDatagram CreateUdpPayload(ReadOnlySpan<byte> udpPayload)
    {
        return new Http3ConnectUdpDatagram(UdpPayloadContextId, udpPayload.ToArray());
    }

    /// <summary>
    /// Parses an RFC 9298 UDP Proxying HTTP Datagram payload.
    /// </summary>
    public static Http3ConnectUdpDatagram Parse(ReadOnlySpan<byte> udpProxyingPayload)
    {
        if (!Http3VariableLengthInteger.TryParse(udpProxyingPayload, out ulong contextId, out int bytesConsumed))
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The CONNECT-UDP HTTP Datagram is too short to contain a Context ID.");
        }

        return new Http3ConnectUdpDatagram(contextId, udpProxyingPayload[bytesConsumed..].ToArray());
    }

    /// <summary>
    /// Parses an RFC 9298 payload from an RFC 9297 HTTP Datagram.
    /// </summary>
    public static Http3ConnectUdpDatagram ParseFromHttp3Datagram(Http3Datagram datagram)
    {
        ArgumentNullException.ThrowIfNull(datagram);
        return Parse(datagram.Payload);
    }

    /// <summary>
    /// Encodes the UDP Proxying HTTP Datagram payload as Context ID followed by UDP Proxying Payload.
    /// </summary>
    public byte[] Encode()
    {
        byte[] encoded = new byte[Http3VariableLengthInteger.GetEncodedLength(ContextId) + Payload.Length];
        if (!Http3VariableLengthInteger.TryFormat(ContextId, encoded, out int bytesWritten))
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The CONNECT-UDP Context ID could not be encoded.");
        }

        Payload.CopyTo(encoded.AsSpan(bytesWritten));
        return encoded;
    }

    /// <summary>
    /// Encodes this UDP Proxying payload inside an RFC 9297 HTTP Datagram for a request stream.
    /// </summary>
    public Http3Datagram ToHttp3Datagram(ulong associatedStreamId)
    {
        return Http3Datagram.CreateForAssociatedStream(associatedStreamId, Encode());
    }
}

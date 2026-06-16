// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9484 IP Proxying HTTP Datagram payload.
/// </summary>
public sealed class Http3ConnectIpDatagram
{
    private const int Ipv4VersionNibble = 4;
    private const int Ipv6VersionNibble = 6;
    private const int Ipv4MinimumHeaderLength = 20;
    private const int Ipv6HeaderLength = 40;
    private const int Ipv4InternetHeaderLengthMask = 0x0F;
    private const int Ipv4InternetHeaderLengthUnitBytes = 4;
    private const int Ipv4TotalLengthOffset = 2;
    private const int Ipv6PayloadLengthOffset = 4;

    /// <summary>
    /// Gets the Context ID reserved for full IP packet payloads.
    /// </summary>
    public const ulong IpPayloadContextId = 0;

    /// <summary>
    /// Gets the largest legal RFC 9484 Context ID value.
    /// </summary>
    public const ulong MaximumContextId = (1UL << 62) - 1;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ConnectIpDatagram" /> class.
    /// </summary>
    public Http3ConnectIpDatagram(ulong contextId, byte[] payload)
    {
        if (contextId > MaximumContextId)
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The CONNECT-IP Context ID is too large.");
        }

        Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        if (contextId == IpPayloadContextId && !IsFullIpPacket(Payload))
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "CONNECT-IP Context ID zero payloads must contain a complete IP packet.");
        }

        ContextId = contextId;
    }

    /// <summary>
    /// Gets the IP Proxying Context ID.
    /// </summary>
    public ulong ContextId { get; }

    /// <summary>
    /// Gets the IP Proxying payload.
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// Creates a Context ID zero IP-packet datagram.
    /// </summary>
    public static Http3ConnectIpDatagram CreateIpPacketPayload(ReadOnlySpan<byte> ipPacket)
    {
        return new Http3ConnectIpDatagram(IpPayloadContextId, ipPacket.ToArray());
    }

    /// <summary>
    /// Parses an RFC 9484 IP Proxying HTTP Datagram payload.
    /// </summary>
    public static Http3ConnectIpDatagram Parse(ReadOnlySpan<byte> ipProxyingPayload)
    {
        if (!Http3VariableLengthInteger.TryParse(ipProxyingPayload, out ulong contextId, out int bytesConsumed))
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The CONNECT-IP HTTP Datagram is too short to contain a Context ID.");
        }

        return new Http3ConnectIpDatagram(contextId, ipProxyingPayload[bytesConsumed..].ToArray());
    }

    /// <summary>
    /// Parses an RFC 9484 payload from an RFC 9297 HTTP Datagram.
    /// </summary>
    public static Http3ConnectIpDatagram ParseFromHttp3Datagram(Http3Datagram datagram)
    {
        ArgumentNullException.ThrowIfNull(datagram);
        return Parse(datagram.Payload);
    }

    /// <summary>
    /// Encodes the IP Proxying HTTP Datagram payload as Context ID followed by payload.
    /// </summary>
    public byte[] Encode()
    {
        byte[] encoded = new byte[Http3VariableLengthInteger.GetEncodedLength(ContextId) + Payload.Length];
        if (!Http3VariableLengthInteger.TryFormat(ContextId, encoded, out int bytesWritten))
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The CONNECT-IP Context ID could not be encoded.");
        }

        Payload.CopyTo(encoded.AsSpan(bytesWritten));
        return encoded;
    }

    /// <summary>
    /// Encodes this IP Proxying payload inside an RFC 9297 HTTP Datagram for a request stream.
    /// </summary>
    public Http3Datagram ToHttp3Datagram(ulong associatedStreamId)
    {
        return Http3Datagram.CreateForAssociatedStream(associatedStreamId, Encode());
    }

    /// <summary>
    /// Returns true when bytes contain a complete IPv4 or IPv6 packet.
    /// </summary>
    public static bool IsFullIpPacket(ReadOnlySpan<byte> ipPacket)
    {
        if (ipPacket.IsEmpty)
        {
            return false;
        }

        int version = ipPacket[0] >> 4;
        return version switch
        {
            Ipv4VersionNibble => IsFullIpv4Packet(ipPacket),
            Ipv6VersionNibble => IsFullIpv6Packet(ipPacket),
            _ => false,
        };
    }

    private static bool IsFullIpv4Packet(ReadOnlySpan<byte> ipPacket)
    {
        if (ipPacket.Length < Ipv4MinimumHeaderLength)
        {
            return false;
        }

        int internetHeaderLength = (ipPacket[0] & Ipv4InternetHeaderLengthMask) * Ipv4InternetHeaderLengthUnitBytes;
        if (internetHeaderLength < Ipv4MinimumHeaderLength || ipPacket.Length < internetHeaderLength)
        {
            return false;
        }

        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(ipPacket.Slice(Ipv4TotalLengthOffset, sizeof(ushort)));
        return totalLength >= internetHeaderLength && totalLength == ipPacket.Length;
    }

    private static bool IsFullIpv6Packet(ReadOnlySpan<byte> ipPacket)
    {
        if (ipPacket.Length < Ipv6HeaderLength)
        {
            return false;
        }

        int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(ipPacket.Slice(Ipv6PayloadLengthOffset, sizeof(ushort)));
        return checked(Ipv6HeaderLength + payloadLength) == ipPacket.Length;
    }
}

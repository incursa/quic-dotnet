// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9298 CONNECT-UDP stream interpretation and HTTP Datagram conversion helpers.
/// </summary>
public static class Http3ConnectUdpConversionPolicy
{
    /// <summary>
    /// Returns the RFC 9298 stream-reference scope for the HTTP version in use.
    /// </summary>
    public static Http3ConnectUdpStreamReferenceScope GetStreamReferenceScope(bool httpVersionSupportsMultiplexingStreams)
    {
        return httpVersionSupportsMultiplexingStreams
            ? Http3ConnectUdpStreamReferenceScope.RequestStream
            : Http3ConnectUdpStreamReferenceScope.EntireConnection;
    }

    /// <summary>
    /// Returns true when CONNECT-UDP conversion continues for a successful open tunnel.
    /// </summary>
    public static bool ShouldConvertDatagramsAndUdpPackets(bool requestSuccessful, bool tunnelClosed)
    {
        return requestSuccessful && !tunnelClosed;
    }

    /// <summary>
    /// Converts a UDP packet payload to the RFC 9298 Section 5 HTTP Datagram format for a request stream.
    /// </summary>
    public static Http3Datagram ConvertUdpPacketToHttpDatagram(ReadOnlySpan<byte> udpPayload, ulong associatedStreamId, bool tunnelClosed)
    {
        if (tunnelClosed)
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "CONNECT-UDP cannot convert UDP packets after the tunnel is closed.");
        }

        return Http3ConnectUdpDatagram.CreateUdpPayload(udpPayload).ToHttp3Datagram(associatedStreamId);
    }

    /// <summary>
    /// Converts an RFC 9298 Section 5 HTTP Datagram to a UDP packet payload.
    /// </summary>
    public static byte[] ConvertHttpDatagramToUdpPacket(Http3Datagram datagram, bool tunnelClosed)
    {
        ArgumentNullException.ThrowIfNull(datagram);

        if (tunnelClosed)
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "CONNECT-UDP cannot convert HTTP Datagrams after the tunnel is closed.");
        }

        Http3ConnectUdpDatagram connectUdpDatagram = Http3ConnectUdpDatagram.ParseFromHttp3Datagram(datagram);
        if (connectUdpDatagram.ContextId != Http3ConnectUdpDatagram.UdpPayloadContextId)
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "CONNECT-UDP UDP packet conversion requires Context ID zero.");
        }

        return connectUdpDatagram.Payload;
    }
}

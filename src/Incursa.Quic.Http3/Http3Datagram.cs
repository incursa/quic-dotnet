// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9297 HTTP/3 Datagram payload.
/// </summary>
public sealed class Http3Datagram
{
    private const ulong StreamIdLowBitsMask = 0x03;
    private const ulong StreamIdToQuarterStreamIdDivisor = 4;

    /// <summary>
    /// Gets the largest legal Quarter Stream ID value.
    /// </summary>
    public const ulong MaximumQuarterStreamId = (1UL << 60) - 1;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3Datagram" /> class.
    /// </summary>
    public Http3Datagram(ulong quarterStreamId, byte[] payload)
    {
        if (quarterStreamId > MaximumQuarterStreamId)
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The HTTP Datagram Quarter Stream ID is too large.");
        }

        QuarterStreamId = quarterStreamId;
        Payload = payload ?? throw new ArgumentNullException(nameof(payload));
    }

    /// <summary>
    /// Gets the Quarter Stream ID carried before the HTTP Datagram payload.
    /// </summary>
    public ulong QuarterStreamId { get; }

    /// <summary>
    /// Gets the associated client-initiated bidirectional stream ID.
    /// </summary>
    public ulong AssociatedStreamId => checked(QuarterStreamId * StreamIdToQuarterStreamIdDivisor);

    /// <summary>
    /// Gets the HTTP Datagram payload bytes after the Quarter Stream ID.
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// Creates an HTTP Datagram for a client-initiated bidirectional request stream.
    /// </summary>
    public static Http3Datagram CreateForAssociatedStream(ulong associatedStreamId, ReadOnlySpan<byte> payload)
    {
        if ((associatedStreamId & StreamIdLowBitsMask) != 0)
        {
            throw new Http3Exception(Http3ErrorCode.IdError, "HTTP Datagrams can only be associated with client-initiated bidirectional request streams.");
        }

        return new Http3Datagram(associatedStreamId / StreamIdToQuarterStreamIdDivisor, payload.ToArray());
    }

    /// <summary>
    /// Parses a QUIC DATAGRAM frame payload as an HTTP/3 Datagram.
    /// </summary>
    public static Http3Datagram Parse(ReadOnlySpan<byte> datagramPayload)
    {
        if (!Http3VariableLengthInteger.TryParse(datagramPayload, out ulong quarterStreamId, out int bytesConsumed))
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The HTTP Datagram payload is too short to contain a Quarter Stream ID.");
        }

        return new Http3Datagram(quarterStreamId, datagramPayload[bytesConsumed..].ToArray());
    }

    /// <summary>
    /// Encodes the HTTP Datagram payload carried inside a QUIC DATAGRAM frame.
    /// </summary>
    public byte[] Encode()
    {
        byte[] encoded = new byte[Http3VariableLengthInteger.GetEncodedLength(QuarterStreamId) + Payload.Length];
        if (!Http3VariableLengthInteger.TryFormat(QuarterStreamId, encoded, out int bytesWritten))
        {
            throw new Http3Exception(Http3ErrorCode.DatagramError, "The HTTP Datagram Quarter Stream ID could not be encoded.");
        }

        Payload.CopyTo(encoded.AsSpan(bytesWritten));
        return encoded;
    }
}

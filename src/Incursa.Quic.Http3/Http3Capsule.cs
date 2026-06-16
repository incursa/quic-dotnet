// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9297 Capsule Protocol entry.
/// </summary>
public sealed class Http3Capsule
{
    /// <summary>
    /// Gets the DATAGRAM Capsule Type value.
    /// </summary>
    public const ulong DatagramCapsuleType = 0x00;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3Capsule" /> class.
    /// </summary>
    public Http3Capsule(ulong type, byte[] payload)
    {
        Type = type;
        Payload = payload ?? throw new ArgumentNullException(nameof(payload));
    }

    /// <summary>
    /// Gets the Capsule Type field.
    /// </summary>
    public ulong Type { get; }

    /// <summary>
    /// Gets the Capsule Value field.
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// Creates a DATAGRAM capsule carrying an HTTP Datagram payload.
    /// </summary>
    public static Http3Capsule CreateDatagram(ReadOnlySpan<byte> httpDatagramPayload)
    {
        return new Http3Capsule(DatagramCapsuleType, httpDatagramPayload.ToArray());
    }

    /// <summary>
    /// Parses capsule entries and silently skips entries rejected by <paramref name="retainCapsuleType" />.
    /// </summary>
    public static Http3Capsule[] ParseSequence(ReadOnlySpan<byte> source, Func<ulong, bool>? retainCapsuleType = null)
    {
        List<Http3Capsule> capsules = [];
        int index = 0;
        while (index < source.Length)
        {
            ulong type = ReadCapsuleInteger(source, ref index, "type");
            ulong length = ReadCapsuleInteger(source, ref index, "length");
            if (length > int.MaxValue || source.Length - index < (int)length)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "The Capsule Protocol stream ended with a truncated Capsule Value.");
            }

            ReadOnlySpan<byte> payload = source.Slice(index, (int)length);
            index += (int)length;
            if (retainCapsuleType is null || retainCapsuleType(type))
            {
                capsules.Add(new Http3Capsule(type, payload.ToArray()));
            }
        }

        return [.. capsules];
    }

    /// <summary>
    /// Encodes the capsule as Type, Length, and Value fields.
    /// </summary>
    public byte[] Encode()
    {
        byte[] encoded = new byte[
            Http3VariableLengthInteger.GetEncodedLength(Type)
            + Http3VariableLengthInteger.GetEncodedLength((ulong)Payload.Length)
            + Payload.Length];
        int offset = 0;
        offset += WriteCapsuleInteger(Type, encoded.AsSpan(offset));
        offset += WriteCapsuleInteger((ulong)Payload.Length, encoded.AsSpan(offset));
        Payload.CopyTo(encoded.AsSpan(offset));
        return encoded;
    }

    private static ulong ReadCapsuleInteger(ReadOnlySpan<byte> source, ref int index, string fieldName)
    {
        if (!Http3VariableLengthInteger.TryParse(source[index..], out ulong value, out int bytesConsumed))
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, $"The Capsule {fieldName} field is truncated.");
        }

        index += bytesConsumed;
        return value;
    }

    private static int WriteCapsuleInteger(ulong value, Span<byte> destination)
    {
        if (!Http3VariableLengthInteger.TryFormat(value, destination, out int bytesWritten))
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        return bytesWritten;
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents an RFC 9460 SVCB SvcParam key/value pair.
/// </summary>
public sealed class DnsServiceBindingServiceParameter
{
    private const int UInt16FieldOctets = 2;
    private const int WireHeaderOctets = UInt16FieldOctets * 2;
    private readonly byte[] value;

    private DnsServiceBindingServiceParameter(ushort key, ReadOnlySpan<byte> value)
    {
        Key = key;
        this.value = value.ToArray();
    }

    /// <summary>
    /// Gets the SvcParamKey.
    /// </summary>
    public ushort Key { get; }

    /// <summary>
    /// Gets the opaque wire-format SvcParamValue.
    /// </summary>
    public ReadOnlyMemory<byte> Value => value;

    /// <summary>
    /// Creates a service parameter from a numeric RFC 9460 key and already encoded value.
    /// </summary>
    public static DnsServiceBindingServiceParameter Create(ushort key, ReadOnlySpan<byte> value)
    {
        return new DnsServiceBindingServiceParameter(key, value);
    }

    internal static ReadOnlyCollection<DnsServiceBindingServiceParameter> DecodeMany(ReadOnlySpan<byte> encoded)
    {
        List<DnsServiceBindingServiceParameter> parameters = [];
        ushort? previousKey = null;
        int offset = 0;
        while (offset < encoded.Length)
        {
            if (encoded.Length - offset < WireHeaderOctets)
            {
                throw new ArgumentException("The SVCB SvcParams wire data ends inside a SvcParam header.", nameof(encoded));
            }

            ushort key = BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
            ushort length = BinaryPrimitives.ReadUInt16BigEndian(encoded[(offset + UInt16FieldOctets)..]);
            offset += WireHeaderOctets;
            if (encoded.Length - offset < length)
            {
                throw new ArgumentException("The SVCB SvcParams wire data ends inside a SvcParamValue.", nameof(encoded));
            }

            if (previousKey.HasValue && key <= previousKey.Value)
            {
                throw new ArgumentException("RFC 9460 SvcParamKeys must appear in strictly increasing numeric order.", nameof(encoded));
            }

            parameters.Add(Create(key, encoded.Slice(offset, length)));
            previousKey = key;
            offset += length;
        }

        return new ReadOnlyCollection<DnsServiceBindingServiceParameter>(parameters);
    }
}

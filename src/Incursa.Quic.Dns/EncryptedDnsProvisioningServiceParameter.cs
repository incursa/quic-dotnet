// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents an RFC 9460 SvcParam key/value pair carried by RFC 9464 provisioning attributes.
/// </summary>
public sealed class EncryptedDnsProvisioningServiceParameter
{
    private const int UInt16FieldOctets = 2;
    private const int WireHeaderOctets = UInt16FieldOctets * 2;
    private readonly byte[] value;

    private EncryptedDnsProvisioningServiceParameter(ushort key, ReadOnlySpan<byte> value)
    {
        Key = key;
        this.value = value.ToArray();
    }

    /// <summary>
    /// Gets the RFC 9460 `alpn` SvcParamKey.
    /// </summary>
    public const ushort AlpnKey = 1;

    /// <summary>
    /// Gets the RFC 9460 `port` SvcParamKey.
    /// </summary>
    public const ushort PortKey = 3;

    /// <summary>
    /// Gets the RFC 9460 `ipv4hint` SvcParamKey, which RFC 9464 forbids in ENCDNS_IP* attributes.
    /// </summary>
    public const ushort Ipv4HintKey = 4;

    /// <summary>
    /// Gets the RFC 9460 `ipv6hint` SvcParamKey, which RFC 9464 forbids in ENCDNS_IP* attributes.
    /// </summary>
    public const ushort Ipv6HintKey = 6;

    /// <summary>
    /// Gets the SvcParamKey.
    /// </summary>
    public ushort Key { get; }

    /// <summary>
    /// Gets the opaque wire-format SvcParamValue.
    /// </summary>
    public ReadOnlyMemory<byte> Value => value;

    internal int EncodedLength => WireHeaderOctets + value.Length;

    /// <summary>
    /// Creates a service parameter from a numeric RFC 9460 key and an already encoded value.
    /// </summary>
    public static EncryptedDnsProvisioningServiceParameter Create(ushort key, ReadOnlySpan<byte> value)
    {
        if (key is Ipv4HintKey or Ipv6HintKey)
        {
            throw new ArgumentException("RFC 9464 ENCDNS_IP* attributes must not include ipv4hint or ipv6hint SvcParams.", nameof(key));
        }

        return new EncryptedDnsProvisioningServiceParameter(key, value);
    }

    /// <summary>
    /// Creates an empty-valued service parameter from a known presentation key.
    /// </summary>
    public static EncryptedDnsProvisioningServiceParameter FromPresentationKey(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        return key.Trim().ToLowerInvariant() switch
        {
            "alpn" => Create(AlpnKey, []),
            "port" => Create(PortKey, []),
            "ipv4hint" or "ipv6hint" => throw new ArgumentException(
                "RFC 9464 ENCDNS_IP* attributes must not include ipv4hint or ipv6hint SvcParams.",
                nameof(key)),
            _ => throw new ArgumentException("The SvcParam presentation key is not supported by this scalar provisioning slice.", nameof(key)),
        };
    }

    internal static ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> Normalize(
        IEnumerable<EncryptedDnsProvisioningServiceParameter>? serviceParameters)
    {
        if (serviceParameters is null)
        {
            return new ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter>([]);
        }

        SortedDictionary<ushort, EncryptedDnsProvisioningServiceParameter> sorted = [];
        foreach (EncryptedDnsProvisioningServiceParameter? parameter in serviceParameters)
        {
            ArgumentNullException.ThrowIfNull(parameter);
            if (!sorted.TryAdd(parameter.Key, parameter))
            {
                throw new ArgumentException("RFC 9460 SvcParamKeys must not be repeated.", nameof(serviceParameters));
            }
        }

        return new ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter>([.. sorted.Values]);
    }

    internal void WriteTo(Span<byte> destination)
    {
        if (destination.Length < EncodedLength)
        {
            throw new ArgumentException("The destination is too small for the SvcParam.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, Key);
        BinaryPrimitives.WriteUInt16BigEndian(destination[UInt16FieldOctets..], checked((ushort)value.Length));
        value.CopyTo(destination[WireHeaderOctets..]);
    }

    internal static ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> DecodeMany(ReadOnlySpan<byte> encoded)
    {
        List<EncryptedDnsProvisioningServiceParameter> parameters = [];
        ushort? previousKey = null;
        int offset = 0;
        while (offset < encoded.Length)
        {
            if (encoded.Length - offset < WireHeaderOctets)
            {
                throw new ArgumentException("The SvcParams wire data ends inside a SvcParam header.", nameof(encoded));
            }

            ushort key = BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
            ushort length = BinaryPrimitives.ReadUInt16BigEndian(encoded[(offset + UInt16FieldOctets)..]);
            offset += WireHeaderOctets;
            if (encoded.Length - offset < length)
            {
                throw new ArgumentException("The SvcParams wire data ends inside a SvcParamValue.", nameof(encoded));
            }

            if (previousKey.HasValue && key <= previousKey.Value)
            {
                throw new ArgumentException("RFC 9460 SvcParamKeys must appear in strictly increasing numeric order.", nameof(encoded));
            }

            parameters.Add(Create(key, encoded.Slice(offset, length)));
            previousKey = key;
            offset += length;
        }

        return new ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter>(parameters);
    }
}

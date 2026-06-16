// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Validated scalar model for RFC 9464 ENCDNS_DIGEST_INFO request attributes.
/// </summary>
public sealed class EncryptedDnsProvisioningDigestInfoAttribute
{
    private EncryptedDnsProvisioningDigestInfoAttribute(ushort length, byte hashAlgorithmCount, ReadOnlyCollection<ushort> hashAlgorithmIdentifiers)
    {
        Length = length;
        HashAlgorithmCount = hashAlgorithmCount;
        HashAlgorithmIdentifiers = hashAlgorithmIdentifiers;
    }

    /// <summary>
    /// Gets the ENCDNS_DIGEST_INFO attribute type.
    /// </summary>
    public const ushort AttributeType = EncryptedDnsProvisioningAttribute.DigestInfoAttributeType;

    /// <summary>
    /// Gets a value indicating whether outbound attributes set the reserved bit.
    /// </summary>
    public bool ReservedBitSet => false;

    /// <summary>
    /// Gets the two-octet Length field value.
    /// </summary>
    public ushort Length { get; }

    /// <summary>
    /// Gets the Num Hash Algs field value.
    /// </summary>
    public byte HashAlgorithmCount { get; }

    /// <summary>
    /// Gets the ADN Length field value for a CFG_REQUEST hash-algorithm list.
    /// </summary>
    public byte AuthenticationDomainNameLength => 0;

    /// <summary>
    /// Gets the requested hash algorithm identifiers.
    /// </summary>
    public IReadOnlyList<ushort> HashAlgorithmIdentifiers { get; }

    /// <summary>
    /// Creates an ENCDNS_DIGEST_INFO CFG_REQUEST hash-algorithm list.
    /// </summary>
    public static EncryptedDnsProvisioningDigestInfoAttribute CreateRequest(IEnumerable<ushort> hashAlgorithmIdentifiers)
    {
        if (hashAlgorithmIdentifiers is null)
        {
            throw new ArgumentNullException(nameof(hashAlgorithmIdentifiers));
        }

        List<ushort> identifiers = [];
        foreach (ushort identifier in hashAlgorithmIdentifiers)
        {
            identifiers.Add(identifier);
        }

        if (identifiers.Count == 0)
        {
            throw new ArgumentException("At least one hash algorithm identifier is required.", nameof(hashAlgorithmIdentifiers));
        }

        if (identifiers.Count > byte.MaxValue)
        {
            throw new ArgumentException("The hash algorithm count must fit in one octet.", nameof(hashAlgorithmIdentifiers));
        }

        int length = 2 + (2 * identifiers.Count);
        if (length > ushort.MaxValue)
        {
            throw new ArgumentException("The ENCDNS_DIGEST_INFO length must fit in two octets.", nameof(hashAlgorithmIdentifiers));
        }

        return new EncryptedDnsProvisioningDigestInfoAttribute(
            (ushort)length,
            (byte)identifiers.Count,
            new ReadOnlyCollection<ushort>(identifiers));
    }
}

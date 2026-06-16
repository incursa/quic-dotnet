// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic.Dns;

/// <summary>
/// Validated scalar model for RFC 9464 ENCDNS_DIGEST_INFO request attributes.
/// </summary>
public sealed class EncryptedDnsProvisioningDigestInfoAttribute
{
    private const int AttributeHeaderOctets = 4;
    private const int UInt16FieldOctets = 2;
    private const int DigestInfoFixedDataLength = 2;
    private const int ReplyOrSetDigestFixedDataLength = 4;
    private const ushort HighestCurrentlyRegisteredHashAlgorithmIdentifier = 7;
    private const ushort PrivateUseHashAlgorithmIdentifierStart = 1024;
    private readonly byte[] certificateDigest;

    private EncryptedDnsProvisioningDigestInfoAttribute(
        EncryptedDnsProvisioningPayloadType payloadType,
        ushort length,
        byte hashAlgorithmCount,
        byte authenticationDomainNameLength,
        string authenticationDomainName,
        ReadOnlyCollection<ushort> hashAlgorithmIdentifiers,
        ReadOnlySpan<byte> certificateDigest,
        bool omitsTrailingFields)
    {
        PayloadType = payloadType;
        Length = length;
        HashAlgorithmCount = hashAlgorithmCount;
        AuthenticationDomainNameLength = authenticationDomainNameLength;
        AuthenticationDomainName = authenticationDomainName;
        HashAlgorithmIdentifiers = hashAlgorithmIdentifiers;
        this.certificateDigest = certificateDigest.ToArray();
        OmitsTrailingFields = omitsTrailingFields;
    }

    /// <summary>
    /// Gets the ENCDNS_DIGEST_INFO attribute type.
    /// </summary>
    public const ushort AttributeType = EncryptedDnsProvisioningAttribute.DigestInfoAttributeType;

    /// <summary>
    /// Gets the SHA2-256 IKEv2 hash algorithm identifier.
    /// </summary>
    public const ushort Sha2_256HashAlgorithmIdentifier = 2;

    /// <summary>
    /// Gets a value indicating whether outbound attributes set the reserved bit.
    /// </summary>
    public bool ReservedBitSet => false;

    /// <summary>
    /// Gets the two-octet Length field value.
    /// </summary>
    public ushort Length { get; }

    /// <summary>
    /// Gets the configuration payload type for this attribute.
    /// </summary>
    public EncryptedDnsProvisioningPayloadType PayloadType { get; }

    /// <summary>
    /// Gets the Num Hash Algs field value.
    /// </summary>
    public byte HashAlgorithmCount { get; }

    /// <summary>
    /// Gets the ADN Length field value for a CFG_REQUEST hash-algorithm list.
    /// </summary>
    public byte AuthenticationDomainNameLength { get; }

    /// <summary>
    /// Gets the Authentication Domain Name field value when it is present.
    /// </summary>
    public string AuthenticationDomainName { get; }

    /// <summary>
    /// Gets the requested hash algorithm identifiers.
    /// </summary>
    public IReadOnlyList<ushort> HashAlgorithmIdentifiers { get; }

    /// <summary>
    /// Gets the Certificate Digest field value for CFG_REPLY or CFG_SET.
    /// </summary>
    public ReadOnlyMemory<byte> CertificateDigest => certificateDigest;

    /// <summary>
    /// Gets a value indicating whether zero Length omits all trailing fields.
    /// </summary>
    public bool OmitsTrailingFields { get; }

    /// <summary>
    /// Gets a value indicating whether this digest applies to the ADN conveyed in the ENCDNS_IP* attribute.
    /// </summary>
    public bool AppliesToProvisioningAttributeAuthenticationDomainName => AuthenticationDomainNameLength == 0;

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
            ValidateHashAlgorithmIdentifier(identifier, nameof(hashAlgorithmIdentifiers));
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

        int length = DigestInfoFixedDataLength + (UInt16FieldOctets * identifiers.Count);
        if (length > ushort.MaxValue)
        {
            throw new ArgumentException("The ENCDNS_DIGEST_INFO length must fit in two octets.", nameof(hashAlgorithmIdentifiers));
        }

        return new EncryptedDnsProvisioningDigestInfoAttribute(
            EncryptedDnsProvisioningPayloadType.Request,
            (ushort)length,
            (byte)identifiers.Count,
            authenticationDomainNameLength: 0,
            authenticationDomainName: string.Empty,
            new ReadOnlyCollection<ushort>(identifiers),
            certificateDigest: [],
            omitsTrailingFields: false);
    }

    /// <summary>
    /// Creates a zero-length ENCDNS_DIGEST_INFO CFG_ACK attribute.
    /// </summary>
    public static EncryptedDnsProvisioningDigestInfoAttribute CreateAck()
    {
        return new EncryptedDnsProvisioningDigestInfoAttribute(
            EncryptedDnsProvisioningPayloadType.Ack,
            length: 0,
            hashAlgorithmCount: 0,
            authenticationDomainNameLength: 0,
            authenticationDomainName: string.Empty,
            new ReadOnlyCollection<ushort>([]),
            certificateDigest: [],
            omitsTrailingFields: true);
    }

    /// <summary>
    /// Creates an ENCDNS_DIGEST_INFO CFG_REPLY or CFG_SET digest attribute.
    /// </summary>
    public static EncryptedDnsProvisioningDigestInfoAttribute CreateReplyOrSet(
        EncryptedDnsProvisioningPayloadType payloadType,
        string? authenticationDomainName,
        ushort hashAlgorithmIdentifier,
        ReadOnlySpan<byte> certificateDigest,
        bool multipleAuthenticationDomainNames = false)
    {
        if (payloadType is not EncryptedDnsProvisioningPayloadType.Reply and not EncryptedDnsProvisioningPayloadType.Set)
        {
            throw new ArgumentException("Only CFG_REPLY and CFG_SET carry populated ENCDNS_DIGEST_INFO certificate digests.", nameof(payloadType));
        }

        ValidateHashAlgorithmIdentifier(hashAlgorithmIdentifier, nameof(hashAlgorithmIdentifier));
        if (certificateDigest.IsEmpty)
        {
            throw new ArgumentException("The certificate digest must not be empty.", nameof(certificateDigest));
        }

        string normalizedName = string.IsNullOrEmpty(authenticationDomainName)
            ? string.Empty
            : NormalizeAuthenticationDomainName(authenticationDomainName);
        if (normalizedName.Length != 0 && !multipleAuthenticationDomainNames)
        {
            throw new ArgumentException("The authentication domain name is included only when multiple ADNs are present in ENCDNS_IP* attributes.", nameof(authenticationDomainName));
        }

        int authenticationNameLength = Encoding.ASCII.GetByteCount(normalizedName);
        if (authenticationNameLength > byte.MaxValue)
        {
            throw new ArgumentException("The authentication domain name must fit in the one-octet ADN Length field.", nameof(authenticationDomainName));
        }

        int length = ReplyOrSetDigestFixedDataLength + authenticationNameLength + certificateDigest.Length;
        if (length > ushort.MaxValue)
        {
            throw new ArgumentException("The ENCDNS_DIGEST_INFO length must fit in two octets.", nameof(certificateDigest));
        }

        return new EncryptedDnsProvisioningDigestInfoAttribute(
            payloadType,
            (ushort)length,
            hashAlgorithmCount: 1,
            checked((byte)authenticationNameLength),
            normalizedName,
            new ReadOnlyCollection<ushort>([hashAlgorithmIdentifier]),
            certificateDigest,
            omitsTrailingFields: false);
    }

    /// <summary>
    /// Computes the mandatory SHA2-256 digest over a DER-encoded SubjectPublicKeyInfo value.
    /// </summary>
    public static byte[] ComputeSha2_256SubjectPublicKeyInfoDigest(ReadOnlySpan<byte> subjectPublicKeyInfoDer)
    {
        if (subjectPublicKeyInfoDer.IsEmpty)
        {
            throw new ArgumentException("The DER-encoded SubjectPublicKeyInfo value must not be empty.", nameof(subjectPublicKeyInfoDer));
        }

        return SHA256.HashData(subjectPublicKeyInfoDer);
    }

    /// <summary>
    /// Encodes the attribute header and data fields in RFC 9464 wire order.
    /// </summary>
    public byte[] Encode()
    {
        byte[] encoded = new byte[AttributeHeaderOctets + Length];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, AttributeType);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(UInt16FieldOctets), Length);
        if (Length == 0)
        {
            return encoded;
        }

        int offset = AttributeHeaderOctets;
        encoded[offset++] = HashAlgorithmCount;
        encoded[offset++] = AuthenticationDomainNameLength;
        offset += Encoding.ASCII.GetBytes(AuthenticationDomainName, encoded.AsSpan(offset));
        foreach (ushort identifier in HashAlgorithmIdentifiers)
        {
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), identifier);
            offset += UInt16FieldOctets;
        }

        certificateDigest.CopyTo(encoded.AsSpan(offset));
        return encoded;
    }

    /// <summary>
    /// Decodes an ENCDNS_DIGEST_INFO attribute header and data fields.
    /// </summary>
    public static EncryptedDnsProvisioningDigestInfoAttribute Decode(
        EncryptedDnsProvisioningPayloadType payloadType,
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < AttributeHeaderOctets)
        {
            throw new ArgumentException("The ENCDNS_DIGEST_INFO attribute is shorter than the IKEv2 attribute header.", nameof(encoded));
        }

        ushort attributeType = (ushort)(BinaryPrimitives.ReadUInt16BigEndian(encoded) & 0x7FFF);
        if (attributeType != AttributeType)
        {
            throw new ArgumentException("The IKEv2 attribute type is not ENCDNS_DIGEST_INFO.", nameof(encoded));
        }

        ushort length = BinaryPrimitives.ReadUInt16BigEndian(encoded[UInt16FieldOctets..]);
        if (encoded.Length != AttributeHeaderOctets + length)
        {
            throw new ArgumentException("The ENCDNS_DIGEST_INFO Length field does not match the encoded attribute size.", nameof(encoded));
        }

        if (length == 0)
        {
            if (payloadType != EncryptedDnsProvisioningPayloadType.Ack)
            {
                throw new ArgumentException("Only CFG_ACK can carry a zero-length ENCDNS_DIGEST_INFO attribute.", nameof(encoded));
            }

            return CreateAck();
        }

        ReadOnlySpan<byte> data = encoded.Slice(AttributeHeaderOctets, length);
        if (data.Length < DigestInfoFixedDataLength)
        {
            throw new ArgumentException("The ENCDNS_DIGEST_INFO data is shorter than the fixed data fields.", nameof(encoded));
        }

        byte hashAlgorithmCount = data[0];
        byte authenticationNameLength = data[1];
        if (payloadType == EncryptedDnsProvisioningPayloadType.Request)
        {
            if (authenticationNameLength != 0)
            {
                throw new ArgumentException("CFG_REQUEST ENCDNS_DIGEST_INFO must set ADN Length to zero.", nameof(encoded));
            }

            if (length != DigestInfoFixedDataLength + (UInt16FieldOctets * hashAlgorithmCount))
            {
                throw new ArgumentException("CFG_REQUEST ENCDNS_DIGEST_INFO length does not match the hash algorithm list.", nameof(encoded));
            }

            List<ushort> identifiers = [];
            int offset = DigestInfoFixedDataLength;
            for (int index = 0; index < hashAlgorithmCount; index++)
            {
                ushort identifier = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
                ValidateHashAlgorithmIdentifier(identifier, nameof(encoded));
                identifiers.Add(identifier);
                offset += UInt16FieldOctets;
            }

            return CreateRequest(identifiers);
        }

        if (payloadType is not EncryptedDnsProvisioningPayloadType.Reply and not EncryptedDnsProvisioningPayloadType.Set)
        {
            throw new ArgumentException("Only CFG_REQUEST, CFG_REPLY, CFG_SET, and CFG_ACK are valid ENCDNS_DIGEST_INFO contexts.", nameof(payloadType));
        }

        if (hashAlgorithmCount != 1)
        {
            throw new ArgumentException("CFG_REPLY and CFG_SET ENCDNS_DIGEST_INFO must set Num Hash Algs to one.", nameof(encoded));
        }

        if (data.Length - DigestInfoFixedDataLength < authenticationNameLength + UInt16FieldOctets)
        {
            throw new ArgumentException("The ENCDNS_DIGEST_INFO data is shorter than the ADN and hash identifier fields.", nameof(encoded));
        }

        string normalizedName = authenticationNameLength == 0
            ? string.Empty
            : NormalizeAuthenticationDomainName(Encoding.ASCII.GetString(data.Slice(DigestInfoFixedDataLength, authenticationNameLength)));
        int hashOffset = DigestInfoFixedDataLength + authenticationNameLength;
        ushort selectedIdentifier = BinaryPrimitives.ReadUInt16BigEndian(data[hashOffset..]);
        ValidateHashAlgorithmIdentifier(selectedIdentifier, nameof(encoded));
        ReadOnlySpan<byte> digest = data[(hashOffset + UInt16FieldOctets)..];
        bool multipleAuthenticationDomainNames = normalizedName.Length != 0;
        return CreateReplyOrSet(payloadType, normalizedName, selectedIdentifier, digest, multipleAuthenticationDomainNames);
    }

    /// <summary>
    /// Returns true when the hash algorithm identifier is registered for IKEv2 hash algorithms.
    /// </summary>
    public static bool IsRegisteredHashAlgorithmIdentifier(ushort identifier)
    {
        return identifier is >= 1 and <= HighestCurrentlyRegisteredHashAlgorithmIdentifier
            or >= PrivateUseHashAlgorithmIdentifierStart;
    }

    private static void ValidateHashAlgorithmIdentifier(ushort identifier, string parameterName)
    {
        if (!IsRegisteredHashAlgorithmIdentifier(identifier))
        {
            throw new ArgumentException("The hash algorithm identifier is not registered for IKEv2 hash algorithms.", parameterName);
        }
    }

    private static string NormalizeAuthenticationDomainName(string? authenticationDomainName)
    {
        return EncryptedDnsProvisioningAttribute.NormalizeAuthenticationDomainName(authenticationDomainName);
    }
}
